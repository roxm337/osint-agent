"""Stage 4: Fast exposure checks without heavyweight scanners."""

from __future__ import annotations

import asyncio
import re

from modules.base import BaseModule
from tools.wrappers import curl, curl_with_status


DEFAULT_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/wp-config.php",
    "/wp-content/debug.log",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/actuator/env",
    "/actuator/heapdump",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/phpmyadmin/",
    "/adminer.php",
    "/backup.sql",
]


PATH_RULES = [
    (re.compile(r"/\.env"), "CRITICAL", "Exposed Environment File"),
    (re.compile(r"/\.git/(config|HEAD)"), "CRITICAL", "Exposed Git Metadata"),
    (re.compile(r"wp-config"), "CRITICAL", "Exposed WordPress Configuration"),
    (re.compile(r"debug\.log|error_log|server-status"), "HIGH", "Sensitive Diagnostic Endpoint Exposed"),
    (re.compile(r"phpinfo|info\.php"), "MEDIUM", "phpinfo Page Exposed"),
    (re.compile(r"actuator/(env|heapdump)"), "CRITICAL", "Sensitive Spring Boot Actuator Exposed"),
    (re.compile(r"swagger|api-docs"), "MEDIUM", "API Documentation Exposed"),
    (re.compile(r"graphql|graphiql"), "MEDIUM", "GraphQL Endpoint Accessible"),
    (re.compile(r"phpmyadmin|adminer"), "HIGH", "Database Admin Interface Exposed"),
    (re.compile(r"backup\.sql"), "CRITICAL", "Database Backup Exposed"),
]


SECURITY_HEADERS = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
}


class FastExposureScan(BaseModule):
    id = "fast_exposure_scan"
    name = "Fast Exposure Scan"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        base_url = self._target()
        if not self.scope.check(base_url).allowed:
            self.state.block_module(self.id, "target outside scope")
            return "blocked"

        cfg = self.config.get("fast_scan", {})
        timeout = int(cfg.get("timeout", 4) or 4)
        concurrency = max(1, int(cfg.get("concurrency", 8) or 8))
        paths = _normalize_paths(cfg.get("paths") or DEFAULT_PATHS)
        max_paths = int(cfg.get("max_paths", len(paths)) or len(paths))
        paths = paths[:max_paths]

        self.log(
            f"Fast scan: headers, CORS, and {len(paths)} paths "
            f"(concurrency={concurrency}, timeout={timeout}s)"
        )

        header_findings = await self._check_headers(base_url, timeout)
        cors_finding = await self._check_cors(base_url, timeout)
        path_findings = await self._check_paths(base_url, paths, concurrency, timeout)
        all_findings = header_findings + ([cors_finding] if cors_finding else []) + path_findings

        evidence_id = self.state.add_evidence(
            self.id,
            "fast_web_checks",
            base_url,
            {
                "target": base_url,
                "paths_checked": len(paths),
                "findings": all_findings,
            },
        )

        for finding in all_findings:
            evidence = list(finding.get("evidence", []))
            self.state.add_finding(
                title=finding["title"],
                severity=finding["severity"],
                confidence=finding.get("confidence", "FIRM"),
                category=finding.get("category", "Web Exposure"),
                description=finding["description"],
                evidence=evidence,
                evidence_refs=[evidence_id],
                remediation=finding.get("remediation", "Restrict public exposure and apply web hardening."),
                asset_keys=[f"webapp:{base_url}"],
            )

        self.state.add_asset(
            "scanner_run",
            f"fast-scan:{self.domain}",
            self.domain,
            confidence="FIRM",
            sources=[self.id],
            attrs={
                "target": base_url,
                "paths_checked": len(paths),
                "findings": len(all_findings),
            },
        )
        self.state.complete_module(self.id)
        self.log(f"Fast scan complete: {len(all_findings)} finding(s)")
        return "done"

    def _target(self) -> str:
        raw = str(self.config.get("target", {}).get("raw_url", "")).strip()
        if raw.startswith(("http://", "https://")):
            return raw.rstrip("/")
        return f"https://{self.domain}".rstrip("/")

    async def _check_headers(self, base_url: str, timeout: int) -> list[dict]:
        result = await curl(base_url, output="headers", timeout=timeout)
        headers_text = str(result.get("body", ""))
        headers = _parse_headers(headers_text)
        missing = [
            display for key, display in SECURITY_HEADERS.items()
            if key not in headers
        ]
        if not missing:
            return []

        return [{
            "title": "Missing Common Security Headers",
            "severity": "LOW",
            "confidence": "FIRM",
            "category": "Web Hardening",
            "description": "The landing response is missing common browser security headers.",
            "evidence": [f"Missing: {', '.join(missing)}", f"Status: {result.get('status', 0)}"],
            "remediation": "Set HSTS, CSP, X-Frame-Options/frame-ancestors, and X-Content-Type-Options where applicable.",
        }]

    async def _check_cors(self, base_url: str, timeout: int) -> dict | None:
        origin = "https://attacker.invalid"
        result = await curl(
            base_url,
            output="headers",
            timeout=timeout,
            headers={"Origin": origin},
        )
        headers = _parse_headers(str(result.get("body", "")))
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        reflected = acao == origin
        wildcard = acao == "*"
        credentialed = acac.lower() == "true"
        if not reflected and not (wildcard and credentialed):
            return None

        return {
            "title": "Permissive CORS Behavior",
            "severity": "MEDIUM" if credentialed else "LOW",
            "confidence": "FIRM",
            "category": "CORS",
            "description": "The target reflects an untrusted Origin or allows wildcard CORS with credentials.",
            "evidence": [
                f"Origin: {origin}",
                f"Access-Control-Allow-Origin: {acao}",
                f"Access-Control-Allow-Credentials: {acac or '<absent>'}",
            ],
            "remediation": "Use a strict allowlist for trusted origins and avoid credentialed wildcard CORS.",
        }

    async def _check_paths(self, base_url: str, paths: list[str],
                           concurrency: int, timeout: int) -> list[dict]:
        semaphore = asyncio.Semaphore(concurrency)
        findings = []

        async def probe(path: str) -> dict:
            async with semaphore:
                result = await curl_with_status(f"{base_url}{path}", timeout=timeout)
                return {
                    "path": path,
                    "status": int(result.get("status", 0) or 0),
                    "body": str(result.get("body", "")),
                }

        tasks = [asyncio.create_task(probe(path)) for path in paths]
        try:
            for task in asyncio.as_completed(tasks):
                item = await task
                finding = self._path_finding(base_url, item)
                if finding:
                    findings.append(finding)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
        return findings

    def _path_finding(self, base_url: str, item: dict) -> dict | None:
        status = item["status"]
        path = item["path"]
        body = item["body"]
        if status not in (200, 401, 403) or (status == 200 and len(body.strip()) < 20):
            return None

        for pattern, severity, title in PATH_RULES:
            if pattern.search(path):
                confidence = "CONFIRMED" if status == 200 else "FIRM"
                public_note = "publicly accessible" if status == 200 else f"returns HTTP {status}"
                return {
                    "title": title,
                    "severity": severity if status == 200 else "LOW",
                    "confidence": confidence,
                    "category": "Information Disclosure",
                    "description": f"{path} is {public_note}.",
                    "evidence": [
                        f"URL: {base_url}{path}",
                        f"Status: {status}",
                        f"Preview: {body[:200]}",
                    ],
                    "remediation": "Remove the exposed resource or require authentication and network restrictions.",
                }
        return None


def _parse_headers(headers_text: str) -> dict[str, str]:
    headers = {}
    for line in headers_text.splitlines():
        if ":" not in line or line.lower().startswith("http/"):
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


def _normalize_paths(value) -> list[str]:
    if isinstance(value, str):
        items = []
        for line in value.splitlines():
            items.extend(part.strip() for part in line.split(","))
    else:
        items = [str(item).strip() for item in value]
    paths = []
    seen = set()
    for item in items:
        if not item:
            continue
        path = item if item.startswith("/") else f"/{item}"
        if path not in seen:
            seen.add(path)
            paths.append(path)
    return paths
