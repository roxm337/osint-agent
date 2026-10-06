"""Stage 4: Fast exposure checks without heavyweight scanners."""

from __future__ import annotations

import asyncio
import re
from typing import Optional

from core.response_fingerprint import (
    Baseline,
    content_matches,
    establish_baseline,
    fingerprint,
)
from core.site_profile import PATH_RULES as SITE_PROFILE_RULES
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


# One rule set for the whole tool. This used to be a second copy of these
# ten rules, which is precisely how they drift out of step with the content
# assertions written against them: a rule renamed here stopped being verified
# there, silently, and an unverified rule fires on anything. `core.site_profile`
# owns them; a module that wants a different set passes its own to
# `grade_path_exposure` rather than redefining one.
PATH_RULES = SITE_PROFILE_RULES

SECURITY_HEADERS = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
}


def content_graded_severity(severity: str, rule_key: str, body: str) -> str:
    """Grade by what leaked, not by what the path is called.

    `/.git/config` earns CRITICAL from the rule table because, at its worst,
    it hands over the remote URL, credentials embedded in that URL, and the
    commit history that makes every other file fetchable. A `.git/config`
    holding only `[core] repositoryformatversion = 0` leaks nothing an
    anonymous visitor did not already know from the host being on GitHub at
    all, and reporting that as CRITICAL is how a program that is right about
    the facts still gets ignored.

    Downgrade, never upgrade: the content gate proves the artifact exists, not
    how much of it is sensitive. Under-claiming costs a triager one question;
    over-claiming costs the report its credit.
    """
    if severity not in ("CRITICAL", "HIGH"):
        return severity

    if rule_key == r"/\.git/(config|HEAD|refs)":
        # CRITICAL is for credentials in the URL. A bare
        # `url = https://github.com/acme/app.git` is a meaningful disclosure —
        # it names the host, the org and the repository, which for a private
        # repo is most of what an attacker needed — but it hands over no
        # secret, and calling it CRITICAL spends the top of the scale on a
        # fact about a URL.
        if re.search(r"^\s*(?:url\s*=\s*)?(https?|git|ssh)://[^\s/@]+:[^\s/@]+@",
                     body, re.M):
            return "CRITICAL"        # credentials embedded in the remote
        if re.search(r"url\s*=\s*\S+://", body):
            return "HIGH"            # remote URL discloses the source location
        if re.search(r"^\s*ref:\s*\S", body, re.M):
            return "HIGH"            # refs/HEAD: repo confirmed, history fetchable
        return "LOW"                 # structure only

    if rule_key == r"/\.env":
        # A .env with nothing on the right-hand side is a template, not a
        # secret: "FOO=" is a key name, not a credential.
        #
        # `[ \t]*` rather than `\s*`. \s matches the newline, so a file of
        # nothing but `DB_PASS=\nAPI_KEY=\n` let the pattern skip the empty
        # value, slide across the line break, and "find" a value on the next
        # key - precisely the case this is meant to catch.
        if not re.search(r"^[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*\S", body, re.M):
            return "HIGH"
        return severity

    return severity



class FastExposureScan(BaseModule):
    id = "fast_exposure_scan"
    name = "Fast Exposure Scan"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        base_url = self._target()
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
        return self.base_url.rstrip("/")

    async def _check_headers(self, base_url: str, timeout: int) -> list[dict]:
        # tech_detection already reports this exact fact with its own header
        # set; a second finding with a different title is noise, not coverage.
        if self.state.is_module_complete("tech_detection"):
            return []
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

        async def fetch(path: str):
            """One request, normalised to (status, body, content_type)."""
            result = await curl_with_status(f"{base_url}{path}", timeout=timeout)
            headers = _parse_headers(str(result.get("headers", "")))
            return (
                int(result.get("status", 0) or 0),
                str(result.get("body", "")),
                headers.get("content-type", ""),
            )

        # Establish what this site serves when nothing matches, before judging
        # any of the paths. On a modern SPA every path returns the same
        # index.html, and without this the scan reports that shell as a
        # CRITICAL database backup twenty times over.
        baseline = await establish_baseline(fetch, base_url)
        self.log(f"  baseline: {baseline.describe()}")

        async def probe(path: str) -> dict:
            async with semaphore:
                status, body, ct = await fetch(path)
                return {
                    "path": path,
                    "status": status,
                    "body": body,
                    "sig": fingerprint(status, body, ct),
                }

        tasks = [asyncio.create_task(probe(path)) for path in paths]
        catch_all_hits = 0
        try:
            for task in asyncio.as_completed(tasks):
                item = await task
                verdict, finding = self._path_finding(base_url, item, baseline)
                if verdict == "catch_all":
                    catch_all_hits += 1
                if finding:
                    findings.append(finding)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
        if catch_all_hits:
            self.log(
                f"  {catch_all_hits}/{len(paths)} path(s) matched the site's "
                "catch-all response and were not treated as exposures"
            )
        return findings

    def _path_finding(self, base_url: str, item: dict,
                      baseline: Optional[Baseline] = None) -> tuple:
        """Grade one probed path.

        Returns (verdict, finding) where verdict is one of
        `not_found` | `catch_all` | `no_content_match` | `finding` | `status_only`.

        Two gates, both of which the previous version lacked:

          1. If the response is the site's catch-all, the path does not exist
             no matter what status came back.
          2. A 200 also has to contain what the named artifact would contain.
             Serving a 200 is not evidence; serving a `.git/config` is.
        """
        status = item["status"]
        path = item["path"]
        body = item["body"]

        if status not in (200, 401, 403) or (status == 200 and len(body.strip()) < 20):
            return "not_found", None

        if baseline is not None and status == 200:
            if baseline.catch_all(item["sig"]):
                return "catch_all", None

        for pattern, severity, title in PATH_RULES:
            if not pattern.search(path):
                continue
            rule_key = pattern.pattern

            if status in (401, 403):
                # The resource exists and is protected. That is a much weaker
                # statement than "exposed", and the old code graded it FIRM
                # against a CRITICAL severity rule.
                return "status_only", {
                    "title": f"{title} (access denied)",
                    "severity": "INFO",
                    "confidence": "FIRM",
                    "category": "Information Disclosure",
                    "description": (
                        f"{path} returns HTTP {status}, so the resource appears to "
                        "exist but is not publicly readable. Nothing is disclosed."
                    ),
                    "evidence": [
                        f"URL: {base_url}{path}",
                        f"Status: {status}",
                    ],
                    "remediation": "No action required unless it should not exist at all.",
                }

            if not content_matches(rule_key, body):
                return "no_content_match", None

            return "finding", {
                "title": title,
                "severity": content_graded_severity(severity, rule_key, body),
                "confidence": "CONFIRMED",
                "category": "Information Disclosure",
                "description": (
                    f"{path} is publicly accessible and its contents match the "
                    f"expected {title.lower()}."
                ),
                "evidence": [
                    f"URL: {base_url}{path}",
                    f"Status: {status}",
                    f"Content matched expected {title.lower()}",
                    f"Preview: {body[:200]}",
                ],
                "remediation": "Remove the exposed resource or require authentication and network restrictions.",
            }
        return "not_found", None


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
