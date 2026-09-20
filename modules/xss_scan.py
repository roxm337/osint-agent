"""Stage 5: Authorized reflected XSS detection with browser confirmation."""

from __future__ import annotations

import html
import secrets
from urllib.parse import parse_qsl, urlparse

from core.validators import inject_param
from modules.base import BaseModule
from tools.external import dalfox_scan, tool_available
from tools.wrappers import curl


class XSSScan(BaseModule):
    id = "xss_scan"
    name = "XSS Scan"
    stage = 5
    detectability = "high"
    depends_on = ["parameter_discovery"]
    requires_auth = True

    async def run(self) -> str:
        points = self._candidate_injection_points()
        if not points:
            self.state.skip_module(self.id, "no parameterized URLs")
            return "skipped"

        in_scope = [point for point in points if self.scope.check(point["url"]).allowed]
        if not in_scope:
            self.state.block_module(self.id, "no in-scope URLs")
            return "blocked"

        cfg = self.config.get("xss", {})
        max_points = int(cfg.get("max_points", 80))
        browser_enabled = bool(cfg.get("browser_confirm", True))
        browser_available = browser_enabled and await _playwright_available()

        internal_findings = []
        for point in in_scope[:max_points]:
            finding = await self._test_reflected_xss(point, browser_available)
            if finding:
                internal_findings.append(finding)

        dalfox_findings = []
        if tool_available("dalfox"):
            result = await dalfox_scan(
                [point["url"] for point in in_scope[:max_points]],
                timeout=int(cfg.get("dalfox_timeout", 600)),
            )
            dalfox_findings = result.get("results", []) if result.get("available", True) else []
        else:
            result = {"available": False, "results": [], "error": "missing"}

        evidence_id = self.state.add_evidence(
            self.id,
            "xss_scan",
            self.domain,
            {
                "targets": in_scope[:max_points],
                "internal_findings": internal_findings,
                "dalfox_findings": dalfox_findings,
                "browser_confirm": browser_available,
                "dalfox_available": result.get("available", False),
                "dalfox_exit_code": result.get("exit_code"),
                "dalfox_stderr": result.get("stderr", ""),
            },
        )

        seen = set()
        for item in internal_findings:
            key = (item["url"], item["param"], item["payload"])
            if key in seen:
                continue
            seen.add(key)
            confirmed = item["confidence"] == "CONFIRMED"
            self.state.add_finding(
                title="Confirmed Reflected Cross-Site Scripting" if confirmed else "Reflected XSS Candidate",
                severity="HIGH",
                confidence=item["confidence"],
                category="XSS",
                description=(
                    "The scanner injected a JavaScript payload into a reflected "
                    "query parameter and observed browser execution."
                    if confirmed else
                    "The scanner found unsanitized reflection of HTML/JavaScript "
                    "metacharacters. Browser execution was not confirmed."
                ),
                evidence=[
                    f"URL: {item['url']}",
                    f"Parameter: {item['param']}",
                    f"Payload: {item['payload']}",
                    f"Evidence: {item['evidence']}",
                ],
                evidence_refs=[evidence_id],
                asset_keys=[f"url:{item['url']}"],
                remediation="Encode output by HTML/attribute/JS context, validate input, set HttpOnly cookies, and enforce CSP.",
            )

        for item in dalfox_findings:
            key = (item.get("url", ""), item.get("payload", ""))
            if key in seen:
                continue
            seen.add(key)
            self.state.add_finding(
                title="Dalfox XSS Candidate",
                severity="HIGH",
                confidence="FIRM",
                category="XSS",
                description="Dalfox reported an XSS proof-of-concept candidate.",
                evidence=[
                    str(item.get("url", "")),
                    str(item.get("payload", "")),
                    str(item.get("evidence", "")),
                ],
                evidence_refs=[evidence_id],
                asset_keys=[f"url:{item.get('url', '')}"],
                remediation="Validate manually, encode output by context, and enforce CSP where appropriate.",
            )

        self.state.complete_module(self.id)
        self.log(
            f"XSS findings: {len(internal_findings)} internal | "
            f"{len(dalfox_findings)} dalfox | browser={browser_available}"
        )
        return "done"

    async def _test_reflected_xss(self, point: dict, browser_available: bool) -> dict | None:
        url = point["url"]
        param = point["param"]
        marker = f"osintxss{secrets.token_hex(4)}"
        marker_url = inject_param(url, param, marker)
        marker_result = await curl(marker_url, output="full")
        marker_body = marker_result.get("body", "")
        if marker not in marker_body:
            return None

        exec_marker = secrets.token_hex(4)
        expected = exec_marker * 2
        payload = f"<sVg/onLOad=document.body.append(`{exec_marker}`.repeat(2))>"
        payload_url = inject_param(url, param, payload)
        payload_result = await curl(payload_url, output="full")
        body = payload_result.get("body", "")

        if browser_available:
            executed = await _browser_confirms_execution(payload_url, expected, self.config)
            if executed:
                return {
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "test_url": payload_url,
                    "confidence": "CONFIRMED",
                    "evidence": f"Browser DOM contained execution marker {expected}",
                }

        if _looks_unsanitized(body, payload, exec_marker):
            return {
                "url": url,
                "param": param,
                "payload": payload,
                "test_url": payload_url,
                "confidence": "FIRM",
                "evidence": "Payload reflected with executable HTML/JS metacharacters unsanitized",
            }

        return None

    def _candidate_injection_points(self) -> list[dict]:
        points = []
        seen = set()

        raw_url = str(self.config.get("target", {}).get("raw_url", "")).strip()
        if raw_url:
            self._add_url_points(raw_url, points, seen, "raw_target")

        for asset in self.state.get_assets_by_type("parameter"):
            url = str(asset.get("attrs", {}).get("url", "")).strip()
            param = str(asset.get("value", "")).strip()
            if not url or not param:
                continue
            parsed = urlparse(url)
            base_url = url if parsed.query else f"{url}?{param}=test"
            key = (base_url, param)
            if key not in seen:
                seen.add(key)
                points.append({"url": base_url, "param": param, "source": "parameter_asset"})

        for asset_type in ("url", "api_endpoint"):
            for asset in self.state.get_assets_by_type(asset_type):
                self._add_url_points(str(asset.get("value", "")).strip(), points, seen, asset_type)

        return points

    def _add_url_points(self, url: str, points: list[dict], seen: set, source: str):
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc or not parsed.query:
            return
        for param, _ in parse_qsl(parsed.query, keep_blank_values=True):
            key = (url, param)
            if key in seen:
                continue
            seen.add(key)
            points.append({"url": url, "param": param, "source": source})


def _looks_unsanitized(body: str, payload: str, marker: str) -> bool:
    if not body:
        return False
    if payload in body:
        return True
    decoded = html.unescape(body)
    if payload in decoded:
        return True
    dangerous_fragments = [
        "<svg",
        "onload=",
        "document.body.append",
        f"`{marker}`.repeat(2)",
    ]
    return all(fragment.lower() in decoded.lower() for fragment in dangerous_fragments)


async def _playwright_available() -> bool:
    try:
        import playwright.async_api  # noqa: F401
        return True
    except Exception:
        return False


async def _browser_confirms_execution(url: str, expected: str, config: dict) -> bool:
    from playwright.async_api import async_playwright

    auth = config.get("auth", {}) or {}
    headers = {
        str(k): str(v)
        for k, v in (auth.get("headers") or {}).items()
        if k and v is not None and str(v) != "" and str(k).lower() != "cookie"
    }
    bearer = auth.get("bearer_token") or auth.get("token")
    if bearer and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {bearer}"

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(extra_http_headers=headers)
        page = await context.new_page()
        try:
            await page.goto(url, wait_until="networkidle", timeout=15000)
            await page.wait_for_timeout(500)
            text = await page.evaluate("() => document.body ? document.body.textContent : ''")
        except Exception:
            await browser.close()
            return False
        await browser.close()
    return expected in (text or "")
