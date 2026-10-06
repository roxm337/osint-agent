"""Stage 5: Authorized reflected XSS detection with browser confirmation."""

from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlparse

from core.validators import inject_param
from core.verification_oracle import looks_unsanitized
from modules.base import BaseModule
from tools.external import dalfox_scan, tool_available
from tools.wrappers import curl


# Backward-compatible alias: the shared oracle lives in core now.
def _looks_unsanitized(body: str, payload: str, marker: str) -> bool:
    return looks_unsanitized(body, payload, marker)


class XSSScan(BaseModule):
    id = "xss_scan"
    name = "XSS Scan"
    stage = 5
    detectability = "high"
    depends_on = ["parameter_discovery"]
    active = True

    async def run(self) -> str:
        points = self._candidate_injection_points()
        cfg = self.config.get("xss", {})
        max_points = int(cfg.get("max_points", 80))
        browser_enabled = bool(cfg.get("browser_confirm", True))
        browser_available = browser_enabled and await _playwright_available()

        # Header reflection needs pages, not parameters: a site with zero
        # query strings can still echo True-Client-IP into markup.
        header_pages = self._header_pages(points)
        if not points and not header_pages:
            self.state.skip_module(self.id, "no parameterized URLs")
            return "skipped"

        internal_findings = []
        for point in points[:max_points]:
            finding = await self._test_reflected_xss(point, browser_available)
            if finding:
                internal_findings.append(finding)

        header_findings = await self._test_header_reflection(
            header_pages, browser_available)
        internal_findings.extend(header_findings)

        dalfox_findings = []
        blind_callback = None
        oob_client = self.oob()
        if tool_available("dalfox"):
            blind_url = None
            if oob_client is not None:
                try:
                    corr_id = await oob_client.register_callback(
                        f"xss-blind:{self.domain}")
                    blind_url = oob_client.callback_url(corr_id, "/xss")
                    blind_callback = corr_id
                except Exception as exc:
                    self.log(f"  OOB registration failed, blind pass skipped: {exc}")
            result = await dalfox_scan(
                [point["url"] for point in points[:max_points]],
                timeout=int(cfg.get("dalfox_timeout", 600)),
                blind=blind_url,
            )
            dalfox_findings = result.get("results", []) if result.get("available", True) else []
        else:
            result = {"available": False, "results": [], "error": "missing"}

        evidence_id = self.state.add_evidence(
            self.id,
            "xss_scan",
            self.domain,
            {
                "targets": points[:max_points],
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
            blind_hit = "blind" in str(item.get("type", "")).lower() or \
                "blind" in str(item.get("evidence", "")).lower()
            if blind_hit and blind_callback and oob_client is not None:
                confirmed = await self._confirm_blind_callback(
                    oob_client, blind_callback)
            else:
                confirmed = False
            if blind_hit and confirmed:
                self.state.add_finding(
                    title="Confirmed Blind XSS via OOB Callback",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    category="XSS",
                    description=(
                        "A blind XSS payload phoned home to the out-of-band "
                        "callback: JavaScript executed in a victim context "
                        "(stored page, admin panel, or mail client)."),
                    evidence=[
                        str(item.get("url", "")),
                        str(item.get("payload", "")),
                        f"OOB callback received (corr {blind_callback[:8]})",
                    ],
                    evidence_refs=[evidence_id],
                    asset_keys=[f"url:{item.get('url', '')}"],
                    remediation="Encode output by context everywhere user input is stored or mailed, and enforce CSP.",
                    verified=True,
                    verification={"method": "oob_callback",
                                  "url": str(item.get("url", ""))},
                )
                continue
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

    async def _confirm_blind_callback(self, oob_client, corr_id: str) -> bool:
        """Poll for the blind payload's phone-home (bounded)."""
        import asyncio as _asyncio
        for _ in range(6):
            try:
                interactions = await oob_client.poll(corr_id)
            except Exception:
                interactions = []
            if interactions:
                return True
            await _asyncio.sleep(oob_client.poll_interval)
        return False

    async def _test_reflected_xss(self, point: dict, browser_available: bool) -> dict | None:
        url = point["url"]
        param = point["param"]
        marker = f"osintxss{secrets.token_hex(4)}"
        marker_url = inject_param(url, param, marker)
        marker_result = await curl(marker_url, output="full")
        marker_body = marker_result.get("body", "")
        if marker not in marker_body:
            return None


        # Payload ladder: element injection first, then attribute breakout,
        # then JS-string breakout. Each carries its own execution marker so
        # a reflection of one payload can never confirm another.
        exec_marker = secrets.token_hex(4)
        expected = exec_marker * 2
        payloads = [
            f"<sVg/onLOad=document.body.append(`{exec_marker}`.repeat(2))>",
            f"\"><sVg/onLOad=document.body.append(`{exec_marker}`.repeat(2))>",
            f"'-document.body.append(`{exec_marker}`.repeat(2))- appeals'",
        ]
        for payload in payloads:
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

    def _header_pages(self, points: list) -> list:
        """Base pages for header probing: point URLs plus crawled pages
        plus the base URL itself, deduplicated and capped."""
        pages = []
        for point in points:
            url = point["url"].split("?")[0].split("#")[0]
            if url not in pages:
                pages.append(url)
        for asset in self.state.get_assets_by_type("url"):
            value = str(asset.get("value", "") or "")
            if value.startswith(("http://", "https://")) \
                    and value not in pages:
                pages.append(value)
        if self.base_url not in pages:
            pages.append(self.base_url)
        return pages[:20]

    async def _test_header_reflection(self, pages: list,
                                      browser_available: bool) -> list:
        """Reflect benign markers off request headers, then escalate.

        Headers like X-Forwarded-For and True-Client-IP land in logs,
        tracking pixels, and admin views. A verbatim reflection with
        executable metacharacters is reflected XSS through a header;
        anything less is not filed — header echoes of plain text are
        normal.
        """
        headers_to_try = ("X-Forwarded-For", "True-Client-IP", "X-Real-IP",
                          "Referer", "User-Agent")
        seen_urls = set()
        findings = []
        for url in pages:
            if url in seen_urls:
                continue
            seen_urls.add(url)
            if len(seen_urls) > 20:
                break
            for header_name in headers_to_try:
                marker = f"hxprobe{secrets.token_hex(4)}"
                try:
                    result = await curl(url, headers={header_name: marker},
                                        output="full", timeout=15)
                except Exception:
                    continue
                body = result.get("body", "") or ""
                if marker not in body:
                    continue
                payload = (f"<sVg/onLOad=document.body.append(`{marker}`"
                           f".repeat(2))>")
                try:
                    probe = await curl(url, headers={header_name: payload},
                                       output="full", timeout=15)
                except Exception:
                    continue
                probe_body = probe.get("body", "") or ""
                if not _looks_unsanitized(probe_body, payload, marker):
                    continue
                confidence = "FIRM"
                evidence = (f"Header {header_name} reflected with executable "
                            f"HTML/JS metacharacters unsanitized")
                if browser_available:
                    from urllib.parse import quote
                    witness = await _browser_confirms_execution(
                        url, marker * 2, self.config)
                    if witness:
                        confidence = "CONFIRMED"
                        evidence = (f"Browser DOM contained execution marker "
                                    f"{marker * 2} after header injection")
                findings.append({
                    "url": url,
                    "param": f"header:{header_name}",
                    "payload": payload,
                    "test_url": url,
                    "confidence": confidence,
                    "evidence": evidence,
                })
                break
        return findings

    def _candidate_injection_points(self) -> list[dict]:
        # One shared builder for every testing module: parameter assets,
        # swagger-derived endpoints ({id} templates included), and crawled
        # query URLs — all in-scope. GET-only here; POST/JSON bodies need
        # body injection this pass does not do.
        from core.probe_targets import iter_probe_points
        points = iter_probe_points(self.state, self.base_url, self.domain)
        raw_url = str(self.config.get("target", {}).get("raw_url", "")).strip()
        if raw_url:
            self._add_url_points(raw_url, points, {
                (p["url"], p["param"]) for p in points}, "raw_target")
        return [p for p in points if p.get("method", "GET") == "GET"]

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
    """Is the payload present in the response *as sent*?

    Unescaping the body before looking (the previous behaviour) made the
    encoding that defends against the payload look like proof of it: on an
    error page that entity-encodes its input, `&lt;sVg/onLOad=...&gt;`
    unescaped straight back into the payload and was reported as an
    unsanitized reflection with HTML/JS metacharacters intact. Four HIGH
    findings came out of one run that way, none of them executable.

    So the dangerous pieces have to appear verbatim, or not at all.
    """
    if not body:
        return False
    if payload in body:
        return True
    dangerous_fragments = [
        "<svg",
        "onload=",
        "document.body.append",
        f"`{marker}`.repeat(2)",
    ]
    raw = body.lower()
    return all(fragment.lower() in raw for fragment in dangerous_fragments)


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
            # textContent misses execution that leaves no text behind
            # (cookie exfil, alert-only, DOM rewrites): innerHTML catches
            # the marker's residue in those shapes.
            inner = await page.evaluate("() => document.documentElement ? document.documentElement.innerHTML : ''")
        except Exception:
            await browser.close()
            return False
        await browser.close()
    return expected in (text or "") or expected in (inner or "")
