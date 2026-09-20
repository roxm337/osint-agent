"""Stage 4: Browser-rendered crawling for JavaScript-heavy applications."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from modules.base import BaseModule
from modules.js_analysis import extract_dom_sinks


class BrowserCrawl(BaseModule):
    id = "browser_crawl"
    name = "Browser-Rendered Crawl"
    stage = 4
    detectability = "medium"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        if not await _playwright_available():
            self.state.skip_module(self.id, "playwright not installed")
            return "skipped"

        targets = self._targets() or [f"https://{self.domain}"]
        crawl_cfg = self.config.get("crawl", {}).get("browser", {})
        max_targets = int(crawl_cfg.get("max_targets", 8))
        wait_ms = int(crawl_cfg.get("wait_ms", 1500))

        discovered: set[str] = set()
        js_urls: set[str] = set()
        source_maps: set[str] = set()
        dom_sinks: list[dict] = []
        evidence_refs = []

        for target in targets[:max_targets]:
            if not self.scope.check(target).allowed:
                continue

            rendered = await _render_page(target, self.config, wait_ms=wait_ms)
            discovered.update(rendered.get("links", []))
            discovered.update(rendered.get("forms", []))
            js_urls.update(rendered.get("scripts", []))
            source_maps.update(rendered.get("source_maps", []))
            dom_sinks.extend(rendered.get("dom_sinks", []))

            evidence_refs.append(
                self.state.add_evidence(
                    self.id,
                    "browser_render",
                    target,
                    {
                        "target": target,
                        "links": sorted(rendered.get("links", []))[:200],
                        "scripts": sorted(rendered.get("scripts", []))[:100],
                        "forms": sorted(rendered.get("forms", []))[:100],
                        "source_maps": sorted(rendered.get("source_maps", []))[:50],
                        "dom_sinks": rendered.get("dom_sinks", [])[:50],
                        "error": rendered.get("error"),
                    },
                )
            )

        scoped_urls = [
            url for url in sorted(discovered)
            if self.scope.check(url).allowed and _is_http(url)
        ]
        for url in scoped_urls[:1000]:
            asset_type = "api_endpoint" if _looks_api(url) else "url"
            self.state.add_asset(
                asset_type,
                f"{asset_type}:{url}",
                url,
                confidence="FIRM",
                sources=[self.id],
                attrs={"path": urlparse(url).path, "query": urlparse(url).query},
            )
            self.state.add_edge(f"domain:{self.domain}", f"{asset_type}:{url}", "rendered_crawl_url")

        for js_url in sorted(js_urls)[:200]:
            if self.scope.check(js_url).allowed:
                self.state.add_asset(
                    "js_file",
                    f"js:{js_url}",
                    js_url,
                    confidence="FIRM",
                    sources=[self.id],
                    attrs={"rendered": True},
                )

        for map_url in sorted(source_maps)[:100]:
            if self.scope.check(map_url).allowed:
                self.state.add_asset(
                    "source_map",
                    f"source_map:{map_url}",
                    map_url,
                    confidence="FIRM",
                    sources=[self.id],
                    attrs={"rendered": True},
                )

        if dom_sinks:
            self.state.add_finding(
                title=f"DOM XSS Sinks Observed in Rendered JavaScript: {len(dom_sinks)}",
                severity="MEDIUM",
                confidence="TENTATIVE",
                category="Client-Side Attack Surface",
                description=(
                    "Browser-rendered crawl observed JavaScript DOM sinks or message "
                    "handlers that should be reviewed with controllable input sources."
                ),
                evidence=[
                    f"{item['sink']} in {item.get('source', 'inline')} near: {item.get('snippet', '')[:120]}"
                    for item in dom_sinks[:12]
                ],
                evidence_refs=evidence_refs,
                remediation="Review sink reachability, sanitize untrusted data, and enforce a strict CSP.",
            )

        self.state.add_asset(
            "browser_crawl_summary",
            f"browser_crawl:{self.domain}",
            self.domain,
            confidence="FIRM",
            sources=[self.id],
            attrs={
                "targets": targets[:max_targets],
                "urls": len(scoped_urls),
                "js_files": len(js_urls),
                "source_maps": len(source_maps),
                "dom_sinks": len(dom_sinks),
            },
        )
        self.state.complete_module(self.id)
        self.log(
            f"Rendered crawl: {len(scoped_urls)} URLs | {len(js_urls)} JS | "
            f"{len(source_maps)} source maps | {len(dom_sinks)} DOM sinks"
        )
        return "done"

    def _targets(self) -> list[str]:
        targets = []
        for asset_type in ("webapp", "url"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "")).strip()
                if _is_http(value) and value not in targets:
                    targets.append(value)
        return targets


async def _playwright_available() -> bool:
    try:
        import playwright.async_api  # noqa: F401
        return True
    except Exception:
        return False


async def _render_page(url: str, config: dict, wait_ms: int = 1500) -> dict:
    from playwright.async_api import async_playwright

    links: set[str] = set()
    scripts: set[str] = set()
    forms: set[str] = set()
    source_maps: set[str] = set()
    dom_sinks: list[dict] = []
    auth_headers = _auth_headers(config)
    auth_cookies = _auth_cookies(config, url)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(extra_http_headers=auth_headers)
        if auth_cookies:
            await context.add_cookies(auth_cookies)
        page = await context.new_page()

        async def capture_response(response):
            resp_url = response.url
            ctype = (response.headers or {}).get("content-type", "")
            is_js = resp_url.endswith(".js") or "javascript" in ctype
            if not is_js:
                return
            scripts.add(resp_url)
            try:
                text = await response.text()
            except Exception:
                return
            for map_ref in re.findall(r"sourceMappingURL=([^\s'\"<>]+\.map)", text):
                source_maps.add(urljoin(resp_url, map_ref))
            dom_sinks.extend(extract_dom_sinks(text, resp_url))

        page.on("response", capture_response)
        try:
            await page.goto(url, wait_until="networkidle", timeout=max(wait_ms * 10, 15000))
            await page.wait_for_timeout(wait_ms)
            data = await page.evaluate(
                """() => ({
                    links: Array.from(document.querySelectorAll('a[href]')).map(a => a.href),
                    scripts: Array.from(document.querySelectorAll('script[src]')).map(s => s.src),
                    forms: Array.from(document.querySelectorAll('form')).map(f => f.action || location.href),
                    inlineScripts: Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent || '')
                })"""
            )
        except Exception as exc:
            await browser.close()
            return {"error": str(exc), "links": [], "scripts": [], "forms": [], "source_maps": [], "dom_sinks": []}

        await browser.close()

    links.update(_normalize(url, item) for item in data.get("links", []) if item)
    scripts.update(_normalize(url, item) for item in data.get("scripts", []) if item)
    forms.update(_normalize(url, item) for item in data.get("forms", []) if item)
    for inline in data.get("inlineScripts", []):
        dom_sinks.extend(extract_dom_sinks(inline or "", f"{url}#inline-script"))

    return {
        "links": sorted(links),
        "scripts": sorted(scripts),
        "forms": sorted(forms),
        "source_maps": sorted(source_maps),
        "dom_sinks": dom_sinks,
    }


def _auth_headers(config: dict) -> dict:
    auth = config.get("auth", {}) or {}
    headers = {
        str(k): str(v)
        for k, v in (auth.get("headers") or {}).items()
        if k and v is not None and str(v) != "" and str(k).lower() != "cookie"
    }
    bearer = auth.get("bearer_token") or auth.get("token")
    if bearer and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {bearer}"
    return headers


def _auth_cookies(config: dict, url: str) -> list[dict]:
    auth = config.get("auth", {}) or {}
    domain = urlparse(url).hostname or ""
    cookie_items = []
    if isinstance(auth.get("cookies"), dict):
        cookie_items.extend(auth["cookies"].items())
    cookie_header = auth.get("cookie") or auth.get("cookie_header")
    if cookie_header:
        for part in str(cookie_header).split(";"):
            if "=" in part:
                name, value = part.strip().split("=", 1)
                cookie_items.append((name, value))
    return [
        {"name": str(name), "value": str(value), "domain": domain, "path": "/"}
        for name, value in cookie_items
        if name and value is not None
    ]


def _normalize(base_url: str, value: str) -> str:
    return urljoin(base_url, value)


def _is_http(url: str) -> bool:
    return str(url).startswith(("http://", "https://"))


def _looks_api(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(token in path for token in ("/api/", "/graphql", "/rest/", "/v1/", "/v2/"))
