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

        targets = self._targets() or [self.base_url]
        crawl_cfg = self.config.get("crawl", {}).get("browser", {})
        max_targets = int(crawl_cfg.get("max_targets", 8))
        wait_ms = int(crawl_cfg.get("wait_ms", 1500))

        discovered: set[str] = set()
        js_urls: set[str] = set()
        source_maps: set[str] = set()
        dom_sinks: list[dict] = []
        evidence_refs = []

        for target in targets[:max_targets]:
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

        http_urls = [url for url in sorted(discovered) if _is_http(url)]
        for url in http_urls[:1000]:
            asset_type = "api_endpoint" if _looks_api(url) else "url"
            self.state.add_asset(
                asset_type,
                f"{asset_type}:{url}",
                url,
                confidence="FIRM",
                sources=[self.id],
                attrs={"path": urlparse(url).path, "query": urlparse(url).query},
            )
            self.state.add_edge(f"domain:{self.domain}", f"{asset_type}:{url}", "DISCOVERED_VIA")

        for js_url in sorted(js_urls)[:200]:
            self.state.add_asset(
                "js_file",
                f"js:{js_url}",
                js_url,
                confidence="FIRM",
                sources=[self.id],
                attrs={"rendered": True},
            )

        for map_url in sorted(source_maps)[:100]:
            self.state.add_asset(
                "source_map",
                f"source_map:{map_url}",
                map_url,
                confidence="FIRM",
                sources=[self.id],
                attrs={"rendered": True},
            )

        # Confirm maps that parse as JSON with sourcesContent: a sourcemap
        # reference is a hint, a fetched map with original sources is
        # exposure. Bounded and cheap (first few only).
        await self._confirm_source_maps(sorted(source_maps)[:5])

        # Sinks are inventory, not a finding — same rule as js_analysis:
        # a sink inventory (including postMessage/onmessage entry points)
        # carries no signal until a source-to-sink flow is traced. They
        # stay as dom_sink assets for anyone who wants the list.
        seen_sinks = set()
        for item in dom_sinks[:200]:
            key = (item.get("sink"), item.get("source"), item.get("snippet", "")[:80])
            if key in seen_sinks:
                continue
            seen_sinks.add(key)
            self.state.add_asset(
                "dom_sink",
                f"dom_sink:{item.get('source', 'inline')}:{len(seen_sinks)}",
                str(item.get("sink", "")),
                confidence="TENTATIVE",
                sources=[self.id],
                attrs={"source": item.get("source", "inline"),
                       "snippet": str(item.get("snippet", ""))[:200]},
            )

        self.state.add_asset(
            "browser_crawl_summary",
            f"browser_crawl:{self.domain}",
            self.domain,
            confidence="FIRM",
            sources=[self.id],
            attrs={
                "targets": targets[:max_targets],
                "urls": len(http_urls),
                "js_files": len(js_urls),
                "source_maps": len(source_maps),
                "dom_sinks": len(dom_sinks),
            },
        )
        self.state.complete_module(self.id)
        self.log(
            f"Rendered crawl: {len(http_urls)} URLs | {len(js_urls)} JS | "
            f"{len(source_maps)} source maps | {len(dom_sinks)} DOM sinks"
        )
        return "done"

    async def _confirm_source_maps(self, map_urls: list) -> None:
        """Fetch candidate maps: JSON with sources is exposure.

        No status gate: a catch-all 200 with an HTML shell fails the JSON
        parse below, which is the actual proof. A 200 literal here would
        re-teach the bare-status shortcut the blind-trust test forbids.
        """
        from tools.wrappers import curl as _curl
        import json as _json
        for map_url in map_urls:
            try:
                result = await _curl(map_url, output="body", timeout=12)
            except Exception:
                continue
            body = (result.get("body", "") or "").strip()
            if not body.startswith("{"):
                continue
            try:
                document = _json.loads(body)
            except (ValueError, TypeError):
                continue
            if not isinstance(document, dict):
                continue
            sources = document.get("sources", []) or []
            has_content = bool(document.get("sourcesContent"))
            if sources:
                files = [str(s).split("/")[-1] for s in sources[:8]]
                self.state.add_finding(
                    title=f"Source Map Exposes Original Source: {map_url}",
                    severity="MEDIUM" if has_content else "LOW",
                    confidence="CONFIRMED",
                    category="Information Disclosure",
                    description=(
                        f"Source map at {map_url} serves "
                        f"{len(sources)} original source file(s)"
                        f"{' with embedded sourcesContent' if has_content else ''}."
                    ),
                    evidence=[f"Map: {map_url}",
                              f"Sources: {', '.join(files)}"],
                    remediation="Remove .map files from production deployments.",
                    asset_keys=[f"url:{map_url}"],
                    verified=True,
                    verification={"method": "sourcemap_json_parse",
                                  "url": map_url},
                )

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


def _hostname(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        # CPython 3.14 raises "Invalid IPv6 URL" for a netloc whose brackets
        # do not pair. Asset values are written by other modules, so a
        # malformed one costs a cookie scope, not the whole crawl.
        return ""


def _auth_cookies(config: dict, url: str) -> list[dict]:
    auth = config.get("auth", {}) or {}
    domain = _hostname(url)
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
