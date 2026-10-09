"""Stage 4: Browser-rendered crawling for JavaScript-heavy applications.

Two upgrades over the original single-context render pass:

- Authenticated contexts. The crawl used to replay only the static
  `auth.cookies`/`auth.headers` with no idea whether the session was
  alive — an expired cookie meant a logged-out crawl mislabelled as
  authenticated. Now every verified AuthHarness identity (static
  config sessions, scripted logins, or sessions auth_audit captured
  mid-run) gets its own browser context with its live cookies, plus
  the anonymous baseline. Each context's evidence says which identity
  rendered it and whether that identity verified.
- Depth. Same-origin links are followed to a configured depth with a
  per-context page cap, so multi-page flows behind a login are
  reachable. Cross-origin links are recorded, never followed: the
  crawl stays on the target it was authorised for.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from core.auth_harness import AuthHarness
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

        crawl_cfg = self.config.get("crawl", {}).get("browser", {})
        if crawl_cfg.get("enabled", True) is False:
            self.state.skip_module(self.id, "disabled in config")
            return "skipped"
        try:
            max_pages = max(1, min(50, int(crawl_cfg.get("max_targets", 8))))
        except (TypeError, ValueError):
            max_pages = 8
        try:
            depth = max(0, min(3, int(crawl_cfg.get("depth", 1) or 0)))
        except (TypeError, ValueError):
            depth = 1
        try:
            max_identities = max(0, min(5, int(crawl_cfg.get("max_identities", 2))))
        except (TypeError, ValueError):
            max_identities = 2
        wait_ms = int(crawl_cfg.get("wait_ms", 1500))

        seeds = self._targets() or [self.base_url]

        # Verified sessions only: an unverified identity is a cookie that
        # may have expired, and rendering as it proves nothing about the
        # authenticated surface. Anonymous always runs as the baseline.
        harness = AuthHarness(self.config)
        harness.adopt_discovered(self.state, log=self.log)
        verified = []
        try:
            verified = await harness.establish_all(self.base_url)
        except Exception as exc:
            self.log(f"  identity establishment failed: {exc}")
        contexts = [("anonymous", None, None, False)]
        for identity in (verified or [])[:max_identities]:
            cookies = dict(identity.cookies or {})
            headers = dict((identity.headers or {}))
            if identity.bearer_token and "Authorization" not in headers:
                headers["Authorization"] = f"Bearer {identity.bearer_token}"
            contexts.append((identity.name, cookies, headers, True))
        self.log(f"  crawl contexts: "
                 f"{', '.join(name for name, *_ in contexts)}")

        discovered: set[str] = set()
        js_urls: set[str] = set()
        source_maps: set[str] = set()
        dom_sinks: list[dict] = []
        evidence_refs = []
        context_stats: list[dict] = []

        for name, cookies, headers, authenticated in contexts:
            rendered = await self._crawl_context(
                name, seeds, depth, max_pages, wait_ms, cookies, headers)
            discovered.update(rendered["links"])
            discovered.update(rendered["forms"])
            js_urls.update(rendered["scripts"])
            source_maps.update(rendered["source_maps"])
            dom_sinks.extend(rendered["dom_sinks"])
            context_stats.append({
                "identity": name,
                "authenticated": authenticated,
                "pages": rendered["pages"],
                "links": len(rendered["links"]),
                "scripts": len(rendered["scripts"]),
            })
            evidence_refs.append(
                self.state.add_evidence(
                    self.id,
                    "browser_render",
                    self.base_url,
                    {
                        "identity": name,
                        "authenticated": authenticated,
                        "pages_rendered": rendered["pages"],
                        "links": sorted(rendered["links"])[:200],
                        "scripts": sorted(rendered["scripts"])[:100],
                        "forms": sorted(rendered["forms"])[:100],
                        "source_maps": sorted(rendered["source_maps"])[:50],
                        "dom_sinks": rendered["dom_sinks"][:50],
                        "errors": rendered["errors"][:10],
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
                "contexts": context_stats,
                "urls": len(http_urls),
                "js_files": len(js_urls),
                "source_maps": len(source_maps),
                "dom_sinks": len(dom_sinks),
            },
        )
        self.state.complete_module(self.id)
        self.log(
            f"Rendered crawl: {len(http_urls)} URLs | {len(js_urls)} JS | "
            f"{len(source_maps)} source maps | {len(dom_sinks)} DOM sinks | "
            f"{len(context_stats)} context(s)"
        )
        return "done"

    async def _crawl_context(self, name: str, seeds: list, depth: int,
                             max_pages: int, wait_ms: int,
                             cookies: dict | None,
                             headers: dict | None) -> dict:
        """BFS render queue for one identity: same-origin links followed
        to `depth`, total pages capped. Cross-origin links are recorded
        as discovered assets by the caller, never rendered here."""
        base_host = _hostname(self.base_url)
        queue: list[tuple[str, int]] = [(s, 0) for s in seeds[:max_pages]]
        visited: set[str] = set()
        links: set[str] = set()
        forms: set[str] = set()
        scripts: set[str] = set()
        source_maps: set[str] = set()
        sinks: list = []
        pages: list[str] = []
        errors: list[str] = []
        while queue and len(pages) < max_pages:
            url, level = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            rendered = await _render_page(url, self.config, wait_ms=wait_ms,
                                          cookies=cookies, headers=headers)
            if rendered.get("error"):
                errors.append(f"{url}: {rendered['error']}"[:200])
                continue
            pages.append(url)
            links.update(rendered.get("links", []))
            forms.update(rendered.get("forms", []))
            scripts.update(rendered.get("scripts", []))
            source_maps.update(rendered.get("source_maps", []))
            sinks.extend(rendered.get("dom_sinks", []))
            if level < depth:
                for link in rendered.get("links", []):
                    if (link not in visited
                            and _hostname(link) == base_host
                            and len(pages) + len(queue) < max_pages * 2):
                        queue.append((link, level + 1))
        return {"links": links, "forms": forms, "scripts": scripts,
                "source_maps": source_maps, "dom_sinks": sinks,
                "pages": pages, "errors": errors}

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


async def _render_page(url: str, config: dict, wait_ms: int = 1500,
                     cookies: dict | None = None,
                     headers: dict | None = None) -> dict:
    from playwright.async_api import async_playwright

    links: set[str] = set()
    scripts: set[str] = set()
    forms: set[str] = set()
    source_maps: set[str] = set()
    dom_sinks: list[dict] = []
    # Explicit session material wins (per-identity contexts); None falls
    # back to the static config session, preserving old callers.
    auth_headers = dict(headers) if headers is not None else _auth_headers(config)
    if cookies is None:
        auth_cookies = _auth_cookies(config, url)
    else:
        domain = _hostname(url)
        auth_cookies = [
            {"name": str(k), "value": str(v), "domain": domain, "path": "/"}
            for k, v in cookies.items() if k and v is not None
        ]

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
