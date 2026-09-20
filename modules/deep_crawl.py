"""Stage 4: Low-rate crawling for endpoint and form discovery."""

from urllib.parse import urlparse

from modules.base import BaseModule
from tools.external import hakrawler_crawl, katana_crawl, tool_available


class DeepCrawl(BaseModule):
    id = "deep_crawl"
    name = "Deep Crawl"
    stage = 4
    detectability = "medium"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        targets = self._targets()
        if not targets:
            targets = [f"https://{self.domain}"]

        if not tool_available("katana") and not tool_available("hakrawler"):
            self.state.skip_module(self.id, "katana/hakrawler not installed")
            return "skipped"

        discovered = set()
        evidence_refs = []
        depth = int(self.config.get("crawl", {}).get("depth", 2))
        for target in targets[:10]:
            if not self.scope.check(target).allowed:
                continue
            source_results = {}
            if tool_available("katana"):
                urls = await katana_crawl(target, depth=depth, timeout=180)
                source_results["katana"] = urls
                discovered.update(urls)
            if tool_available("hakrawler"):
                urls = await hakrawler_crawl(target, depth=depth, timeout=180)
                source_results["hakrawler"] = urls
                discovered.update(urls)
            evidence_refs.append(
                self.state.add_evidence(
                    self.id,
                    "crawl",
                    target,
                    {
                        "target": target,
                        "depth": depth,
                        "results": source_results,
                    },
                )
            )

        in_scope_urls = [
            url for url in sorted(discovered)
            if self.scope.check(url).allowed and _is_http(url)
        ]
        for url in in_scope_urls[:1000]:
            asset_type = "api_endpoint" if _looks_api(url) else "url"
            self.state.add_asset(
                asset_type,
                f"{asset_type}:{url}",
                url,
                confidence="FIRM",
                sources=[self.id],
                attrs={"path": urlparse(url).path, "query": urlparse(url).query},
            )
            self.state.add_edge(f"domain:{self.domain}", f"{asset_type}:{url}", "crawled_url")

        api_urls = [url for url in in_scope_urls if _looks_api(url)]
        admin_urls = [url for url in in_scope_urls if _looks_admin(url)]
        if api_urls or admin_urls:
            self.state.add_finding(
                title="Crawl Discovered High-Value Endpoints",
                severity="LOW",
                confidence="FIRM",
                category="Attack Surface",
                description=(
                    f"Crawling found {len(api_urls)} API-like and "
                    f"{len(admin_urls)} admin/internal-looking endpoints."
                ),
                evidence=(api_urls[:8] + admin_urls[:8])[:15],
                evidence_refs=evidence_refs,
                asset_keys=[f"url:{url}" for url in (api_urls + admin_urls)[:10]],
                remediation="Review endpoint exposure, authentication, and authorization boundaries.",
            )

        self.state.add_asset(
            "crawl_summary",
            f"crawl:{self.domain}",
            self.domain,
            confidence="FIRM",
            sources=[self.id],
            attrs={"targets": targets, "urls": len(in_scope_urls)},
        )
        self.state.complete_module(self.id)
        self.log(f"Crawl URLs: {len(in_scope_urls)}")
        return "done"

    def _targets(self) -> list[str]:
        targets = []
        for asset_type in ("webapp", "url"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "")).strip()
                if _is_http(value) and value not in targets:
                    targets.append(value)
        return targets


def _is_http(url: str) -> bool:
    return str(url).startswith(("http://", "https://"))


def _looks_api(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(token in path for token in ("/api/", "/graphql", "/rest/", "/v1/", "/v2/"))


def _looks_admin(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(token in path for token in ("/admin", "/dashboard", "/manage", "/internal"))
