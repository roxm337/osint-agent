"""Stage 4: Low-rate crawling for endpoint and form discovery.

A crawled URL is a stronger signal than a guessed one: the crawler followed a
real link, so the path's existence is established, and the assets here are
FIRM on that basis. What is not established is what the path *is*.

The previous version reported "Crawl Discovered High-Value Endpoints" as a
LOW/FIRM finding, which asserted as fact what is a substring guess. The
matchers were unanchored, so `/blog/manage-your-account` scored as an admin
endpoint and `/v1/` matched any path containing it. A blog post about managing
your account is not a management console.

The matchers below are now segment-aware — they look at whole path segments
rather than substrings — and the finding is reported as INFO discovery with
TENTATIVE confidence, because "this path exists and its name suggests it is an
API" is a lead to investigate, not a weakness. Nothing here is a vulnerability
until something shows that a request to the path should have been refused.
"""

from urllib.parse import urlparse

from modules.base import BaseModule
from tools.external import hakrawler_crawl, katana_crawl, tool_available


# Whole path segments, so "/blog/manage-your-account" is a blog post rather
# than a management console.
API_SEGMENTS = {"api", "graphql", "rest", "v1", "v2", "v3", "rpc", "ajax"}
ADMIN_SEGMENTS = {"admin", "administrator", "dashboard", "manage", "management",
                  "panel", "console", "cp", "cpanel", "internal", "backend",
                  "actuator", "phpmyadmin"}

# Prefixed admin paths that are conventional enough to be worth naming.
# Prefix matching is avoided generally: "administrators" starts with
# "administrator", which would put /news/administrators-meet back in the
# admin bucket. /wp-admin is common enough to name outright.
PREFIXED_ADMIN_SEGMENTS = {"wp-admin", "wp-login", "wp-config", "administrator",
                           "admin-panel", "admin-login", "my-admin"}


def _segments(url: str) -> list:
    """Lowercased path segments, ignoring empty and dot segments."""
    return [s for s in urlparse(str(url)).path.lower().split("/") if s and s != "."]


def _looks_api(url: str) -> bool:
    """Does any whole path segment look like an API namespace?"""
    return any(seg in API_SEGMENTS for seg in _segments(url))


def _looks_admin(url: str) -> bool:
    """Does any whole path segment look like an admin surface?"""
    segments = _segments(url)
    return any(seg in ADMIN_SEGMENTS or seg in PREFIXED_ADMIN_SEGMENTS
               for seg in segments)


class DeepCrawl(BaseModule):
    id = "deep_crawl"
    name = "Deep Crawl"
    stage = 4
    detectability = "medium"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        targets = self._targets()
        if not targets:
            targets = [self.base_url]

        if not tool_available("katana") and not tool_available("hakrawler"):
            self.state.skip_module(self.id, "katana/hakrawler not installed")
            return "skipped"

        discovered = set()
        evidence_refs = []
        depth = int(self.config.get("crawl", {}).get("depth", 2))
        import time
        try:
            _deadline = float(self.config.get("module_timeout", 300) or 300)
        except (TypeError, ValueError):
            _deadline = 300.0
        _stop_at = time.monotonic() + max(60.0, _deadline - 30.0)
        for target in targets[:10]:
            if time.monotonic() >= _stop_at:
                self.log("  Time-box hit — keeping the URLs crawled so far")
                break
            source_results = {}
            remaining = max(30.0, _stop_at - time.monotonic())
            call_timeout = min(180, int(remaining))
            if tool_available("katana"):
                urls = await katana_crawl(target, depth=depth, timeout=call_timeout)
                source_results["katana"] = urls
                discovered.update(urls)
            if tool_available("hakrawler"):
                urls = await hakrawler_crawl(target, depth=depth, timeout=call_timeout)
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

        http_urls = [url for url in sorted(discovered) if _is_http(url)]
        for url in http_urls[:1000]:
            asset_type = "api_endpoint" if _looks_api(url) else "url"
            self.state.add_asset(
                asset_type,
                f"{asset_type}:{url}",
                url,
                # The crawler followed a link to this URL, so its existence is
                # established. That is what FIRM means here — not that the
                # path is safe, or even that it is an API.
                confidence="FIRM",
                sources=[self.id],
                attrs={"path": urlparse(url).path, "query": urlparse(url).query},
            )
            self.state.add_edge(f"domain:{self.domain}", f"{asset_type}:{url}", "DISCOVERED_VIA")

        api_urls = [url for url in http_urls if _looks_api(url)]
        admin_urls = [url for url in http_urls if _looks_admin(url)]
        if api_urls or admin_urls:
            self.state.add_finding(
                title=(
                    f"Crawl found {len(api_urls)} API-like and "
                    f"{len(admin_urls)} admin-like path(s)"
                ),
                severity="INFO",
                # The URLs are real. What they are is inferred from their names.
                confidence="TENTATIVE",
                category="Attack Surface",
                description=(
                    f"Link-following found {len(api_urls)} path(s) with a segment "
                    f"that names an API namespace and {len(admin_urls)} with a "
                    "segment that names an admin surface. Both are reachable and "
                    "linked from the site. This is a map of what to look at, not "
                    "a weakness: a discovered /admin path is expected, and "
                    "nothing here shows that a request to it should have been "
                    "refused. Check whether each is meant to be reachable without "
                    "authentication before treating it as anything more."
                ),
                evidence=(api_urls[:8] + admin_urls[:8])[:15],
                evidence_refs=evidence_refs,
                asset_keys=[f"url:{url}" for url in (api_urls + admin_urls)[:10]],
                remediation=(
                    "Confirm whether each path is intended to be reachable. An "
                    "admin path that needs no authentication is worth reporting; "
                    "one that does is not a finding."
                ),
            )

        self.state.add_asset(
            "crawl_summary",
            f"crawl:{self.domain}",
            self.domain,
            confidence="FIRM",
            sources=[self.id],
            attrs={"targets": targets, "urls": len(http_urls),
                   "api_like": len(api_urls), "admin_like": len(admin_urls)},
        )
        self.state.complete_module(self.id)
        self.log(
            f"Crawl URLs: {len(http_urls)} "
            f"({len(api_urls)} API-like, {len(admin_urls)} admin-like)"
        )
        return "done"

    def _targets(self) -> list:
        targets = []
        for asset_type in ("webapp", "url"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "")).strip()
                if _is_http(value) and value not in targets:
                    targets.append(value)
        return targets


def _is_http(url: str) -> bool:
    return str(url).startswith(("http://", "https://"))
