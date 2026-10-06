"""Stage 4: Sitemap Exploit — discover hidden pages and content."""

import re
from modules.base import BaseModule
from tools.wrappers import curl


class SitemapExploit(BaseModule):
    id = "sitemap_exploit"
    name = "Sitemap Exploit"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]

    SITEMAP_PATHS = [
        "/sitemap_index.xml",
        "/sitemap.xml",
        "/page-sitemap.xml",
        "/post-sitemap.xml",
        "/portfolio_page-sitemap.xml",
        "/author-sitemap.xml",
        "/category-sitemap.xml",
    ]

    async def run(self) -> str:
        base_url = self.base_url
        self.log("Checking Yoast/standard sitemaps...")

        all_urls = []

        for path in self.SITEMAP_PATHS:
            result = await curl(f"{base_url}{path}", output="body")
            body = result.get("body", "") or ""
            lowered = body.lower()
            # An error page can mention "sitemap" without being one; a
            # sitemap names itself in the root element and lists locations.
            if "<urlset" not in lowered and "<sitemapindex" not in lowered:
                continue

            # Extract all URLs from XML
            urls = re.findall(r'<loc>(.*?)</loc>', body)
            if urls:
                self.state.add_asset(
                    "webapp",
                    f"webapp:{base_url}{path}",
                    f"{base_url}{path}",
                    confidence="CONFIRMED",
                    sources=["sitemap probe"],
                    attrs={"urls_found": len(urls), "sample_urls": urls[:20]},
                )
                all_urls.extend(urls)
                self.log(f"  {path}: {len(urls)} URLs")

                # If sub-sitemap found (sitemap index), fetch each sub-sitemap
                sub_sitemaps = re.findall(r'<loc>(.*?sitemap.*?\.xml)</loc>', body)
                for sub in sub_sitemaps:
                    sub_result = await curl(sub, output="body")
                    sub_body = sub_result.get("body", "")
                    sub_urls = re.findall(r'<loc>(.*?)</loc>', sub_body)
                    if sub_urls:
                        all_urls.extend(sub_urls)
                        self.log(f"    {sub}: {len(sub_urls)} URLs")

        # Process discovered URLs: substring matches are leads until a
        # live fetch through the site profile says otherwise. A sitemap
        # entry for /blog/old-posts is content, not a finding.
        interesting = []
        for url in all_urls:
            if any(kw in url.lower() for kw in ["test", "draft", "backup", "old",
                                                  "private", "admin", "dev"]):
                interesting.append(url)

        live_interesting = await self._live_filter(base_url, interesting[:10])
        if live_interesting:
            self.state.add_finding(
                title="Hidden/Test Pages Reachable via Sitemap",
                severity="LOW",
                confidence="FIRM",
                category="Information Disclosure",
                description=f"{len(live_interesting)} potentially sensitive pages from "
                            f"sitemaps answer live with distinct content.",
                evidence=[f"Pages: {live_interesting[:10]}"],
                remediation="Review and remove test/draft pages from production.",
            )
        elif interesting:
            self.log(f"  {len(interesting)} sitemap keyword hits, none live — skipping")

        # Check portfolio/custom post type sitemaps for client data.
        # Public marketing content by design: inventoried for OSINT at
        # INFO, never a LOW that reads as exposure.
        portfolio_urls = [u for u in all_urls if "portfolio" in u.lower()]
        if portfolio_urls:
            client_names = set()
            for url in portfolio_urls:
                slug = url.rstrip("/").split("/")[-1]
                name = slug.replace("-", " ").title()
                client_names.add(name)

            self.state.add_finding(
                title="Client Portfolio Enumerable via Sitemap",
                severity="INFO",
                confidence="FIRM",
                category="Information Disclosure",
                description=f"{len(client_names)} client portfolio entries are "
                            f"enumerable via Yoast portfolio sitemap. Public "
                            f"content — useful for targeting, not a vulnerability.",
                evidence=[f"Clients: {sorted(client_names)[:30]}",
                          f"Source: portfolio_page-sitemap.xml"],
                remediation="No action required; use for engagement scoping.",
            )

        self.state.complete_module(self.id)
        self.log(f"Sitemaps: {len(all_urls)} total URLs, {len(interesting)} interesting")
        return "done"

    async def _live_filter(self, base_url: str, urls: list) -> list:
        """Keep only sitemap URLs that answer live with distinct content.

        Judged through the shared site profile so SPA catch-alls and
        parked pages do not launder dead sitemap entries into findings.
        """
        import asyncio
        from urllib.parse import urlparse
        from core.response_fingerprint import fingerprint as make_fingerprint
        from core.site_profile import get_profile

        try:
            parsed = urlparse(base_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            return []

        async def fetch(path: str):
            try:
                result = await curl(origin + path, output="body", timeout=10)
            except Exception:
                return 0, "", ""
            return (result.get("status", 0),
                    result.get("body", "") or "", "")

        try:
            profile = await get_profile(origin, fetch)
        except Exception:
            profile = None

        semaphore = asyncio.Semaphore(6)

        async def check(url: str):
            try:
                path = urlparse(url).path or "/"
                if urlparse(url).query:
                    path += "?" + urlparse(url).query
            except Exception:
                return None
            status, body, _ = await fetch(path)
            if status != 200 or not body:
                return None
            if profile is not None and profile.baseline.catch_all(
                    make_fingerprint(status, body)):
                return None
            return url

        probed = await asyncio.gather(
            *(check(url) for url in urls), return_exceptions=True)
        return [url for url in probed if isinstance(url, str)]
