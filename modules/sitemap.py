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
        base_url = f"https://{self.domain}"
        self.log("Checking Yoast/standard sitemaps...")

        all_urls = []

        for path in self.SITEMAP_PATHS:
            result = await curl(f"{base_url}{path}", output="body")
            body = result.get("body", "")
            if not body or "sitemap" not in body.lower():
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

        # Process discovered URLs
        interesting = []
        for url in all_urls:
            if any(kw in url.lower() for kw in ["test", "draft", "backup", "old",
                                                  "private", "admin", "dev"]):
                interesting.append(url)

        if interesting:
            self.state.add_finding(
                title="Hidden/Test Pages Discovered via Sitemap",
                severity="LOW",
                confidence="CONFIRMED",
                category="Information Disclosure",
                description=f"{len(interesting)} potentially sensitive pages found "
                            f"in sitemaps.",
                evidence=[f"Pages: {interesting[:10]}"],
                remediation="Review and remove test/draft pages from production.",
            )

        # Check portfolio/custom post type sitemaps for client data
        portfolio_urls = [u for u in all_urls if "portfolio" in u.lower()]
        if portfolio_urls:
            client_names = set()
            for url in portfolio_urls:
                slug = url.rstrip("/").split("/")[-1]
                name = slug.replace("-", " ").title()
                client_names.add(name)

            self.state.add_finding(
                title="Full Client Portfolio Exposed via Sitemap",
                severity="LOW",
                confidence="CONFIRMED",
                category="Information Disclosure",
                description=f"{len(client_names)} client portfolio entries are "
                            f"enumerable via Yoast portfolio sitemap.",
                evidence=[f"Clients: {sorted(client_names)[:30]}",
                          f"Source: portfolio_page-sitemap.xml"],
                remediation="Consider excluding portfolio from sitemaps.",
            )

        self.state.complete_module(self.id)
        self.log(f"Sitemaps: {len(all_urls)} total URLs, {len(interesting)} interesting")
        return "done"
