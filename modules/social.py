"""Stage 3: Social Media Discovery — LinkedIn, Twitter, Facebook, etc."""

from modules.base import BaseModule
from tools.wrappers import curl


class SocialMedia(BaseModule):
    id = "social_media"
    name = "Social Media Discovery"
    stage = 3
    detectability = "low"
    depends_on = ["seed_discovery"]

    PLATFORMS = [
        {"name": "LinkedIn", "url": "https://www.linkedin.com/company/{slug}"},
        {"name": "Twitter/X", "url": "https://twitter.com/{slug}"},
        {"name": "Facebook", "url": "https://www.facebook.com/{slug}/"},
        {"name": "Instagram", "url": "https://www.instagram.com/{slug}/"},
        {"name": "YouTube", "url": "https://www.youtube.com/@{slug}"},
        {"name": "GitHub", "url": "https://github.com/{slug}"},
    ]

    async def run(self) -> str:
        self.log("Discovering social media accounts...")
        base_name = self.domain.split(".")[0]

        # Derive candidate slugs
        slugs = [
            base_name,
            base_name.replace("-", ""),
            f"{base_name}official",
        ]

        found_accounts = []

        for platform in self.PLATFORMS:
            for slug in slugs:
                url = platform["url"].format(slug=slug)
                result = await curl(url, output="status")
                status = result.get("status", 0)

                if status in (200, 301, 302):
                    found_accounts.append({
                        "platform": platform["name"],
                        "url": url,
                        "status": status,
                    })
                    self.state.add_asset(
                        "social_media",
                        f"social:{platform['name']}:{slug}",
                        url,
                        confidence="FIRM",
                        sources=[f"HTTP check"],
                        attrs={"platform": platform["name"], "slug": slug, "status": status},
                    )
                    self.log(f"  {platform['name']}: {url}")
                    break  # Found on this platform, move on

        if found_accounts:
            self.state.add_finding(
                title=f"Social Media Accounts Found: {len(found_accounts)}",
                severity="INFO",
                confidence="CONFIRMED",
                category="Attack Surface",
                description=f"{len(found_accounts)} social media accounts identified "
                            f"for the target, providing additional phishing surface.",
                evidence=[f"{a['platform']}: {a['url']}" for a in found_accounts],
                remediation="Monitor for impersonator accounts.",
            )

        self.state.complete_module(self.id)
        return "done"
