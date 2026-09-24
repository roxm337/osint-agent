"""Stage 3: Social Media Discovery — verified platform hits only."""

import re

from modules.base import BaseModule
from tools.wrappers import curl


# Common non-brand prefixes to strip when deriving the org slug.
_STRIP_PREFIXES = {"www", "api", "app", "apps", "mail", "web", "portal", "login"}


class SocialMedia(BaseModule):
    id = "social_media"
    name = "Social Media Discovery"
    stage = 3
    detectability = "low"
    depends_on = ["seed_discovery"]

    PLATFORMS = [
        {
            "name": "LinkedIn",
            "url": "https://www.linkedin.com/company/{slug}",
            "verify": lambda body, status, url: (
                status == 200 and "linkedin.com/company" in url
                and '"@type":"organization"' in body.lower()
            ) or (
                status == 200 and "/company/" in url
                and "linkedin" in body.lower()
                and "page not found" not in body.lower()
            ),
        },
        {
            "name": "Twitter/X",
            "url": "https://twitter.com/{slug}",
            "verify": lambda body, status, url: (
                status == 200
                and f"/{url.rstrip('/').split('/')[-1]}" in body
                and "doesn't exist" not in body.lower()
                and "this account doesn" not in body.lower()
            ),
        },
        {
            "name": "Facebook",
            "url": "https://www.facebook.com/{slug}/",
            "verify": lambda body, status, url: (
                status == 200
                and "content isn't available" not in body.lower()
                and "page isn't available" not in body.lower()
                and "facebook.com/login" not in url
            ),
        },
        {
            "name": "Instagram",
            "url": "https://www.instagram.com/{slug}/",
            "verify": lambda body, status, url: (
                status == 200
                and "/accounts/login/" not in url
                and '"username":"' + url.rstrip('/').split('/')[-1] + '"' in body
            ),
        },
        {
            "name": "YouTube",
            "url": "https://www.youtube.com/@{slug}",
            "verify": lambda body, status, url: (
                status == 200
                and '"@type":"person"' in body.lower()
                and "this page isn't available" not in body.lower()
            ),
        },
        {
            "name": "GitHub",
            "url": "https://github.com/{slug}",
            "verify": lambda body, status, url: (
                status == 200
                and f"<title>{url.rstrip('/').split('/')[-1]}" in body.lower()
            ),
        },
    ]

    async def run(self) -> str:
        self.log("Discovering social media accounts...")
        slugs = self._derive_slugs()
        if not slugs:
            self.state.skip_module(self.id, "no plausible org slugs")
            return "skipped"

        self.log(f"  Candidate slugs: {slugs}")

        found_accounts = []
        for platform in self.PLATFORMS:
            for slug in slugs:
                url = platform["url"].format(slug=slug)
                # Use full output so we can inspect the body for verification.
                result = await curl(url, output="full", follow_redirects=True, timeout=15)
                status = result.get("status", 0)
                body = result.get("body", "") or ""

                try:
                    verified = platform["verify"](body, status, url)
                except Exception:
                    verified = False

                if verified:
                    found_accounts.append({
                        "platform": platform["name"],
                        "url": url,
                        "slug": slug,
                        "status": status,
                    })
                    self.state.add_asset(
                        "social_media",
                        f"social:{platform['name']}:{slug}",
                        url,
                        confidence="CONFIRMED",
                        sources=[f"verified HTTP check ({platform['name']})"],
                        attrs={
                            "platform": platform["name"],
                            "slug": slug,
                            "status": status,
                            "verified": True,
                        },
                    )
                    self.log(f"  {platform['name']}: {url}")
                    break

        if found_accounts:
            self.state.add_finding(
                title=f"Social Media Accounts: {len(found_accounts)} verified",
                severity="INFO",
                confidence="CONFIRMED",
                category="Attack Surface",
                description=(
                    f"{len(found_accounts)} social media accounts confirmed via "
                    f"platform-specific verification. These expand the phishing "
                    f"surface and can reveal additional organizational context."
                ),
                evidence=[
                    f"{a['platform']}: {a['url']} (slug: {a['slug']})"
                    for a in found_accounts
                ],
                remediation="Monitor for impersonation; tag official accounts.",
                verified=True,
                verification={
                    "method": "platform_specific_signature",
                    "accounts": found_accounts,
                },
            )

        self.state.complete_module(self.id)
        self.log(f"Social media: {len(found_accounts)} verified of "
                 f"{len(self.PLATFORMS) * len(slugs)} probed")
        return "done"

    def _derive_slugs(self) -> list:
        """Derive plausible organization slugs from the target domain.

        Skips known-subdomain prefixes (www, api, app, ...) and prefers the
        registrable domain's second-level label.
        """
        parts = self.domain.strip().lower().split(".")
        # Strip common prefix subdomains.
        while len(parts) > 2 and parts[0] in _STRIP_PREFIXES:
            parts = parts[1:]
        if len(parts) < 2:
            return []

        # Take the label immediately left of the TLD.
        base = parts[-2] if len(parts) >= 2 else parts[0]

        candidates = {
            base,
            base.replace("-", ""),
            base.replace("-", "_"),
        }
        # Full hyphenated domain without TLD, for compound names.
        if len(parts) > 2:
            candidates.add("-".join(parts[:-1]))

        # Reject junk.
        candidates = {
            c for c in candidates
            if c and len(c) >= 3 and c not in _STRIP_PREFIXES
        }
        return sorted(candidates)
