"""Stage 2: Email Harvesting — page scrape + pattern derivation."""

import re
from modules.base import BaseModule
from tools.wrappers import curl


class EmailHarvest(BaseModule):
    id = "email_harvest"
    name = "Email Harvest"
    stage = 2
    detectability = "low"
    depends_on = ["seed_discovery"]

    EMAIL_RE = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+')
    NAME_RE = re.compile(r'(?:^|\s)([A-Z][a-zéèêëàâäùûüôöîïç]+(?:\s[A-Z][a-zéèêëàâäùûüôöîïç-]+)+)')
    PHONE_RE = re.compile(r'\+?[\d\s\-\.\(\)]{10,20}')

    async def run(self) -> str:
        self.log(f"Harvesting emails from {self.domain}")

        # 1. Scrape homepage
        urls_to_scrape = [f"https://{self.domain}"]
        # Get known pages from subdomains and sitemap
        webapps = self.state.get_assets_by_type("webapp")
        for wa in webapps:
            if wa["value"] not in urls_to_scrape:
                urls_to_scrape.append(wa["value"])

        all_emails = set()
        all_names = []
        all_phones = set()

        for url in urls_to_scrape:
            result = await curl(url, output="body")
            body = result.get("body", "")

            # Emails
            emails = self.EMAIL_RE.findall(body)
            for e in emails:
                e = e.lower().strip()
                if e not in all_emails and not e.endswith((".example.com", ".png", ".jpg", ".css", ".js")):
                    all_emails.add(e)

        # 2. WP REST API for more emails (if WP detected)
        wp_json = await curl(f"https://{self.domain}/wp-json/wp/v2/pages?per_page=100",
                              output="body")
        body = wp_json.get("body", "")
        if body:
            emails = self.EMAIL_RE.findall(body)
            for e in emails:
                e = e.lower().strip()
                if e not in all_emails:
                    all_emails.add(e)

        # 3. Pattern derivation
        email_domain = self._derive_email_domain(list(all_emails))
        pattern = self._derive_pattern(list(all_emails))

        # 4. Store
        for email in sorted(all_emails):
            local, _, domain_part = email.partition("@")
            if domain_part:
                self.state.add_asset(
                    "email",
                    f"email:{email}",
                    email,
                    confidence="TENTATIVE",
                    sources=["page scrape"],
                    attrs={"domain": domain_part, "local": local},
                )
                self.state.add_edge(
                    f"email:{email}",
                    f"domain:{self.domain}",
                    "RELATED_TO",
                )

        self.state.add_asset(
            "email_pattern",
            f"email_pattern:{self.domain}",
            self.domain,
            confidence="FIRM" if pattern != "unknown" else "TENTATIVE",
            sources=["email harvest"],
            attrs={
                "total_emails": len(all_emails),
                "primary_domain": email_domain,
                "pattern": pattern,
                "sample_emails": sorted(list(all_emails))[:20],
            },
        )

        self.state.complete_module(self.id)
        self.log(f"Emails: {len(all_emails)} found | Domain: {email_domain} | Pattern: {pattern}")
        return "done"

    def _derive_email_domain(self, emails: list) -> str:
        """Find the most common email domain."""
        domains = {}
        for e in emails:
            _, _, domain = e.partition("@")
            if domain:
                domains[domain] = domains.get(domain, 0) + 1
        if domains:
            return max(domains, key=domains.get)
        return ""

    def _derive_pattern(self, emails: list) -> str:
        """Derive email pattern from known names."""
        for email in emails:
            local, _, domain = email.partition("@")
            if not domain or domain == self.domain:
                continue
            # Pattern: first.last
            if "." in local and not local.startswith("info") and not local.startswith("contact"):
                parts = local.split(".")
                if len(parts) == 2:
                    return "{first}.{last}"
            # Pattern: first_initial + last
            if len(local) > 2 and local[0].isalpha():
                # e.g. rbranquart → r + branquart
                return "{first_initial}{last}"
        return "unknown"
