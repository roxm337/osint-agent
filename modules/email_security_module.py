"""Stage 3: Email Security Audit — SPF, DMARC, DKIM, BIMI, MTA-STS."""

from modules.base import BaseModule
from tools.wrappers import dig


class EmailSecurity(BaseModule):
    id = "email_security"
    name = "Email Security Audit"
    stage = 3
    detectability = "low"
    depends_on = ["seed_discovery"]

    async def run(self) -> str:
        self.log(f"Email security audit for {self.domain}")

        # Check primary domain
        await self._check_domain(self.domain, "primary")

        # Check discovered email domains
        email_domains = self.state.get_assets_by_type("email_domain")
        for asset in email_domains:
            edomain = asset.get("value", "")
            if edomain and edomain != self.domain:
                await self._check_domain(edomain, "email")

        self.state.complete_module(self.id)
        return "done"

    async def _check_domain(self, domain: str, role: str):
        self.log(f"  Checking {domain} ({role})...")

        # SPF
        spf = await dig("TXT", domain)
        spf_records = [a for a in spf.get("answers", []) if a.startswith("v=spf1")]
        spf_record = spf_records[0] if spf_records else ""

        # DMARC (use full dig to follow CNAME chains like dmarc.ionos.fr)
        dmarc = await dig("TXT", f"_dmarc.{domain}", follow_cname=True)
        dmarc_records = [a for a in dmarc.get("answers", [])
                         if "v=DMARC1" in a or "p=" in a]
        # Fallback: parse raw to handle CNAME responses
        if not dmarc_records:
            raw = dmarc.get("raw", "")
            for line in raw.split("\n"):
                if "v=DMARC1" in line or 'p=' in line:
                    dmarc_records.append(line.strip())

        # DKIM selectors
        dkim_selectors = []
        for sel in ["google", "selector1", "default", "mail", "k1", "s1", "s2"]:
            dkim = await dig("TXT", f"{sel}._domainkey.{domain}")
            if dkim.get("answers"):
                dkim_selectors.append(sel)

        # BIMI
        bimi = await dig("TXT", f"default._bimi.{domain}")

        # MTA-STS
        mta_sts = await dig("TXT", f"_mta-sts.{domain}")

        # Store
        attrs = {
            "spf": spf_record,
            "dmarc": dmarc_records,
            "dkim_selectors": dkim_selectors,
            "bimi": bimi.get("answers", []),
            "mta_sts": mta_sts.get("answers", []),
        }
        self.state.add_asset(
            "email_domain",
            f"email_domain:{domain}",
            domain,
            confidence="CONFIRMED",
            sources=["email security audit"],
            attrs=attrs,
        )

        # Findings: SPF
        if spf_record:
            if "+all" in spf_record:
                self.state.add_finding(
                    title=f"SPF +all on {domain} (anyone can send)",
                    severity="CRITICAL",
                    confidence="CONFIRMED",
                    category="Email Security",
                    description=f"{domain} has SPF +all, meaning any server can send "
                                f"email as this domain.",
                    evidence=[f"SPF: {spf_record}"],
                    remediation="Change SPF to -all (hardfail).",
                    asset_keys=[f"email_domain:{domain}"],
                )
            elif "~all" in spf_record:
                self.state.add_finding(
                    title=f"SPF ~all (softfail) on {domain}",
                    severity="MEDIUM" if role == "primary" else "LOW",
                    confidence="CONFIRMED",
                    category="Email Security",
                    description=f"{domain} uses SPF softfail (~all). Spoofing is "
                                f"possible but may trigger spam filters.",
                    evidence=[f"SPF: {spf_record}"],
                    remediation="Change to -all (hardfail).",
                    asset_keys=[f"email_domain:{domain}"],
                )
        else:
            self.state.add_finding(
                title=f"No SPF Record on {domain}",
                severity="HIGH",
                confidence="CONFIRMED",
                category="Email Security",
                description=f"{domain} has no SPF record. Any server can send email "
                            f"as this domain.",
                evidence=["No SPF TXT record found"],
                remediation="Add SPF record with -all.",
                asset_keys=[f"email_domain:{domain}"],
            )

        # Findings: DMARC
        dmarc_text = " ".join(dmarc_records)
        if dmarc_text:
            if "p=none" in dmarc_text:
                self.state.add_finding(
                    title=f"DMARC p=none on {domain} (no protection)",
                    severity="MEDIUM",
                    confidence="CONFIRMED",
                    category="Email Security",
                    description=f"{domain} has DMARC policy set to 'none', meaning "
                                f"receiving servers take no action on spoofed emails.",
                    evidence=[f"DMARC: {dmarc_text}"],
                    remediation="Set DMARC to p=quarantine or p=reject.",
                    asset_keys=[f"email_domain:{domain}"],
                )
            if "sp=none" in dmarc_text:
                self.state.add_finding(
                    title=f"DMARC sp=none on {domain} (subdomains unprotected)",
                    severity="LOW",
                    confidence="CONFIRMED",
                    category="Email Security",
                    description=f"{domain} has DMARC subdomain policy set to 'none', "
                                f"allowing spoofing from subdomains.",
                    evidence=[f"DMARC sp=none in: {dmarc_text}"],
                    remediation="Set sp=quarantine or sp=reject.",
                    asset_keys=[f"email_domain:{domain}"],
                )
        else:
            self.state.add_finding(
                title=f"No DMARC Record on {domain}",
                severity="HIGH",
                confidence="CONFIRMED",
                category="Email Security",
                description=f"{domain} has no DMARC record. Email spoofing is "
                            f"completely unrestricted.",
                evidence=["No DMARC TXT record at _dmarc.{domain}"],
                remediation="Add DMARC record with p=reject.",
                asset_keys=[f"email_domain:{domain}"],
            )

        # M365 detection
        if "spf.protection.outlook.com" in spf_record:
            self.state.add_asset(
                "saas_service",
                f"saas:m365:{domain}",
                f"Microsoft 365 ({domain})",
                confidence="FIRM",
                sources=["SPF record"],
                attrs={"provider": "Microsoft 365", "domain": domain},
            )

        # Google Workspace detection
        if "_spf.google.com" in spf_record:
            self.state.add_asset(
                "saas_service",
                f"saas:gws:{domain}",
                f"Google Workspace ({domain})",
                confidence="FIRM",
                sources=["SPF record"],
                attrs={"provider": "Google Workspace", "domain": domain},
            )
