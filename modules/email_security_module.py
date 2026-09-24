"""Stage 3: Email Security Audit — SPF, DMARC, DKIM, BIMI, MTA-STS.

Scope discipline:
  - Audits the target's registrable apex. `www.example.com` audits
    `example.com`, since SPF/DMARC/DKIM live at the apex.
  - Iterates `email_domain` assets but skips any that aren't the apex or a
    subdomain of it. SPF `include:` directives point at third-party
    infrastructure (Hostinger, Google, Microsoft, ...) — those are enrichment
    data, not auditable targets.
  - "No SPF" and "No DMARC" findings fire on the apex only. Subdomains
    inherit the apex organizational policy per RFC 7489; a subdomain without
    its own record is normal behavior, not a finding.
"""

from modules.base import BaseModule
from tools.wrappers import dig


# Common single-label subdomain prefixes to strip when deriving the apex.
_APEX_STRIP_PREFIXES = {"www", "api", "app", "apps", "mail", "web", "m", "portal"}


class EmailSecurity(BaseModule):
    id = "email_security"
    name = "Email Security Audit"
    stage = 3
    detectability = "low"
    depends_on = ["seed_discovery"]

    async def run(self) -> str:
        apex = self._registrable_domain(self.domain)
        if apex != self.domain:
            self.log(f"Email security audit for {apex} (target: {self.domain})")
        else:
            self.log(f"Email security audit for {apex}")

        # Audit the apex — this is where SPF, DMARC, DKIM, BIMI, MTA-STS live.
        await self._check_domain(apex, "primary")

        # Audit only email domains that belong to the target organization.
        # SPF includes pointing at third-party infra are recorded as assets
        # but skipped here — auditing them produces false positives about
        # infrastructure the target does not own.
        email_domains = self.state.get_assets_by_type("email_domain")
        audited = {apex}
        for asset in email_domains:
            edomain = str(asset.get("value", "")).strip().lower().rstrip(".")
            if not edomain or edomain in audited:
                continue
            if not self._is_owned_domain(edomain, apex):
                continue
            audited.add(edomain)
            await self._check_domain(edomain, "email")

        self.state.complete_module(self.id)
        return "done"

    async def _check_domain(self, domain: str, role: str):
        self.log(f"  Checking {domain} ({role})...")

        # ── SPF ──────────────────────────────────────────────────
        spf = await dig("TXT", domain)
        spf_records = [a for a in spf.get("answers", []) if a.startswith("v=spf1")]
        spf_record = spf_records[0] if spf_records else ""

        # ── DMARC (follow CNAME chains like dmarc.ionos.fr) ───────
        dmarc = await dig("TXT", f"_dmarc.{domain}", follow_cname=True)
        dmarc_records = [
            a for a in dmarc.get("answers", [])
            if "v=DMARC1" in a or "p=" in a
        ]
        if not dmarc_records:
            raw = dmarc.get("raw", "")
            for line in raw.split("\n"):
                if "v=DMARC1" in line or "p=" in line:
                    dmarc_records.append(line.strip())

        # ── DKIM selectors ───────────────────────────────────────
        dkim_selectors = []
        for sel in ["google", "selector1", "default", "mail", "k1", "s1", "s2"]:
            dkim = await dig("TXT", f"{sel}._domainkey.{domain}")
            if dkim.get("answers"):
                dkim_selectors.append(sel)

        # ── BIMI ─────────────────────────────────────────────────
        bimi = await dig("TXT", f"default._bimi.{domain}")

        # ── MTA-STS ──────────────────────────────────────────────
        mta_sts = await dig("TXT", f"_mta-sts.{domain}")

        # ── Store asset (records the audit) ──────────────────────
        self.state.add_asset(
            "email_domain",
            f"email_domain:{domain}",
            domain,
            confidence="CONFIRMED",
            sources=["email security audit"],
            attrs={
                "role": role,
                "spf": spf_record,
                "dmarc": dmarc_records,
                "dkim_selectors": dkim_selectors,
                "bimi": bimi.get("answers", []),
                "mta_sts": mta_sts.get("answers", []),
            },
        )

        # ── SPF findings ─────────────────────────────────────────
        if spf_record:
            if "+all" in spf_record:
                self.state.add_finding(
                    title=f"SPF +all on {domain} (anyone can send)",
                    severity="CRITICAL",
                    confidence="CONFIRMED",
                    category="Email Security",
                    description=(
                        f"{domain} publishes SPF +all. Every server on the "
                        f"internet is authorized to send email as this domain."
                    ),
                    evidence=[f"SPF: {spf_record}"],
                    remediation="Change SPF to -all (hardfail).",
                    asset_keys=[f"email_domain:{domain}"],
                    verified=True,
                    verification={
                        "method": "spf_record_parsed",
                        "record": spf_record,
                    },
                )
            elif "~all" in spf_record:
                self.state.add_finding(
                    title=f"SPF ~all (softfail) on {domain}",
                    severity="MEDIUM" if role == "primary" else "LOW",
                    confidence="CONFIRMED",
                    category="Email Security",
                    description=(
                        f"{domain} uses SPF softfail (~all). Spoofed mail may "
                        f"still be delivered, but is more likely to be filtered."
                    ),
                    evidence=[f"SPF: {spf_record}"],
                    remediation="Change to -all (hardfail).",
                    asset_keys=[f"email_domain:{domain}"],
                    verified=True,
                    verification={
                        "method": "spf_record_parsed",
                        "record": spf_record,
                    },
                )
        elif role == "primary":
            # Only fire on the apex — subdomains without SPF is normal.
            self.state.add_finding(
                title=f"No SPF Record on {domain}",
                severity="HIGH",
                confidence="CONFIRMED",
                category="Email Security",
                description=(
                    f"{domain} has no SPF record. Any server can send email "
                    f"claiming to be from this domain."
                ),
                evidence=["No SPF TXT record found"],
                remediation="Add SPF record ending in -all.",
                asset_keys=[f"email_domain:{domain}"],
                verified=True,
                verification={
                    "method": "spf_lookup_empty",
                    "queried": domain,
                },
            )

        # ── DMARC findings ───────────────────────────────────────
        dmarc_text = " ".join(dmarc_records)
        if dmarc_text:
            if "p=none" in dmarc_text:
                self.state.add_finding(
                    title=f"DMARC p=none on {domain} (monitor-only)",
                    severity="MEDIUM" if role == "primary" else "LOW",
                    confidence="CONFIRMED",
                    category="Email Security",
                    description=(
                        f"{domain} publishes DMARC with p=none. Receiving mail "
                        f"servers take no action against spoofed messages."
                    ),
                    evidence=[f"DMARC: {dmarc_text}"],
                    remediation="Move DMARC policy to p=quarantine or p=reject.",
                    asset_keys=[f"email_domain:{domain}"],
                    verified=True,
                    verification={
                        "method": "dmarc_record_parsed",
                        "record": dmarc_text,
                    },
                )
            if "sp=none" in dmarc_text:
                self.state.add_finding(
                    title=f"DMARC sp=none on {domain} (subdomains unprotected)",
                    severity="LOW",
                    confidence="CONFIRMED",
                    category="Email Security",
                    description=(
                        f"{domain} DMARC subdomain policy is sp=none. Subdomains "
                        f"can be spoofed even when the apex is protected."
                    ),
                    evidence=[f"DMARC sp=none in: {dmarc_text}"],
                    remediation="Set sp=quarantine or sp=reject.",
                    asset_keys=[f"email_domain:{domain}"],
                    verified=True,
                    verification={
                        "method": "dmarc_subdomain_policy",
                        "record": dmarc_text,
                    },
                )
        elif role == "primary":
            # Only fire on the apex — subdomains inherit per RFC 7489.
            self.state.add_finding(
                title=f"No DMARC Record on {domain}",
                severity="HIGH",
                confidence="CONFIRMED",
                category="Email Security",
                description=(
                    f"{domain} has no DMARC record. Email spoofing is not "
                    f"restricted by any policy."
                ),
                evidence=[f"No DMARC TXT record at _dmarc.{domain}"],
                remediation="Add DMARC record with p=reject and rua reporting.",
                asset_keys=[f"email_domain:{domain}"],
                verified=True,
                verification={
                    "method": "dmarc_lookup_empty",
                    "queried": f"_dmarc.{domain}",
                },
            )

        # ── SaaS provider detection ──────────────────────────────
        if "spf.protection.outlook.com" in spf_record:
            self.state.add_asset(
                "saas_service",
                f"saas:m365:{domain}",
                f"Microsoft 365 ({domain})",
                confidence="FIRM",
                sources=["SPF record"],
                attrs={"provider": "Microsoft 365", "domain": domain},
            )

        if "_spf.google.com" in spf_record:
            self.state.add_asset(
                "saas_service",
                f"saas:gws:{domain}",
                f"Google Workspace ({domain})",
                confidence="FIRM",
                sources=["SPF record"],
                attrs={"provider": "Google Workspace", "domain": domain},
            )

    # ── helpers ──────────────────────────────────────────────────

    def _registrable_domain(self, host: str) -> str:
        """Strip common subdomain prefixes to derive the registrable apex.

        Not public-suffix-aware — for the common single-label subdomain case
        (www, api, mail, portal, ...) it returns the registrable domain. Falls
        back to the host itself when no prefix is stripped.
        """
        host = str(host or "").strip().lower().rstrip(".")
        if not host:
            return host
        parts = host.split(".")
        if len(parts) < 3:
            return host
        if parts[0] in _APEX_STRIP_PREFIXES:
            return ".".join(parts[1:])
        return host

    def _is_owned_domain(self, candidate: str, apex: str) -> bool:
        """True if candidate equals the apex or is a subdomain of it."""
        candidate = str(candidate or "").strip().lower().rstrip(".")
        if not candidate or not apex:
            return False
        return candidate == apex or candidate.endswith(f".{apex}")