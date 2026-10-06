"""Stage 4: Identity OSINT with optional third-party tools."""

import re

from modules.base import BaseModule
from tools.external import holehe_scan, maigret_scan, theharvester_scan, tool_available


def _username_variants(full_name: str) -> list:
    """Handle-shaped guesses from a display name: alice.martin etc."""
    parts = re.findall(r"[A-Za-zéèêëàâäùûüôöîïç]+", full_name.lower())
    if len(parts) < 2:
        return []
    first, last = parts[0], parts[-1]
    return sorted({
        first + last, f"{first}.{last}", f"{first}_{last}",
        first[0] + last, f"{first[0]}.{last}",
    })


class SocialOSINT(BaseModule):
    id = "social_osint"
    name = "Social OSINT"
    stage = 4
    detectability = "low"
    depends_on = ["email_harvest"]

    async def run(self) -> str:
        emails = [
            str(asset.get("value", "")).strip()
            for asset in self.state.get_assets_by_type("email")
            if "@" in str(asset.get("value", ""))
        ]
        usernames = set()
        for email in emails:
            local = email.split("@", 1)[0]
            if not local:
                continue
            # Keep the raw local: dots and underscores are significant on
            # most platforms, and stripping them collides distinct users.
            usernames.add(local)
            squashed = re.sub(r"[^a-z0-9]", "", local.lower())
            if squashed and squashed != local:
                usernames.add(squashed)
        # People found on team pages seed name-shaped variants; the bare
        # domain stem is NOT a username (it matches hundreds of unrelated
        # accounts on every site maigret checks).
        for asset in self.state.get_assets_by_type("person"):
            for variant in _username_variants(str(asset.get("value", ""))):
                usernames.add(variant)
        usernames = sorted(usernames)

        if not usernames and not emails:
            self.state.skip_module(self.id, "no identity seeds")
            return "skipped"

        evidence_refs = []
        accounts = []
        registrations = []
        harvested_emails = []
        hosts = []

        if tool_available("maigret"):
            for username in usernames[:5]:
                result = await maigret_scan(username)
                accounts.extend(result.get("results", []))
                evidence_refs.append(
                    self.state.add_evidence(self.id, "maigret", username, result)
                )

        if tool_available("holehe"):
            for email in emails[:10]:
                result = await holehe_scan(email)
                registrations.extend([
                    {"email": email, "result": item}
                    for item in result.get("results", [])
                ])
                evidence_refs.append(
                    self.state.add_evidence(self.id, "holehe", email, result)
                )

        if tool_available("theHarvester"):
            result = await theharvester_scan(self.domain)
            harvested_emails = result.get("emails", [])
            hosts = result.get("hosts", [])
            evidence_refs.append(
                self.state.add_evidence(self.id, "theharvester", self.domain, result)
            )

        for account in accounts[:100]:
            url = account.get("url", "")
            if not url:
                continue
            self.state.add_asset(
                "identity_account",
                f"identity:{url}",
                url,
                confidence="FIRM",
                sources=[self.id],
                attrs=account,
            )

        for email in harvested_emails:
            self.state.add_asset(
                "email",
                f"email:{email.lower()}",
                email.lower(),
                confidence="FIRM",
                sources=[self.id, "theHarvester"],
            )

        for host in hosts:
            if host.endswith(self.domain):
                self.state.add_asset(
                    "subdomain",
                    f"sub:{host.lower()}",
                    host.lower(),
                    confidence="FIRM",
                    sources=[self.id, "theHarvester"],
                )

        # holehe registrations are CONFIRMED (the address is registered
        # there); maigret claims are unconfirmed until something
        # corroborates them. They file separately so triage can tell
        # proof from lead.
        if registrations:
            self.state.add_finding(
                title=f"Confirmed Email Registrations: {len(registrations)}",
                severity="LOW",
                confidence="FIRM",
                category="Identity OSINT",
                description=(
                    "Account-registration checks confirm these target emails "
                    "are registered on the listed platforms — phishing and "
                    "impersonation surface."
                ),
                evidence=[f"{item['email']}: {item['result']}"
                          for item in registrations[:15]],
                evidence_refs=evidence_refs,
                remediation="Use findings for awareness, impersonation monitoring, and phishing-surface reduction.",
            )
        if accounts:
            self.state.add_finding(
                title=f"Claimed Social Profiles (Unconfirmed): {len(accounts)}",
                severity="INFO",
                confidence="TENTATIVE",
                category="Identity OSINT",
                description=(
                    "Username presence checks claim these profiles for "
                    "target-related handles. Unconfirmed: a matching handle "
                    "is not proof of ownership."
                ),
                evidence=[f"{item.get('site')}: {item.get('url')}"
                          for item in accounts[:15]],
                evidence_refs=evidence_refs,
                remediation="Corroborate via bio links or website backlinks before acting.",
            )

        self.state.add_asset(
            "identity_osint",
            f"identity_osint:{self.domain}",
            self.domain,
            confidence="FIRM",
            sources=[self.id],
            attrs={
                "usernames": usernames,
                "emails_checked": len(emails),
                "accounts": len(accounts),
                "registrations": len(registrations),
                "harvested_emails": len(harvested_emails),
                "hosts": len(hosts),
            },
        )
        self.state.complete_module(self.id)
        self.log(f"Identity OSINT: {len(accounts)} accounts, {len(registrations)} registrations")
        return "done"
