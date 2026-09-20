"""Stage 4: Identity OSINT with optional third-party tools."""

from modules.base import BaseModule
from tools.external import holehe_scan, maigret_scan, theharvester_scan, tool_available


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
        usernames = sorted({
            email.split("@", 1)[0].replace(".", "").replace("_", "")
            for email in emails
        })
        base = self.domain.split(".", 1)[0]
        if base:
            usernames.extend([base, base.replace("-", "")])
        usernames = sorted(set(filter(None, usernames)))

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

        if accounts or registrations:
            self.state.add_finding(
                title=f"Identity OSINT Accounts Found: {len(accounts) + len(registrations)}",
                severity="LOW",
                confidence="FIRM",
                category="Identity OSINT",
                description=(
                    "External identity checks found public account or registration "
                    "signals for target-related usernames/emails."
                ),
                evidence=(
                    [f"{item.get('site')}: {item.get('url')}" for item in accounts[:10]]
                    + [f"{item['email']}: {item['result']}" for item in registrations[:10]]
                )[:15],
                evidence_refs=evidence_refs,
                remediation="Use findings for awareness, impersonation monitoring, and phishing-surface reduction.",
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
