"""Stage 4: Breach Data — HIBP, HudsonRock, IntelX, paste site search."""

import json
import os
from modules.base import BaseModule
from tools.wrappers import bash, curl_with_status


class BreachCheck(BaseModule):
    id = "breach_check"
    name = "Breach Data Check"
    stage = 4
    detectability = "low"
    depends_on = ["email_harvest"]

    async def run(self) -> str:
        self.log("Checking breach data...")

        emails = self.state.get_assets_by_type("email")
        email_list = [e.get("value", "") for e in emails
                      if "@" in e.get("value", "")]

        if not email_list:
            self.log("No emails to check.")
            self.state.skip_module(self.id, "no emails")
            return "skipped"

        domain = self.domain
        hibp_api_key = (
            self.config.get("hibp_api_key")
            or os.environ.get("HIBP_API_KEY", "")
        )

        # 1. HIBP per email
        breached_emails = {}
        if hibp_api_key:
            self.log(f"  HIBP: checking {min(len(email_list), 20)} emails...")
            for email in email_list[:20]:
                result = await bash(
                    f"curl -s 'https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false' "
                    f"-H 'hibp-api-key: {hibp_api_key}' "
                    f"-H 'User-Agent: osint-agent' "
                    f"--max-time 10 2>/dev/null || true"
                )
                stdout = result["stdout"].strip()
                if stdout and stdout not in ("[]", ""):
                    try:
                        breach_data = json.loads(stdout)
                        if isinstance(breach_data, list) and breach_data:
                            breached_emails[email] = [
                                b.get("Name", "") for b in breach_data
                            ]
                    except json.JSONDecodeError:
                        pass
                # Respect HIBP rate limit (1 req/1.5s)
                import asyncio
                await asyncio.sleep(1.5)
        else:
            self.log("  HIBP: skipped (set HIBP_API_KEY)")

        # 2. HudsonRock Cavalier (domain-level infostealer data)
        self.log("  Checking HudsonRock Cavalier...")
        hudson_result = await bash(
            f"curl -s 'https://cavalier.hudsonrock.com/api/json/v2/domain/info?domain={domain}' "
            f"--max-time 15 2>/dev/null || true"
        )
        hudson_data = {}
        hudson_employees = 0
        hudson_computers = 0
        try:
            hudson_data = json.loads(hudson_result["stdout"] or "{}")
            hudson_employees = hudson_data.get("total_corporate_users", 0)
            hudson_computers = hudson_data.get("total_infected_machines", 0)
        except json.JSONDecodeError:
            pass

        if hudson_employees > 0:
            self.state.add_finding(
                title=f"Infostealer Credentials Found: {hudson_employees} Corporate Users",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="Credential Exposure",
                description=(
                    f"HudsonRock Cavalier reports {hudson_employees} corporate users "
                    f"and {hudson_computers} infected machines from infostealer malware. "
                    f"Valid credentials may be available on dark web markets."
                ),
                evidence=[
                    f"Employees in infostealers: {hudson_employees}",
                    f"Infected machines: {hudson_computers}",
                    f"Source: HudsonRock Cavalier",
                ],
                remediation=(
                    "Force password reset for all corporate accounts. "
                    "Enable MFA. Review HudsonRock for affected accounts."
                ),
            )

        # 3. Paste site search
        self.log("  Checking paste sites...")
        paste_results = await self._check_pastes(domain)

        # 4. Store results
        breach_info = {
            "domain": domain,
            "emails_checked": len(email_list),
            "breached_emails": list(breached_emails.keys()),
            "breach_details": breached_emails,
            "hibp_enabled": bool(hibp_api_key),
            "hudsonrock": {
                "employees_found": hudson_employees,
                "infected_machines": hudson_computers,
            },
            "paste_hits": paste_results,
        }

        self.state.add_asset(
            "breach_data",
            f"breach:{domain}",
            domain,
            confidence="CONFIRMED",
            sources=["breach check"],
            attrs=breach_info,
        )

        # HIBP findings
        if breached_emails:
            all_breach_names = set()
            for breach_list in breached_emails.values():
                all_breach_names.update(breach_list)

            self.state.add_finding(
                title=f"HIBP: {len(breached_emails)} Breached Employee Emails",
                severity="HIGH",
                confidence="CONFIRMED",
                category="Credential Exposure",
                description=(
                    f"{len(breached_emails)} employee email(s) appear in known data breaches: "
                    f"{list(breached_emails.keys())[:5]}. "
                    f"Breaches include: {list(all_breach_names)[:10]}."
                ),
                evidence=[
                    f"{email}: {', '.join(breaches[:3])}"
                    for email, breaches in list(breached_emails.items())[:10]
                ],
                remediation="Force password reset; enable MFA; check for credential reuse.",
            )
        elif hibp_api_key:
            self.state.add_finding(
                title="HIBP: No Breached Emails Found",
                severity="INFO",
                confidence="CONFIRMED",
                category="Negative Finding",
                description=f"No emails from {domain} found in HIBP breach database.",
                evidence=[f"Checked: {len(email_list)} emails"],
                remediation="Continue monitoring.",
            )

        if paste_results:
            self.state.add_finding(
                title=f"Domain Found in Paste Sites: {len(paste_results)} hits",
                severity="MEDIUM",
                confidence="FIRM",
                category="Credential Exposure",
                description=f"Domain {domain} appears in {len(paste_results)} public pastes. "
                            f"May contain leaked credentials or sensitive data.",
                evidence=[r.get("url", "") for r in paste_results[:5]],
                remediation="Review paste content for credential leakage.",
            )

        self.state.complete_module(self.id)
        self.log(
            f"Breach: {len(breached_emails)} HIBP | "
            f"Hudson: {hudson_employees} employees | "
            f"Pastes: {len(paste_results)}"
        )
        return "done"

    async def _check_pastes(self, domain: str) -> list:
        """Search for domain in public paste sites."""
        results = []

        # psbdmp.ws (Pastebin dump search)
        r = await bash(
            f"curl -s 'https://psbdmp.ws/api/v3/search/{domain}' "
            f"--max-time 10 2>/dev/null || true"
        )
        try:
            data = json.loads(r["stdout"])
            if isinstance(data, dict) and data.get("data"):
                for item in data["data"][:5]:
                    results.append({
                        "site": "pastebin",
                        "url": f"https://pastebin.com/{item.get('id', '')}",
                        "date": item.get("time", ""),
                    })
        except (json.JSONDecodeError, TypeError):
            pass

        # Leakix (open source breach intel)
        r2 = await bash(
            f"curl -s 'https://leakix.net/domain/{domain}' "
            f"-H 'Accept: application/json' --max-time 10 2>/dev/null || true"
        )
        try:
            data2 = json.loads(r2["stdout"])
            if isinstance(data2, list):
                for item in data2[:3]:
                    results.append({
                        "site": "leakix",
                        "url": f"https://leakix.net/domain/{domain}",
                        "type": item.get("plugin", ""),
                    })
        except (json.JSONDecodeError, TypeError):
            pass

        return results
