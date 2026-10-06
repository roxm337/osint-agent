"""Stage 4: Breach Data — HIBP, HudsonRock, paste site search."""

import asyncio
import json
from urllib.parse import quote

from core.validators import extract_secrets
from modules.base import BaseModule
from tools.wrappers import curl


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
            or self.config.get("api_keys", {}).get("hibp", "")
        )
        if not hibp_api_key:
            import os
            hibp_api_key = os.environ.get("HIBP_API_KEY", "")

        # 1. HIBP per email. Key travels in an HTTP header through the
        # pooled client, never on a shell command line (process-list leak)
        # and the address is URL-encoded, not interpolated.
        breached_emails = {}
        if hibp_api_key:
            self.log(f"  HIBP: checking {min(len(email_list), 20)} emails...")
            for email in email_list[:20]:
                try:
                    result = await curl(
                        "https://haveibeenpwned.com/api/v3/breachedaccount/"
                        f"{quote(email)}?truncateResponse=false",
                        headers={"hibp-api-key": hibp_api_key,
                                 "User-Agent": "osint-agent"},
                        output="body",
                        timeout=15,
                    )
                except Exception:
                    continue
                body = (result.get("body", "") or "").strip()
                if body and body not in ("[]", ""):
                    try:
                        breach_data = json.loads(body)
                        if isinstance(breach_data, list) and breach_data:
                            breached_emails[email] = [
                                b.get("Name", "") for b in breach_data
                                if isinstance(b, dict)
                            ]
                    except json.JSONDecodeError:
                        pass
                # Respect HIBP rate limit (1 req/1.5s)
                await asyncio.sleep(1.5)
        else:
            self.log("  HIBP: skipped (set HIBP_API_KEY)")

        # 2. HudsonRock Cavalier (domain-level infostealer data). The free
        # endpoint reports aggregate counts, not per-account credentials, so
        # counts alone are HIGH at most: CRITICAL needs per-account proof
        # the API does not give.
        self.log("  Checking HudsonRock Cavalier...")
        hudson_data = {}
        try:
            result = await curl(
                "https://cavalier.hudsonrock.com/api/json/v2/domain/info"
                f"?domain={quote(domain)}",
                output="body",
                timeout=20,
            )
            hudson_data = json.loads(result.get("body", "") or "{}")
            if not isinstance(hudson_data, dict):
                hudson_data = {}
        except Exception:
            hudson_data = {}
        hudson_employees = int(hudson_data.get("total_corporate_users", 0) or 0)
        hudson_computers = int(hudson_data.get("total_infected_machines", 0) or 0)

        if hudson_employees > 0 or hudson_computers > 0:
            if hudson_computers > 0 and hudson_employees > 0:
                severity, title = "HIGH", (
                    f"Active Infostealer Footprint: {hudson_employees} "
                    f"Corporate Users, {hudson_computers} Infected Machines")
                description = (
                    f"HudsonRock Cavalier reports {hudson_employees} corporate users "
                    f"and {hudson_computers} infected machines from infostealer malware. "
                    f"Aggregate counts only — per-account credential proof needs "
                    f"the HudsonRock portal, but the footprint is current.")
            else:
                severity, title = "MEDIUM", (
                    f"Historical Infostealer Exposure: {hudson_employees} "
                    f"Corporate Users")
                description = (
                    f"HudsonRock Cavalier reports {hudson_employees} corporate users "
                    f"in historical infostealer data with no currently infected "
                    f"machines. Stale but worth a password review.")
            self.state.add_finding(
                title=title,
                severity=severity,
                confidence="FIRM",
                category="Credential Exposure",
                description=description,
                evidence=[
                    f"Employees in infostealers: {hudson_employees}",
                    f"Infected machines: {hudson_computers}",
                    "Source: HudsonRock Cavalier",
                ],
                remediation=(
                    "Force password reset for all corporate accounts. "
                    "Enable MFA. Review HudsonRock for affected accounts."
                ),
            )

        # 3. Paste site search with content assertion: a domain MENTION is
        # spam-list noise, credential-shaped content is a finding.
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

        # HIBP findings: per-email breach names are the proof.
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
            # A clean HIBP result is a log line, not a finding: negative
            # results filed as INFO findings train triagers to ignore INFO.
            self.log(f"  HIBP: no breached emails among {len(email_list)} checked")

        credential_pastes = [r for r in paste_results if r.get("has_credentials")]
        mention_pastes = [r for r in paste_results if not r.get("has_credentials")]
        if credential_pastes:
            self.state.add_finding(
                title=f"Credentials in Public Pastes: {len(credential_pastes)} paste(s)",
                severity="MEDIUM",
                confidence="FIRM",
                category="Credential Exposure",
                description=(f"{len(credential_pastes)} public paste(s) mention {domain} "
                             f"AND contain credential-shaped content (email:password "
                             f"pairs or secret patterns)."),
                evidence=[f"{r.get('site')}: {r.get('url', '')} :: {r.get('match', '')}"
                          for r in credential_pastes[:5]],
                remediation="Rotate exposed credentials; request paste takedown.",
            )
        elif mention_pastes:
            self.state.add_finding(
                title=f"Domain Mentioned in Paste Sites: {len(mention_pastes)} hit(s)",
                severity="LOW",
                confidence="FIRM",
                category="Credential Exposure",
                description=(f"{domain} appears in {len(mention_pastes)} public paste(s) "
                             f"with no credential-shaped content observed. Mention, "
                             f"not a leak."),
                evidence=[r.get("url", "") for r in mention_pastes[:5]],
                remediation="No action unless a later paste carries credentials.",
            )

        self.state.complete_module(self.id)
        self.log(
            f"Breach: {len(breached_emails)} HIBP | "
            f"Hudson: {hudson_employees} employees | "
            f"Pastes: {len(credential_pastes)} credential, {len(mention_pastes)} mention"
        )
        return "done"

    async def _check_pastes(self, domain: str) -> list:
        """Search paste indexes, then assert content before claiming."""
        results = []

        # psbdmp.ws (Pastebin dump search)
        try:
            result = await curl(
                f"https://psbdmp.ws/api/v3/search/{quote(domain)}",
                output="body",
                timeout=15,
            )
            data = json.loads(result.get("body", "") or "{}")
            if isinstance(data, dict) and data.get("data"):
                for item in data["data"][:5]:
                    if not isinstance(item, dict):
                        continue
                    paste_id = str(item.get("id", ""))
                    results.append({
                        "site": "pastebin",
                        "url": f"https://pastebin.com/{paste_id}",
                        "raw_url": f"https://pastebin.com/raw/{paste_id}" if paste_id else "",
                        "date": item.get("time", ""),
                    })
        except Exception:
            pass

        # LeakIX (open source breach intel)
        try:
            result = await curl(
                f"https://leakix.net/domain/{quote(domain)}",
                headers={"Accept": "application/json"},
                output="body",
                timeout=15,
            )
            data = json.loads(result.get("body", "") or "[]")
            if isinstance(data, list):
                for item in data[:3]:
                    if not isinstance(item, dict):
                        continue
                    results.append({
                        "site": "leakix",
                        "url": f"https://leakix.net/domain/{domain}",
                        "type": item.get("plugin", ""),
                    })
        except Exception:
            pass

        # Content assertion on the first few pastebins: fetch raw text and
        # look for credential shapes, not just the domain string.
        for entry in results:
            entry["has_credentials"] = False
            raw_url = entry.get("raw_url", "")
            if not raw_url:
                continue
            try:
                response = await curl(raw_url, output="body", timeout=15)
            except Exception:
                continue
            body = response.get("body", "") or ""
            if not body or domain not in body:
                continue
            if _credential_shaped(body, domain):
                entry["has_credentials"] = True
                entry["match"] = _credential_sample(body, domain)
            if results.index(entry) >= 2:
                break
        return results


def _credential_shaped(body: str, domain: str) -> bool:
    """Email:password pairs or secret patterns alongside the domain."""
    import re
    lines = str(body or "").splitlines()
    domain_lines = [line for line in lines if domain in line]
    for line in domain_lines[:50]:
        if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\s*[:;|]\s*\S{4,}", line):
            return True
    if extract_secrets(body[:20000]):
        return True
    return False


def _credential_sample(body: str, domain: str) -> str:
    """One redacted sample line proving the paste carries credentials."""
    import re
    for line in str(body or "").splitlines()[:50]:
        if domain not in line:
            continue
        match = re.search(
            r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*[:;|]\s*(\S{4,})", line)
        if match:
            return f"{match.group(1)}:<redacted>"
    secrets = extract_secrets(body[:20000])
    if secrets:
        return f"{secrets[0]['type']}:{secrets[0]['redacted']}"
    return "credential-shaped content observed"
