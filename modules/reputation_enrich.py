"""Stage 3: GreyNoise and AbuseIPDB keyed reputation enrichment."""

from datetime import datetime, timezone

from core.validators import is_routable_ip
from modules.base import BaseModule
from tools.wrappers import abuseipdb_check, greynoise_ip


class ReputationEnrich(BaseModule):
    id = "reputation_enrich"
    name = "Keyed Reputation Enrichment"
    stage = 3
    detectability = "low"
    depends_on = ["seed_discovery"]

    async def run(self) -> str:
        available = self.keys.available(["greynoise", "abuseipdb"])
        if not available:
            self.state.skip_module(
                self.id,
                "GreyNoise/AbuseIPDB keys missing; set GREYNOISE_API_KEY or ABUSEIPDB_API_KEY",
            )
            return "skipped"

        ips = [
            str(asset.get("value", "")).strip()
            for asset in self.state.get_assets_by_type("ip")
            if str(asset.get("value", "")).strip()
        ]
        # Reputation about RFC1918/loopback is a fact about the address,
        # not the target — and querying it burns key quota for nothing.
        routable = sorted({ip for ip in ips if is_routable_ip(ip)})
        skipped_private = sorted({ip for ip in ips if not is_routable_ip(ip)})
        if skipped_private:
            self.log(f"  Skipping {len(skipped_private)} non-routable IP(s)")
        if not routable:
            self.state.skip_module(self.id, "no routable IP assets")
            return "skipped"

        evidence_refs = []
        noisy = []
        abusive = []
        results = {}

        for ip in routable[:50]:
            results[ip] = {}
            if self.keys.has("greynoise"):
                greynoise = await greynoise_ip(ip, self.keys.get("greynoise"))
                results[ip]["greynoise"] = _greynoise_digest(greynoise)
                evidence_refs.append(
                    self.state.add_evidence(self.id, "greynoise_ip", ip, greynoise)
                )
                if _greynoise_suspicious(greynoise):
                    noisy.append(ip)

            if self.keys.has("abuseipdb"):
                abuse = await abuseipdb_check(ip, self.keys.get("abuseipdb"))
                results[ip]["abuseipdb"] = _abuseipdb_digest(abuse)
                evidence_refs.append(
                    self.state.add_evidence(self.id, "abuseipdb_check", ip, abuse)
                )
                if _abuseipdb_suspicious(abuse):
                    abusive.append(ip)

        if noisy:
            self.state.add_finding(
                title=f"GreyNoise Malicious Classification: {len(noisy)} IP(s)",
                severity="HIGH",
                confidence="FIRM",
                category="Threat Intelligence",
                description="GreyNoise classifies in-scope IPs as malicious "
                            "(observed attacking, not background scanning).",
                evidence=[f"{ip}: {results[ip].get('greynoise', {})}" for ip in noisy[:10]],
                evidence_refs=evidence_refs,
                asset_keys=[f"ip:{ip}" for ip in noisy[:10]],
                remediation="Investigate whether the asset is compromised or spoofed; "
                            "confirm ownership first.",
            )

        if abusive:
            worst = max(abusive, key=lambda ip: results[ip]["abuseipdb"]["abuseConfidenceScore"])
            top = results[worst]["abuseipdb"]
            self.state.add_finding(
                title=f"AbuseIPDB Reputation Signals: {len(abusive)} IP(s)",
                severity="HIGH",
                confidence="FIRM",
                category="Threat Intelligence",
                description=(f"AbuseIPDB reports recent, multi-report abuse confidence "
                             f"(top: {worst} score {top['abuseConfidenceScore']}, "
                             f"{top['totalReports']} reports, last seen {top['last_reported']})."),
                evidence=[f"{ip}: score={results[ip]['abuseipdb']['abuseConfidenceScore']} "
                          f"reports={results[ip]['abuseipdb']['totalReports']} "
                          f"last={results[ip]['abuseipdb']['last_reported']}"
                          for ip in abusive[:10]],
                evidence_refs=evidence_refs,
                asset_keys=[f"ip:{ip}" for ip in abusive[:10]],
                remediation="Investigate abuse reports and confirm the infrastructure is not compromised.",
            )

        self.state.add_asset(
            "reputation_intel",
            f"reputation:{self.domain}",
            self.domain,
            confidence="FIRM",
            sources=available,
            attrs={
                "ips_checked": routable[:50],
                "greynoise_hits": len(noisy),
                "abuseipdb_hits": len(abusive),
                "results": results,
                "evidence_refs": evidence_refs,
            },
        )
        self.state.complete_module(self.id)
        self.log(f"Reputation: {len(noisy)} GreyNoise, {len(abusive)} AbuseIPDB")
        return "done"


def _greynoise_digest(result: dict) -> dict:
    return {
        "noise": bool(result.get("noise")),
        "riot": bool(result.get("riot")),
        "classification": result.get("classification", ""),
        "name": result.get("name", ""),
    }


def _greynoise_suspicious(result: dict) -> bool:
    """Only a malicious classification is a finding. Every Shodan, Censys
    and research scanner on the internet is "noise" — filing scanner
    sightings as MEDIUMs is background-radiation reporting."""
    return str(result.get("classification", "") or "").lower() == "malicious"


def _abuseipdb_digest(result: dict) -> dict:
    data = result.get("data", {}) if isinstance(result, dict) else {}
    return {
        "abuseConfidenceScore": int(data.get("abuseConfidenceScore") or 0),
        "totalReports": int(data.get("totalReports") or 0),
        "countryCode": data.get("countryCode", ""),
        "last_reported": str(data.get("lastReportedAt", "") or ""),
    }


def _abuseipdb_suspicious(result: dict) -> bool:
    """Recent, multi-report, high-confidence abuse only. One user report on
    a CDN egress IP is not a HIGH finding."""
    data = result.get("data", {}) if isinstance(result, dict) else {}
    score = int(data.get("abuseConfidenceScore") or 0)
    reports = int(data.get("totalReports") or 0)
    if score < 50 or reports < 5:
        return False
    last = str(data.get("lastReportedAt", "") or "")
    if not last:
        return False
    try:
        seen = datetime.fromisoformat(last.replace("Z", "+00:00"))
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - seen).days
    except ValueError:
        return False
    return age_days <= 90
