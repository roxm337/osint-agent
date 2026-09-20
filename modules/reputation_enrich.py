"""Stage 3: GreyNoise and AbuseIPDB keyed reputation enrichment."""

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
        if not ips:
            self.state.skip_module(self.id, "no IP assets")
            return "skipped"

        evidence_refs = []
        noisy = []
        abusive = []
        results = {}

        for ip in sorted(set(ips))[:50]:
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
                title=f"GreyNoise Internet Noise Signals: {len(noisy)} IP(s)",
                severity="MEDIUM",
                confidence="FIRM",
                category="Threat Intelligence",
                description="GreyNoise marked in-scope IPs as scanner/noise activity.",
                evidence=[f"{ip}: {results[ip].get('greynoise', {})}" for ip in noisy[:10]],
                evidence_refs=evidence_refs,
                asset_keys=[f"ip:{ip}" for ip in noisy[:10]],
                remediation="Confirm ownership and determine whether the asset is expected to scan the internet.",
            )

        if abusive:
            self.state.add_finding(
                title=f"AbuseIPDB Reputation Signals: {len(abusive)} IP(s)",
                severity="HIGH",
                confidence="FIRM",
                category="Threat Intelligence",
                description="AbuseIPDB returned non-zero abuse confidence for in-scope IPs.",
                evidence=[f"{ip}: {results[ip].get('abuseipdb', {})}" for ip in abusive[:10]],
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
                "ips_checked": sorted(set(ips))[:50],
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
    return bool(result.get("noise")) and str(result.get("classification", "")).lower() != "benign"


def _abuseipdb_digest(result: dict) -> dict:
    data = result.get("data", {}) if isinstance(result, dict) else {}
    return {
        "abuseConfidenceScore": int(data.get("abuseConfidenceScore") or 0),
        "totalReports": int(data.get("totalReports") or 0),
        "countryCode": data.get("countryCode", ""),
    }


def _abuseipdb_suspicious(result: dict) -> bool:
    data = result.get("data", {}) if isinstance(result, dict) else {}
    return int(data.get("abuseConfidenceScore") or 0) > 0
