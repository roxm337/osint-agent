"""Stage 3: VirusTotal keyed enrichment."""

from modules.base import BaseModule
from tools.wrappers import (
    virustotal_domain,
    virustotal_domain_subdomains,
    virustotal_ip,
)


class VirusTotalEnrich(BaseModule):
    id = "vt_enrich"
    name = "VirusTotal Enrichment"
    stage = 3
    detectability = "low"
    depends_on = ["seed_discovery"]

    async def run(self) -> str:
        ok, reason = self.keys.require("virustotal")
        if not ok:
            self.state.skip_module(self.id, reason)
            return "skipped"

        api_key = self.keys.get("virustotal")
        self.log("Querying VirusTotal...")

        domain_result = await virustotal_domain(self.domain, api_key)
        subdomains = await virustotal_domain_subdomains(self.domain, api_key)
        evidence_refs = [
            self.state.add_evidence(
                self.id,
                "virustotal_domain",
                self.domain,
                domain_result,
            )
        ]
        if subdomains:
            evidence_refs.append(
                self.state.add_evidence(
                    self.id,
                    "virustotal_subdomains",
                    self.domain,
                    {"subdomains": subdomains},
                )
            )

        for subdomain in subdomains:
            self.state.add_asset(
                "subdomain",
                f"sub:{subdomain}",
                subdomain,
                confidence="FIRM",
                sources=["virustotal"],
            )
            self.state.add_edge(f"domain:{self.domain}", f"sub:{subdomain}", "vt_subdomain")

        ip_results = {}
        for asset in self.state.get_assets_by_type("ip")[:25]:
            ip = str(asset.get("value", "")).strip()
            if not ip:
                continue
            result = await virustotal_ip(ip, api_key)
            ip_results[ip] = _vt_stats(result)
            evidence_refs.append(
                self.state.add_evidence(self.id, "virustotal_ip", ip, result)
            )

        domain_stats = _vt_stats(domain_result)
        if domain_stats["malicious"] or domain_stats["suspicious"]:
            self.state.add_finding(
                title="VirusTotal Reputation Signal on Domain",
                severity="HIGH" if domain_stats["malicious"] else "MEDIUM",
                confidence="FIRM",
                category="Threat Intelligence",
                description=(
                    "VirusTotal returned malicious or suspicious reputation votes "
                    "for the target domain."
                ),
                evidence=[
                    f"malicious={domain_stats['malicious']}",
                    f"suspicious={domain_stats['suspicious']}",
                ],
                evidence_refs=evidence_refs,
                asset_keys=[f"domain:{self.domain}"],
                remediation="Validate reputation context and inspect affected services.",
            )

        bad_ips = [
            ip for ip, stats in ip_results.items()
            if stats["malicious"] or stats["suspicious"]
        ]
        if bad_ips:
            self.state.add_finding(
                title=f"VirusTotal IP Reputation Signals: {len(bad_ips)} IP(s)",
                severity="HIGH",
                confidence="FIRM",
                category="Threat Intelligence",
                description="VirusTotal returned suspicious or malicious votes for in-scope IPs.",
                evidence=[
                    f"{ip}: malicious={ip_results[ip]['malicious']}, "
                    f"suspicious={ip_results[ip]['suspicious']}"
                    for ip in bad_ips[:10]
                ],
                evidence_refs=evidence_refs,
                asset_keys=[f"ip:{ip}" for ip in bad_ips[:10]],
                remediation="Confirm current ownership and investigate reputation sources.",
            )

        self.state.add_asset(
            "vt_intel",
            f"vt:{self.domain}",
            self.domain,
            confidence="FIRM",
            sources=["virustotal"],
            attrs={
                "domain_stats": domain_stats,
                "subdomain_count": len(subdomains),
                "ip_stats": ip_results,
                "evidence_refs": evidence_refs,
            },
        )
        self.state.complete_module(self.id)
        self.log(f"VirusTotal: {len(subdomains)} subdomain(s), {len(ip_results)} IP(s)")
        return "done"


def _vt_stats(result: dict) -> dict:
    attrs = result.get("data", {}).get("attributes", {}) if isinstance(result, dict) else {}
    stats = attrs.get("last_analysis_stats", {}) if isinstance(attrs, dict) else {}
    return {
        "malicious": int(stats.get("malicious") or 0),
        "suspicious": int(stats.get("suspicious") or 0),
        "harmless": int(stats.get("harmless") or 0),
        "undetected": int(stats.get("undetected") or 0),
    }
