"""Stage 3: Passive threat intelligence enrichment."""

from urllib.parse import urlparse

from modules.base import BaseModule
from tools.wrappers import ip_api, threatfox_ioc, urlhaus_host


class ThreatIntel(BaseModule):
    id = "threat_intel"
    name = "Threat Intelligence"
    stage = 3
    detectability = "low"
    depends_on = ["seed_discovery"]

    async def run(self) -> str:
        self.log("Checking passive threat intelligence sources...")

        hostnames = {self.domain} if self.domain else set()
        for asset_type in ("domain", "subdomain", "webapp", "url"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "")).strip()
                host = _host_from_value(value)
                if host:
                    hostnames.add(host)

        ips = {
            str(asset.get("value", "")).strip()
            for asset in self.state.get_assets_by_type("ip")
            if str(asset.get("value", "")).strip()
        }

        if not hostnames and not ips:
            self.state.skip_module(self.id, "no indicators")
            return "skipped"

        evidence_refs = []
        urlhaus_hits = []
        threatfox_hits = []
        geo_asn = {}

        for host in sorted(hostnames)[:50]:
            urlhaus = await urlhaus_host(host)
            evidence_refs.append(
                self.state.add_evidence(self.id, "urlhaus_host", host, urlhaus)
            )
            if _has_urlhaus_hit(urlhaus):
                urlhaus_hits.append({"indicator": host, "result": urlhaus})

            threatfox = await threatfox_ioc(host)
            evidence_refs.append(
                self.state.add_evidence(self.id, "threatfox_ioc", host, threatfox)
            )
            if _has_threatfox_hit(threatfox):
                threatfox_hits.append({"indicator": host, "result": threatfox})

        for ip in sorted(ips)[:50]:
            enrich = await ip_api(ip)
            evidence_refs.append(self.state.add_evidence(self.id, "ip_api", ip, enrich))
            if enrich.get("status") == "success":
                geo_asn[ip] = {
                    "as": enrich.get("as", ""),
                    "asname": enrich.get("asname", ""),
                    "country": enrich.get("countryCode", ""),
                    "org": enrich.get("org", ""),
                    "reverse": enrich.get("reverse", ""),
                }
            threatfox = await threatfox_ioc(ip)
            evidence_refs.append(
                self.state.add_evidence(self.id, "threatfox_ioc", ip, threatfox)
            )
            if _has_threatfox_hit(threatfox):
                threatfox_hits.append({"indicator": ip, "result": threatfox})

        if urlhaus_hits:
            self.state.add_finding(
                title=f"URLHaus Reputation Hits: {len(urlhaus_hits)} Indicator(s)",
                severity="HIGH",
                confidence="FIRM",
                category="Threat Intelligence",
                description=(
                    "URLHaus returned abuse or malware URL history for one or more "
                    "in-scope indicators. Validate ownership and current compromise state."
                ),
                evidence=[
                    f"{hit['indicator']}: {hit['result'].get('query_status', 'hit')}"
                    for hit in urlhaus_hits[:10]
                ],
                evidence_refs=evidence_refs,
                remediation="Review affected hosts for compromise, redirects, and stale DNS.",
            )

        if threatfox_hits:
            self.state.add_finding(
                title=f"ThreatFox IOC Hits: {len(threatfox_hits)} Indicator(s)",
                severity="HIGH",
                confidence="FIRM",
                category="Threat Intelligence",
                description=(
                    "ThreatFox returned IOC matches for in-scope indicators. Treat as "
                    "priority triage until ownership and freshness are confirmed."
                ),
                evidence=[
                    f"{hit['indicator']}: {hit['result'].get('query_status', 'hit')}"
                    for hit in threatfox_hits[:10]
                ],
                evidence_refs=evidence_refs,
                remediation="Confirm IOC freshness and inspect affected infrastructure.",
            )

        self.state.add_asset(
            "threat_intel",
            f"threat_intel:{self.domain}",
            self.domain,
            confidence="FIRM",
            sources=[self.id, "urlhaus", "threatfox", "ip-api"],
            attrs={
                "hostnames_checked": sorted(hostnames),
                "ips_checked": sorted(ips),
                "urlhaus_hits": len(urlhaus_hits),
                "threatfox_hits": len(threatfox_hits),
                "geo_asn": geo_asn,
                "evidence_refs": evidence_refs,
            },
        )
        self.state.complete_module(self.id)
        self.log(
            f"Threat intel: {len(urlhaus_hits)} URLHaus hit(s), "
            f"{len(threatfox_hits)} ThreatFox hit(s)"
        )
        return "done"


def _host_from_value(value: str) -> str:
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or value
    return host.strip().lower().strip(".")


def _has_urlhaus_hit(result: dict) -> bool:
    status = str(result.get("query_status", "")).lower()
    if not status or status in {"no_results", "no_result", "not_found", "invalid_host"}:
        return False
    return bool(result.get("urls")) or status in {"ok", "found"}


def _has_threatfox_hit(result: dict) -> bool:
    status = str(result.get("query_status", "")).lower()
    if not status or status in {"no_result", "no_results", "not_found", "invalid_ioc"}:
        return False
    return bool(result.get("data")) or status in {"ok", "found"}
