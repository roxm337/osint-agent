"""Stage 2: ASN expansion from discovered IP addresses."""

from modules.base import BaseModule
from tools.wrappers import asn_lookup, bgpview_asn, ip_api


class ASNExpansion(BaseModule):
    id = "asn_expansion"
    name = "ASN Expansion"
    stage = 2
    detectability = "low"
    depends_on = ["seed_discovery"]

    async def run(self) -> str:
        self.log("Expanding ASN and network prefixes...")

        ip_assets = self.state.get_assets_by_type("ip")
        ips = [str(asset.get("value", "")).strip() for asset in ip_assets]
        ips = [ip for ip in ips if ip]

        if not ips and self.domain:
            fallback = await ip_api(self.domain)
            if fallback.get("status") == "success" and fallback.get("query"):
                ips.append(str(fallback["query"]))

        if not ips:
            self.state.skip_module(self.id, "no IP assets")
            return "skipped"

        asns = {}
        evidence_refs = []
        for ip in sorted(set(ips))[:25]:
            lookup = await asn_lookup(ip)
            evidence_id = self.state.add_evidence(self.id, "asn_lookup", ip, lookup)
            evidence_refs.append(evidence_id)
            asn = str(lookup.get("asn", "")).upper().strip()
            if asn:
                asns[asn] = lookup
                self.state.add_asset(
                    "asn",
                    f"asn:{asn}",
                    asn,
                    confidence="FIRM",
                    sources=[self.id],
                    attrs={
                        "org": lookup.get("org", ""),
                        "country": lookup.get("country", ""),
                    },
                )
                self.state.add_edge(f"ip:{ip}", f"asn:{asn}", "announced_by")

        if not asns:
            self.state.skip_module(self.id, "no ASN results")
            return "skipped"

        prefix_count = 0
        for asn in sorted(asns)[:10]:
            prefixes = await bgpview_asn(asn)
            evidence_id = self.state.add_evidence(
                self.id, "bgpview_prefixes", asn, prefixes
            )
            evidence_refs.append(evidence_id)
            for prefix in prefixes.get("ipv4_prefixes", [])[:100]:
                cidr = prefix.get("prefix") if isinstance(prefix, dict) else ""
                if not cidr:
                    continue
                self.state.add_asset(
                    "cidr",
                    f"cidr:{cidr}",
                    cidr,
                    confidence="FIRM",
                    sources=[self.id, "bgpview"],
                    attrs={
                        "asn": asn,
                        "name": prefix.get("name", "") if isinstance(prefix, dict) else "",
                        "description": (
                            prefix.get("description", "")
                            if isinstance(prefix, dict)
                            else ""
                        ),
                    },
                )
                self.state.add_edge(f"asn:{asn}", f"cidr:{cidr}", "announces")
                prefix_count += 1

        self.state.add_asset(
            "asn_intel",
            f"asn_intel:{self.domain}",
            self.domain,
            confidence="FIRM",
            sources=[self.id],
            attrs={
                "asn_count": len(asns),
                "prefix_count": prefix_count,
                "asns": sorted(asns),
                "evidence_refs": evidence_refs,
            },
        )
        self.state.complete_module(self.id)
        self.log(f"ASN expansion: {len(asns)} ASN(s), {prefix_count} prefix(es)")
        return "done"
