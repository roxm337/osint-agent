"""Stage 1: Seed Discovery — WHOIS/RDAP, DNS, ASN, CT logs, MX analysis."""

import re
from modules.base import BaseModule
from tools.wrappers import dig_all, whois_lookup, rdap_lookup, crtsh, bash, asn_lookup


class SeedDiscovery(BaseModule):
    id = "seed_discovery"
    name = "Seed Discovery"
    stage = 1
    detectability = "low"
    depends_on = []

    async def run(self) -> str:
        self.log(f"Starting seed discovery for {self.domain}")

        # 1. DNS Records (all types, parallel)
        self.log("Fetching DNS records...")
        dns = await dig_all(self.domain)
        for rtype, answers in dns.items():
            self.state.add_asset(
                "dns_record",
                f"dns:{self.domain}:{rtype}",
                f"{self.domain} {rtype}",
                confidence="CONFIRMED",
                sources=[f"dig {rtype}"],
                attrs={"type": rtype, "records": answers},
            )
            if rtype == "A":
                for ip in answers:
                    self.state.add_asset(
                        "ip", f"ip:{ip}", ip,
                        confidence="CONFIRMED",
                        sources=["dig A"],
                    )
                    self.state.add_edge(f"domain:{self.domain}", f"ip:{ip}", "RESOLVES_TO")
            elif rtype == "AAAA":
                for ipv6 in answers:
                    self.state.add_asset(
                        "ip", f"ip:{ipv6}", ipv6,
                        confidence="CONFIRMED",
                        sources=["dig AAAA"],
                        attrs={"ipv6": True},
                    )
            elif rtype == "MX":
                for mx in answers:
                    mx_host = mx.split()[-1].rstrip(".") if " " in mx else mx.rstrip(".")
                    self.state.add_asset(
                        "mx_server", f"mx:{mx_host}", mx_host,
                        confidence="CONFIRMED",
                        sources=["dig MX"],
                        attrs={"mx_record": mx},
                    )
            elif rtype == "NS":
                for ns in answers:
                    ns = ns.rstrip(".")
                    self.state.add_asset(
                        "nameserver", f"ns:{ns}", ns,
                        confidence="CONFIRMED",
                        sources=["dig NS"],
                    )

        # 2. SPF/TXT analysis
        if "TXT" in dns:
            txt_records = dns["TXT"]
            for txt in txt_records:
                if "v=spf1" in txt:
                    includes = re.findall(r'include:([\w.-]+)', txt)
                    for inc in includes:
                        if inc != self.domain:
                            self.state.add_asset(
                                "email_domain", f"email_domain:{inc}", inc,
                                confidence="FIRM",
                                sources=["SPF include"],
                                attrs={"spf_included": True},
                            )
                    # Extract redirect:
                    redirects = re.findall(r'redirect=([\w.-]+)', txt)
                    for redir in redirects:
                        self.state.add_asset(
                            "email_domain", f"email_domain:{redir}", redir,
                            confidence="FIRM",
                            sources=["SPF redirect"],
                        )
                elif "v=DKIM1" in txt or "p=" in txt:
                    pass  # DKIM key — handled in email_security module

        # 3. WHOIS
        self.log("Fetching WHOIS...")
        whois = await whois_lookup(self.domain)
        whois_fields = whois.get("fields", {})

        # 4. RDAP (structured JSON alternative)
        self.log("Fetching RDAP...")
        rdap = await rdap_lookup(self.domain)

        self.state.add_asset(
            "domain",
            f"domain:{self.domain}",
            self.domain,
            confidence="CONFIRMED",
            sources=["whois", "rdap", "dns"],
            attrs={
                "registrar": rdap.get("registrar") or whois_fields.get("registrar_name", ""),
                "registrant": rdap.get("registrant") or whois_fields.get("registrant_organization", ""),
                "created": rdap.get("created") or whois_fields.get("creation_date", ""),
                "expires": rdap.get("expires") or whois_fields.get("registry_expiry_date", ""),
                "nameservers": rdap.get("nameservers") or dns.get("NS", []),
                "status": rdap.get("status", []),
                "whois_raw": whois.get("raw", "")[:1000],
            },
        )

        # 5. ASN lookup for all discovered IPs
        ipv4s = dns.get("A", [])
        if ipv4s:
            primary_ip = ipv4s[0]
            self.log(f"ASN lookup for {primary_ip}...")
            asn_info = await asn_lookup(primary_ip)
            asn = asn_info.get("asn", "")
            if asn:
                self.state.add_asset(
                    "asn", f"asn:{asn}", asn,
                    confidence="CONFIRMED",
                    sources=["ipinfo.io", "whois radb"],
                    attrs={
                        "ip": primary_ip,
                        "org": asn_info.get("org", ""),
                        "country": asn_info.get("country", ""),
                        "hostname": asn_info.get("hostname", ""),
                    },
                )
                self.state.add_edge(f"ip:{primary_ip}", f"asn:{asn}", "BELONGS_TO_ASN")

        # 6. Certificate Transparency (crt.sh)
        self.log("Checking crt.sh...")
        certs = await crtsh(self.domain)
        if certs:
            seen_names = set()
            for cert in certs[:200]:
                name_value = cert.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and name not in seen_names:
                        seen_names.add(name)
                        if name.endswith(f".{self.domain}") and name != self.domain:
                            self.state.add_asset(
                                "subdomain", f"sub:{name}", name,
                                confidence="TENTATIVE",
                                sources=["crt.sh"],
                                attrs={"cert_issued": True,
                                       "cert_id": cert.get("id", "")},
                            )
            self.log(f"  CT logs: {len(seen_names)} unique names")

        # 7. Reverse DNS for discovered IPs
        for ip in ipv4s[:5]:
            ptr_result = await bash(f"dig +short -x {ip} 2>/dev/null")
            ptr = ptr_result["stdout"].strip().rstrip(".")
            if ptr and ptr != ip:
                self.state.add_asset(
                    "ptr_record", f"ptr:{ip}", ptr,
                    confidence="CONFIRMED",
                    sources=["reverse DNS"],
                    attrs={"ip": ip, "ptr": ptr},
                )
                self.state.add_edge(f"ip:{ip}", f"ptr:{ip}", "HAS_PTR")

        # 8. Zone transfer attempt (passive detectability)
        ns_servers = dns.get("NS", [])
        if ns_servers:
            ns = ns_servers[0].rstrip(".")
            zt_result = await bash(f"dig AXFR {self.domain} @{ns} 2>/dev/null")
            zt_output = zt_result["stdout"]
            if "Transfer failed" not in zt_output and len(zt_output) > 200:
                self.state.add_finding(
                    title=f"DNS Zone Transfer Allowed: {ns}",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    category="DNS Exposure",
                    description=f"DNS zone transfer succeeded from {ns}. "
                                f"All DNS records are publicly enumerable.",
                    evidence=[f"NS: {ns}", f"AXFR output: {zt_output[:500]}"],
                    remediation="Disable AXFR on public-facing name servers.",
                )

        self.log("Seed discovery complete.")
        self.state.complete_module(self.id)
        return "done"
