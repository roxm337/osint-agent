"""Stage 2: Subdomain Enumeration — passive + active with tool fallbacks."""

import asyncio
from modules.base import BaseModule
from tools.wrappers import (
    dig, crtsh, otx_passive_dns, hackertarget_hostsearch,
    urlscan_search, subfinder_scan, amass_passive, dnsx_resolve, dig_bulk,
    rapiddns, anubisdb, certspotter,
)


class SubdomainEnum(BaseModule):
    id = "subdomain_enum"
    name = "Subdomain Enumeration"
    stage = 2
    detectability = "low"
    depends_on = ["seed_discovery"]

    async def run(self) -> str:
        self.log(f"Enumerating subdomains for {self.domain}")

        discovered = set()
        source_map = {}

        # 1. crt.sh Certificate Transparency
        self.log("Querying crt.sh...")
        certs = await crtsh(self.domain)
        for cert in certs[:500]:
            for name in cert.get("name_value", "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                self._record_hostname(name, "crt.sh", discovered, source_map)

        # 2. OTX AlienVault Passive DNS
        self.log("Querying OTX AlienVault...")
        otx_results = await otx_passive_dns(self.domain)
        for entry in otx_results:
            hostname = entry.get("hostname", "").strip().lower()
            self._record_hostname(hostname, "otx", discovered, source_map)

        # 3. HackerTarget hostsearch
        self.log("Querying HackerTarget...")
        ht_results = await hackertarget_hostsearch(self.domain)
        for entry in ht_results:
            hostname = entry.get("hostname", "").strip().lower()
            if self._record_hostname(hostname, "hackertarget", discovered, source_map):
                if entry.get("ip"):
                    source_map[hostname + "_ip"] = entry["ip"]

        # 4. URLScan.io
        api_key = self.config.get("urlscan_api_key", "") or ""
        self.log("Querying URLScan.io...")
        urlscan_results = await urlscan_search(self.domain, api_key=api_key)
        for result in urlscan_results:
            page = result.get("page", {})
            domain_val = page.get("domain", "").strip().lower()
            self._record_hostname(domain_val, "urlscan", discovered, source_map)

        # 5. Additional free passive APIs
        free_api_sources = [
            ("rapiddns", rapiddns),
            ("anubisdb", anubisdb),
            ("certspotter", certspotter),
        ]
        for source_name, source_func in free_api_sources:
            self.log(f"Querying {source_name}...")
            try:
                hostnames = await source_func(self.domain)
            except Exception as exc:
                self.log(f"  {source_name} failed: {exc}")
                hostnames = []
            if hostnames:
                self.state.add_evidence(
                    self.id,
                    "passive_subdomains",
                    source_name,
                    {"source": source_name, "count": len(hostnames), "hosts": hostnames[:500]},
                )
            for hostname in hostnames:
                self._record_hostname(hostname, source_name, discovered, source_map)

        # 6. subfinder (if available)
        self.log("Running subfinder (if available)...")
        subfinder_results = await subfinder_scan(self.domain)
        for sub in subfinder_results:
            sub = sub.strip().lower()
            self._record_hostname(sub, "subfinder", discovered, source_map)

        # 7. amass passive (if available)
        self.log("Running amass passive (if available)...")
        amass_results = await amass_passive(self.domain)
        for sub in amass_results:
            sub = sub.strip().lower()
            self._record_hostname(sub, "amass", discovered, source_map)

        # 8. DNS brute-force from wordlist
        wordlist = self.config.get("wordlists", {}).get("subdomains", [])
        self.log(f"DNS brute-force: {len(wordlist)} candidates...")
        bf_candidates = [f"{sub}.{self.domain}" for sub in wordlist if sub]
        # Prefer dnsx for bulk, fallback to parallel dig
        try:
            resolved = await dnsx_resolve(bf_candidates)
            for hostname, ips in resolved.items():
                if hostname not in discovered:
                    discovered.add(hostname)
                source_map.setdefault(hostname, []).append("dns-brute")
                for ip in ips:
                    self.state.add_asset(
                        "ip", f"ip:{ip}", ip,
                        confidence="CONFIRMED",
                        sources=["dns-brute"],
                    )
                    self.state.add_edge(f"sub:{hostname}", f"ip:{ip}", "RESOLVES_TO")
        except Exception:
            # Fallback to parallel dig
            resolved_map = await dig_bulk(bf_candidates, concurrency=15)
            for hostname, answers in resolved_map.items():
                for answer in answers:
                    if answer and answer[0].isdigit():
                        if hostname not in discovered:
                            discovered.add(hostname)
                        source_map.setdefault(hostname, []).append("dns-brute")

        # 9. Register all discovered subdomains and resolve to IPs
        self.log(f"Resolving {len(discovered)} discovered subdomains...")
        all_subs = sorted(discovered)

        # Batch resolve using dnsx if available, otherwise parallel dig
        resolved_all = {}
        try:
            resolved_all = await dnsx_resolve(all_subs)
        except Exception:
            resolved_all = await dig_bulk(all_subs, concurrency=10)

        added = 0
        for sub in all_subs:
            if not self.scope.check(sub).allowed:
                continue
            ips = resolved_all.get(sub, [])
            sources = source_map.get(sub, ["passive"])

            if ips:
                confidence = "CONFIRMED"
                for ip in ips:
                    if ip and ip[0].isdigit():
                        self.state.add_asset(
                            "ip", f"ip:{ip}", ip,
                            confidence="CONFIRMED",
                            sources=sources,
                        )
                        self.state.add_edge(f"sub:{sub}", f"ip:{ip}", "RESOLVES_TO")
            else:
                confidence = "TENTATIVE"

            self.state.add_asset(
                "subdomain",
                f"sub:{sub}",
                sub,
                confidence=confidence,
                sources=sources,
                attrs={"ips": ips, "sources": sources},
            )
            added += 1

        # 10. Wildcard detection
        await self._check_wildcard()

        self.state.complete_module(self.id)
        self.log(
            "Subdomains: "
            f"{added} unique | Sources: crt.sh, OTX, HackerTarget, URLScan, "
            "RapidDNS, AnubisDB, Cert Spotter, subfinder, amass, dns-brute"
        )
        return "done"

    def _record_hostname(self, hostname: str, source: str, discovered: set,
                         source_map: dict) -> bool:
        hostname = str(hostname or "").strip().lower().lstrip("*.").strip(".")
        if not hostname:
            return False
        if hostname != self.domain and not hostname.endswith(f".{self.domain}"):
            return False
        if hostname not in discovered:
            discovered.add(hostname)
        source_map.setdefault(hostname, []).append(source)
        return True

    async def _check_wildcard(self):
        """Detect wildcard DNS to avoid false positives."""
        import uuid
        random_sub = f"{uuid.uuid4().hex[:8]}.{self.domain}"
        result = await dig("A", random_sub)
        if result.get("answers"):
            self.state.add_asset(
                "dns_wildcard",
                f"wildcard:{self.domain}",
                self.domain,
                confidence="CONFIRMED",
                sources=["wildcard detection"],
                attrs={"wildcard_ips": result["answers"]},
            )
            self.state.add_finding(
                title=f"Wildcard DNS Detected on {self.domain}",
                severity="INFO",
                confidence="CONFIRMED",
                category="DNS",
                description=f"Wildcard DNS is configured for *.{self.domain}, "
                            f"resolving to {result['answers']}. Subdomain brute-force "
                            f"results may contain false positives.",
                evidence=[f"*.{self.domain} → {result['answers']}"],
                remediation="Review wildcard DNS configuration.",
            )
