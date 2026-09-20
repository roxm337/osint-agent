"""Stage 4: Origin Discovery — CDN bypass, real IP, Shodan, historical DNS."""

import re
import json
from modules.base import BaseModule
from tools.wrappers import curl, curl_with_status, dig, bash, shodan_host, asn_lookup


CDN_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1"},
]

CDN_INDICATORS = {
    "cloudflare": ["cf-ray", "cf-cache-status", "cloudflare"],
    "akamai": ["akamai", "x-check-cacheable", "x-akamai"],
    "fastly": ["x-fastly", "x-served-by", "fastly"],
    "cloudfront": ["x-amz-cf-id", "x-cache", "cloudfront"],
    "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "incapsula": ["x-iinfo", "x-cdn", "incapsula"],
    "azure_cdn": ["x-azure-ref", "x-ec-custom-error"],
    "maxcdn": ["x-cache", "x-edge-ip"],
}


class OriginDiscovery(BaseModule):
    id = "origin_discovery"
    name = "Origin IP Discovery"
    stage = 4
    detectability = "low"
    depends_on = ["seed_discovery", "tech_detection"]

    async def run(self) -> str:
        self.log("Discovering real origin IP behind CDN...")
        base_url = f"https://{self.domain}"

        cdn_detected = None
        origin_candidates = []

        # 1. Detect CDN from headers
        r = await curl(base_url, output="headers")
        headers_text = r.get("body", "").lower()

        for cdn_name, indicators in CDN_INDICATORS.items():
            if any(ind in headers_text for ind in indicators):
                cdn_detected = cdn_name
                self.log(f"  CDN detected: {cdn_name}")
                break

        if not cdn_detected:
            self.log("  No CDN detected.")
            self.state.complete_module(self.id)
            return "done"

        # 2. SPF record IP ranges — often reveal origin servers
        txt_result = await dig("TXT", self.domain)
        spf_ips = []
        for record in txt_result.get("answers", []):
            if "v=spf1" in record:
                # Extract ip4 includes
                for m in re.findall(r'ip4:([\d./]+)', record):
                    spf_ips.append(m.split("/")[0])
                # Expand include: domains
                for include in re.findall(r'include:([\w.-]+)', record):
                    inc_txt = await dig("TXT", include)
                    for inc_rec in inc_txt.get("answers", []):
                        for m in re.findall(r'ip4:([\d./]+)', inc_rec):
                            spf_ips.append(m.split("/")[0])

        if spf_ips:
            self.log(f"  SPF IPs found: {spf_ips}")
            for ip in spf_ips[:10]:
                origin_candidates.append({"ip": ip, "source": "SPF record"})

        # 3. Historical DNS via SecurityTrails (free endpoint)
        hist_result = await bash(
            f"curl -s 'https://securitytrails.com/list/apex_domain/{self.domain}' "
            f"--max-time 10 -H 'Accept: application/json' 2>/dev/null || true"
        )

        # 4. ViewDNS historical
        viewdns_result = await bash(
            f"curl -s 'https://viewdns.info/iphistory/?domain={self.domain}&output=json' "
            f"--max-time 10 2>/dev/null || true"
        )
        try:
            vd_data = json.loads(viewdns_result["stdout"])
            for record in vd_data.get("response", {}).get("records", []):
                ip = record.get("ip", "")
                if ip and not self._is_cdn_ip(ip, cdn_detected):
                    origin_candidates.append({"ip": ip, "source": "viewdns historical"})
        except (json.JSONDecodeError, TypeError):
            pass

        # 5. Censys.io origin search (public API, no key needed for basic)
        censys_result = await bash(
            f"curl -s 'https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.names%3A{self.domain}&per_page=5' "
            f"--max-time 10 2>/dev/null || true"
        )
        try:
            c_data = json.loads(censys_result["stdout"])
            for host in c_data.get("result", {}).get("hits", []):
                ip = host.get("ip", "")
                if ip and not self._is_cdn_ip(ip, cdn_detected):
                    origin_candidates.append({"ip": ip, "source": "censys TLS certs"})
        except (json.JSONDecodeError, TypeError):
            pass

        # 6. Shodan lookup (if API key available)
        shodan_key = self.config.get("shodan_api_key", "")
        if not shodan_key:
            import os
            shodan_key = os.environ.get("SHODAN_API_KEY", "")

        if shodan_key:
            shodan_result = await bash(
                f"curl -s 'https://api.shodan.io/shodan/host/search?key={shodan_key}&query=hostname:{self.domain}' "
                f"--max-time 10 2>/dev/null || true"
            )
            try:
                s_data = json.loads(shodan_result["stdout"])
                for match in s_data.get("matches", []):
                    ip = match.get("ip_str", "")
                    if ip and not self._is_cdn_ip(ip, cdn_detected):
                        origin_candidates.append({"ip": ip, "source": "shodan"})
            except (json.JSONDecodeError, TypeError):
                pass

        # 7. Verify candidates by direct IP request
        confirmed_origins = []
        for candidate in origin_candidates:
            ip = candidate["ip"]
            verified = await self._verify_origin(ip)
            if verified:
                confirmed_origins.append({**candidate, "verified": True})

                # ASN lookup
                asn_info = await asn_lookup(ip)
                self.state.add_asset(
                    "ip",
                    f"ip:{ip}",
                    ip,
                    confidence="CONFIRMED",
                    sources=["origin discovery"],
                    attrs={
                        "origin": True,
                        "source": candidate["source"],
                        "asn": asn_info.get("asn", ""),
                        "org": asn_info.get("org", ""),
                    },
                )

        if confirmed_origins:
            self.state.add_finding(
                title=f"Origin IP Discovered Behind {cdn_detected.title()} CDN",
                severity="HIGH",
                confidence="CONFIRMED",
                category="CDN Bypass",
                description=(
                    f"Real origin server IP(s) discovered behind {cdn_detected} CDN: "
                    f"{[c['ip'] for c in confirmed_origins]}. "
                    f"Direct access bypasses WAF/CDN protections and rate limiting."
                ),
                evidence=[
                    f"{c['ip']} (source: {c['source']})"
                    for c in confirmed_origins
                ],
                remediation=(
                    "Restrict origin server to only accept connections from CDN IP ranges. "
                    "Implement firewall rules blocking direct access from non-CDN sources."
                ),
            )
        elif origin_candidates:
            self.log(f"  {len(origin_candidates)} candidates found but none verified.")

        # 8. CDN bypass header test
        await self._test_cdn_bypass_headers(base_url)

        self.state.add_asset(
            "origin_discovery",
            f"origin:{self.domain}",
            self.domain,
            confidence="CONFIRMED",
            sources=["origin discovery"],
            attrs={
                "cdn": cdn_detected,
                "candidates": len(origin_candidates),
                "confirmed_origins": confirmed_origins,
                "spf_ips": spf_ips,
            },
        )

        self.state.complete_module(self.id)
        self.log(
            f"Origin discovery: CDN={cdn_detected} | "
            f"candidates={len(origin_candidates)} | "
            f"confirmed={len(confirmed_origins)}"
        )
        return "done"

    async def _verify_origin(self, ip: str) -> bool:
        """Verify IP serves the target domain by requesting with Host header."""
        r = await curl(
            f"https://{ip}",
            headers={"Host": self.domain},
            output="status",
        )
        status = r.get("status", 0)
        if status in (200, 301, 302, 403, 401):
            return True
        # Try HTTP
        r2 = await curl(
            f"http://{ip}",
            headers={"Host": self.domain},
            output="status",
        )
        return r2.get("status", 0) in (200, 301, 302, 403, 401)

    def _is_cdn_ip(self, ip: str, cdn: str) -> bool:
        """Basic heuristic to filter out known CDN IP ranges."""
        cdn_ranges = {
            "cloudflare": ["103.21.", "103.22.", "103.31.", "104.16.", "104.17.",
                           "104.18.", "104.19.", "172.64.", "172.65.", "172.66.",
                           "172.67.", "172.68.", "172.69.", "198.41."],
            "cloudfront": ["13.32.", "13.35.", "52.84.", "54.192.", "54.230."],
            "fastly": ["23.235.", "43.249.", "103.244.", "151.101.", "157.52.",
                       "167.82.", "172.111.", "185.31.", "199.27.", "199.232."],
            "akamai": ["2.16.", "23.0.", "23.1.", "23.2.", "23.3.", "104.64.",
                       "184.24.", "184.25.", "184.26.", "184.27.", "184.28."],
        }
        ranges = cdn_ranges.get(cdn, [])
        return any(ip.startswith(r) for r in ranges)

    async def _test_cdn_bypass_headers(self, base_url: str):
        """Test if CDN can be bypassed with IP spoofing headers."""
        self.log("  Testing CDN bypass headers...")
        # Get baseline response
        baseline = await curl_with_status(base_url)
        baseline_size = len(baseline.get("body", ""))

        for header_dict in CDN_BYPASS_HEADERS[:4]:  # Limit to 4 tests
            r = await curl(
                base_url,
                headers={**header_dict, "User-Agent": "Mozilla/5.0"},
                output="body",
            )
            body = r.get("body", "")
            # Significant size difference may indicate bypass
            if body and abs(len(body) - baseline_size) > 500:
                header_name = list(header_dict.keys())[0]
                self.state.add_finding(
                    title=f"Potential CDN Bypass via {header_name}",
                    severity="MEDIUM",
                    confidence="TENTATIVE",
                    category="CDN Bypass",
                    description=f"Response with {header_name}: 127.0.0.1 differs significantly "
                                f"from baseline, suggesting IP spoofing header may affect behavior.",
                    evidence=[
                        f"Header: {header_dict}",
                        f"Baseline size: {baseline_size}",
                        f"Modified size: {len(body)}",
                    ],
                    remediation="Configure CDN/WAF to strip IP spoofing headers from untrusted sources.",
                )
