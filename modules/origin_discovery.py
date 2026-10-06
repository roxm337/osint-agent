"""Stage 4: Origin Discovery — CDN bypass via differential proof.

An origin claim needs proof, not a status code. The old check returned
True for any 200/301/302/403/401 with a Host header, which wildcard
vhosts and parking pages pass trivially. Here a candidate IP is the
origin only when it serves the SAME content as the CDN baseline (body
hash equality) or presents a certificate covering the domain. SPF
mail-server IPs are not candidates at all: mail infrastructure is not
the web origin.
"""

import hashlib
import re

from core.validators import is_routable_ip
from modules.base import BaseModule
from tools.external import run_command
from tools.wrappers import crtsh, curl, dig, securitytrails_history_dns


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

# Headers whose appearance under a spoofed IP proves the header was
# honored, not merely that the page is dynamic.
ORIGIN_REVEAL_MARKERS = (
    "x-backend", "x-origin", "x-server-name", "x-powered-by: php",
    "x-aspnet-version", "server: apache", "server: nginx",
)


class OriginDiscovery(BaseModule):
    id = "origin_discovery"
    name = "Origin IP Discovery"
    stage = 4
    detectability = "low"
    depends_on = ["seed_discovery", "tech_detection"]

    async def run(self) -> str:
        self.log("Discovering real origin IP behind CDN...")
        base_url = self.base_url

        # 1. Detect CDN from headers + establish the content baseline.
        # The baseline body hash is the oracle everything else is
        # compared against: same bytes from a direct IP means same backend.
        try:
            base_result = await curl(base_url, output="full", timeout=20)
        except Exception:
            base_result = {}
        base_body = base_result.get("body", "") or ""
        base_hash = hashlib.sha256(base_body.encode()).hexdigest() if base_body else ""
        headers_text = str(base_result.get("headers", "") or "").lower()

        cdn_detected = None
        for cdn_name, indicators in CDN_INDICATORS.items():
            if any(ind in headers_text for ind in indicators):
                cdn_detected = cdn_name
                self.log(f"  CDN detected: {cdn_name}")
                break

        if not cdn_detected:
            self.log("  No CDN detected — direct hosting; still checking history.")
        if not base_hash or len(base_body) < 200:
            self.log("  No usable content baseline; verification downgraded.")

        # 2. Candidate IPs: historical DNS (authenticated), CT hostnames
        # resolved now, current A records outside CDN ranges. No SPF: mail
        # servers are not the web origin.
        candidates = await self._gather_candidates(cdn_detected)
        self.log(f"  {len(candidates)} origin candidate(s)")

        # 3. Verify each candidate differentially, inside a time-box:
        # each verify is an HTTP fetch plus an openssl TLS probe.
        import time as _time
        try:
            _deadline = float(self.config.get("module_timeout", 300) or 300)
        except (TypeError, ValueError):
            _deadline = 300.0
        _stop_at = _time.monotonic() + max(60.0, _deadline - 30.0)
        confirmed = []
        likely = []
        for candidate in candidates[:25]:
            if _time.monotonic() >= _stop_at:
                self.log("  Time-box hit — keeping the origins verified so far")
                break
            ip = candidate["ip"]
            verdict, proof = await self._verify_origin(ip, base_hash)
            if verdict == "confirmed":
                confirmed.append({**candidate, "proof": proof})
                self.state.add_asset(
                    "ip",
                    f"ip:{ip}",
                    ip,
                    confidence="CONFIRMED",
                    sources=["origin discovery"],
                    attrs={
                        "origin": True,
                        "source": candidate["source"],
                        "proof": proof,
                    },
                )
            elif verdict == "likely":
                likely.append({**candidate, "proof": proof})

        if confirmed:
            self.state.add_finding(
                title=f"Origin IP Discovered Behind {cdn_detected.title() + ' ' if cdn_detected else ''}CDN".replace("  ", " ").strip(),
                severity="HIGH",
                confidence="CONFIRMED",
                category="CDN Bypass",
                description=(
                    f"Real origin server IP(s) serve byte-identical content to "
                    f"the CDN baseline or present a certificate covering "
                    f"{self.domain}: "
                    f"{[c['ip'] for c in confirmed]}. "
                    f"Direct access bypasses WAF/CDN protections and rate limiting."
                ),
                evidence=[
                    f"{c['ip']} (source: {c['source']}; {c['proof']})"
                    for c in confirmed
                ],
                remediation=(
                    "Restrict origin server to only accept connections from CDN IP ranges. "
                    "Implement firewall rules blocking direct access from non-CDN sources."
                ),
                verified=True,
                verification={"method": "origin_content_or_cert",
                              "url": self.base_url},
            )
        if likely:
            self.state.add_finding(
                title=f"Likely Origin IP(s) (Unconfirmed): {len(likely)} candidate(s)",
                severity="MEDIUM",
                confidence="FIRM",
                category="CDN Bypass",
                description=(
                    "Candidate IPs show origin signals (domain certificate or "
                    "protected API surface) without byte-identical content. "
                    "Verify by hand before firewalling."
                ),
                evidence=[
                    f"{c['ip']} (source: {c['source']}; {c['proof']})"
                    for c in likely[:10]
                ],
                remediation="Manually verify, then restrict origin to CDN ranges.",
            )
        if candidates and not confirmed and not likely:
            self.log("  Candidates found but none verified.")

        # 4. CDN bypass header test (honest version below).
        await self._test_cdn_bypass_headers(base_url)

        self.state.add_asset(
            "origin_discovery",
            f"origin:{self.domain}",
            self.domain,
            confidence="CONFIRMED",
            sources=["origin discovery"],
            attrs={
                "cdn": cdn_detected,
                "candidates": len(candidates),
                "confirmed_origins": [c["ip"] for c in confirmed],
                "likely_origins": [c["ip"] for c in likely],
            },
        )

        self.state.complete_module(self.id)
        self.log(
            f"Origin discovery: CDN={cdn_detected} | "
            f"candidates={len(candidates)} | confirmed={len(confirmed)}"
        )
        return "done"

    # ── Candidates ──────────────────────────────────────────────

    async def _gather_candidates(self, cdn_detected: str | None) -> list:
        """Historical + CT-derived IPs outside known CDN ranges."""
        import time
        from core.validators import is_public_target
        try:
            _deadline = float(self.config.get("module_timeout", 300) or 300)
        except (TypeError, ValueError):
            _deadline = 300.0
        _stop_at = time.monotonic() + max(60.0, _deadline - 60.0)
        candidates: dict[str, dict] = {}
        public = is_public_target(self.domain)

        def consider(ip: str, source: str):
            ip = str(ip or "").strip()
            if not ip or not is_routable_ip(ip):
                return
            if cdn_detected and self._is_cdn_ip(ip, cdn_detected):
                return
            candidates.setdefault(ip, {"ip": ip, "source": source})

        # Authenticated historical DNS — public targets only: crt.sh and
        # SecurityTrails know nothing about localhost but answer slowly.
        st_key = self.keys.get("securitytrails") or ""
        if public and st_key:
            try:
                history = await securitytrails_history_dns(self.domain, st_key)
            except Exception as exc:
                self.log(f"  SecurityTrails failed: {exc}")
                history = {}
            for record in (history.get("records") or [])[:20]:
                for value in (record.get("values") or [])[:10]:
                    consider(str(value.get("ip", "")), "securitytrails history")
        else:
            self.log("  SecurityTrails: skipped (no API key)")

        # Certificate-transparency hostnames resolved now: names the
        # target pointed at the open internet, minus CDN ranges.
        # Public only — CT for localhost is noise served slowly.
        entries = []
        if public:
            try:
                entries = await crtsh(self.domain)
            except Exception:
                entries = []
        names = set()
        for entry in (entries or [])[:100]:
            if isinstance(entry, dict):
                raw = entry.get("name_value", "") or entry.get("common_name", "")
            else:
                raw = str(entry)
            for name in raw.splitlines():
                name = name.strip().lower().lstrip("*.")
                if name and name.endswith(self.domain.lower()):
                    names.add(name)
        for name in sorted(names)[:40]:
            if time.monotonic() >= _stop_at:
                self.log("  Time-box hit during CT resolution")
                break
            try:
                resolved = await dig("A", name)
            except Exception:
                continue
            for answer in resolved.get("answers", [])[:5]:
                consider(str(answer).split()[0], f"crt.sh:{name}")

        # Current A records of known subdomains outside CDN ranges.
        for asset in self.state.get_assets_by_type("subdomain")[:100]:
            if time.monotonic() >= _stop_at:
                self.log("  Time-box hit during subdomain resolution")
                break
            host = str(asset.get("value", "")).strip()
            if not host:
                continue
            try:
                resolved = await dig("A", host)
            except Exception:
                continue
            for answer in resolved.get("answers", [])[:3]:
                consider(str(answer).split()[0], f"subdomain:{host}")

        return list(candidates.values())

    # ── Verification ────────────────────────────────────────────

    async def _verify_origin(self, ip: str, base_hash: str) -> tuple:
        """Differential origin proof. Returns (verdict, proof).

        confirmed: the IP serves byte-identical content to the CDN
        baseline, or presents a certificate covering the domain AND a
        protected/live HTTP surface. likely: domain cert without content
        equality. Anything else: not the origin.
        """
        # Plain HTTP with Host header: no TLS pitfalls.
        http_status, http_body = 0, ""
        try:
            result = await curl(
                f"http://{ip}",
                headers={"Host": self.domain},
                output="full",
                timeout=12,
            )
            http_status = result.get("status", 0)
            http_body = result.get("body", "") or ""
        except Exception:
            pass
        if http_body and base_hash and \
                hashlib.sha256(http_body.encode()).hexdigest() == base_hash:
            return "confirmed", f"HTTP body byte-identical to CDN baseline ({len(http_body)} bytes)"

        # HTTPS: content equality plus certificate coverage via openssl
        # (SNI carries the domain; verification is off by construction —
        # the point is what the server presents, not whether we trust it).
        tls_status, tls_body, sans = await self._tls_probe(ip)
        if tls_body and base_hash and \
                hashlib.sha256(tls_body.encode()).hexdigest() == base_hash:
            return "confirmed", f"TLS body byte-identical to CDN baseline ({len(tls_body)} bytes)"
        domain_covered = self._cert_covers(sans)
        if domain_covered and tls_status in (200, 401, 403):
            level = "confirmed" if tls_status == 200 else "likely"
            return level, (f"serves a certificate covering {self.domain} "
                           f"(HTTP {tls_status} on direct IP)")
        if domain_covered:
            return "likely", f"serves a certificate covering {self.domain}"
        return "unproven", f"HTTP {http_status}, TLS {tls_status}, no cert/body match"

    async def _tls_probe(self, ip: str) -> tuple:
        """Fetch via openssl s_client with SNI; parse status/body/SANs."""
        request = (f"GET / HTTP/1.0\r\nHost: {self.domain}\r\n"
                   f"Connection: close\r\n\r\n")
        try:
            result = await run_command(
                ["openssl", "s_client", "-connect", f"{ip}:443",
                 "-servername", self.domain, "-ign_eof", "-showcerts"],
                timeout=20,
                stdin_data=request,
            )
        except Exception as exc:
            return 0, "", []
        stdout = result.get("stdout", "") or ""
        sans = re.findall(r"DNS:([^\s,]+)", stdout)
        # Split the HTTP response out of the s_client session chatter: the
        # first HTTP/ line starts it, session info follows the body.
        status, body = 0, ""
        match = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", stdout)
        if match:
            status = int(match.group(1))
            tail = stdout[match.end():]
            sep = re.search(r"\r\n\r\n|\n\n", tail)
            if sep:
                remainder = tail[sep.end():]
                # Cut s_client's post-response session dump.
                cut = re.search(
                    r"\n(?:New, [A-Z]|Verify return code|---\n|closed)", remainder)
                body = (remainder[:cut.start()] if cut else remainder)[:20000]
        return status, body, sans

    def _cert_covers(self, sans: list) -> bool:
        """Does any presented SAN match the apex or a subdomain of it?"""
        apex = self.domain.lower().lstrip(".")
        for san in sans:
            entry = str(san or "").lower()
            if entry == apex or entry.endswith("." + apex):
                return True
            if entry.startswith("*.") and (
                    entry[2:] == apex or entry[2:].endswith("." + apex)):
                return True
        return False

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
        ranges = cdn_ranges.get(cdn or "", [])
        return any(ip.startswith(r) for r in ranges)

    async def _test_cdn_bypass_headers(self, base_url: str):
        """IP-spoofing headers only count when they reveal origin markers.

        A bare size delta on a dynamic page is not a bypass. The response
        must additionally surface something only the origin would say: a
        changed Server/backend header or an origin-revealing body marker.
        """
        self.log("  Testing CDN bypass headers...")
        try:
            baseline = await curl(base_url, output="full", timeout=15)
        except Exception:
            return
        baseline_body = baseline.get("body", "") or ""
        baseline_server = str((baseline.get("headers", "") or ""))
        if not baseline_body:
            return

        for header_dict in CDN_BYPASS_HEADERS[:4]:  # Limit to 4 tests
            try:
                result = await curl(
                    base_url,
                    headers={**header_dict, "User-Agent": "Mozilla/5.0"},
                    output="full",
                    timeout=15,
                )
            except Exception:
                continue
            body = result.get("body", "") or ""
            headers_text = str(result.get("headers", "") or "").lower()
            if not body or abs(len(body) - len(baseline_body)) <= 500:
                continue
            reveals = [marker for marker in ORIGIN_REVEAL_MARKERS
                       if marker in headers_text or marker in body.lower()]
            server_changed = _server_header(headers_text) != _server_header(
                baseline_server.lower())
            if reveals or server_changed:
                header_name = list(header_dict.keys())[0]
                self.state.add_finding(
                    title=f"CDN Bypass via {header_name} Exposes Origin Markers",
                    severity="MEDIUM",
                    confidence="FIRM",
                    category="CDN Bypass",
                    description=(f"Response with {header_name}: 127.0.0.1 differs "
                                 f"from baseline AND reveals origin markers: "
                                 f"{reveals or ['Server header changed']}."),
                    evidence=[
                        f"Header: {header_dict}",
                        f"Baseline size: {len(baseline_body)}",
                        f"Modified size: {len(body)}",
                        f"Markers: {reveals or ['server-change']}",
                    ],
                    remediation="Configure CDN/WAF to strip IP spoofing headers from untrusted sources.",
                )


def _server_header(headers_text: str) -> str:
    """Extract the server response header value, if any."""
    match = re.search(r"^server:\s*([^\r\n]+)", headers_text, re.M | re.I)
    return match.group(1).strip().lower() if match else ""
