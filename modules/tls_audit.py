"""Stage 3: TLS/SSL Deep Audit — protocols, ciphers, certificates, HSTS."""

import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from modules.base import BaseModule
from tools.external import run_command
from tools.wrappers import cert_info, curl, tls_protocols


WEAK_PROTOCOLS = {"ssl2": "CRITICAL", "ssl3": "HIGH", "tls1": "MEDIUM", "tls1_1": "MEDIUM"}

WEAK_CIPHER_STRING = "DES:RC4:EXPORT:LOW:MD5:NULL:eNULL"


def parse_cert_expiry(not_after: str) -> tuple:
    """Parse certificate expiry and return (days_until_expiry, expired)."""
    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(not_after.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            delta = dt - now
            return delta.days, delta.days <= 0
        except ValueError:
            continue
    return None, False


class TLSAudit(BaseModule):
    id = "tls_audit"
    name = "TLS/SSL Deep Audit"
    stage = 3
    detectability = "low"
    depends_on = ["seed_discovery"]

    async def run(self) -> str:
        endpoints = self._tls_endpoints()
        if not endpoints:
            self.state.skip_module(self.id, "no TLS endpoints (plaintext only)")
            return "skipped"
        for host, port in endpoints:
            await self._audit_endpoint(host, port)
        self.state.complete_module(self.id)
        return "done"

    def _tls_endpoints(self) -> list:
        """(host, port) pairs that actually speak TLS: the base URL when
        https, plus every discovered webapp URL with an https scheme."""
        endpoints = []

        def add(value: str):
            try:
                parsed = urlparse(value if "://" in value else f"https://{value}")
            except Exception:
                return
            if (parsed.scheme or "https").lower() != "https":
                return
            host = (parsed.hostname or "").strip()
            if not host:
                return
            port = parsed.port or 443
            if (host, port) not in endpoints:
                endpoints.append((host, port))

        add(self.base_url)
        for asset in self.state.get_assets_by_type("webapp"):
            add(str(asset.get("value", "") or ""))
        return endpoints[:10]

    async def _audit_endpoint(self, host: str, port: int) -> None:
        self.log(f"TLS audit for {host}:{port}...")

        # 1. Certificate details
        cert = await cert_info(host, port)
        protocols = await tls_protocols(host, port)

        # 2. Certificate expiry check
        not_after = cert.get("notafter", cert.get("not after", ""))
        days_left, expired = None, False
        if not_after:
            days_left, expired = parse_cert_expiry(not_after)

        if expired:
            self.state.add_finding(
                title=f"TLS Certificate Expired: {host}",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="TLS Configuration",
                description=f"TLS certificate for {host} has expired.",
                evidence=[f"Not After: {not_after}"],
                remediation="Renew TLS certificate immediately.",
                asset_keys=[f"domain:{host}"],
                verified=True,
                verification={"method": "cert_notafter_parse",
                              "url": f"{host}:{port}"},
            )
        elif days_left is not None and days_left <= 30:
            self.state.add_finding(
                title=f"TLS Certificate Expiring Soon: {days_left} days",
                severity="HIGH" if days_left <= 14 else "MEDIUM",
                confidence="CONFIRMED",
                category="TLS Configuration",
                description=f"TLS certificate for {host} expires in {days_left} days.",
                evidence=[f"Not After: {not_after}", f"Days remaining: {days_left}"],
                remediation="Renew TLS certificate before expiration.",
                asset_keys=[f"domain:{host}"],
                verified=True,
                verification={"method": "cert_notafter_parse",
                              "url": f"{host}:{port}"},
            )

        # 3. Weak protocol check
        for proto, proto_state in protocols.items():
            if proto_state is True and proto in WEAK_PROTOCOLS:
                severity = WEAK_PROTOCOLS[proto]
                proto_display = proto.upper().replace("TLS1", "TLS 1.0").replace("TLS1_1", "TLS 1.1")
                self.state.add_finding(
                    title=f"Weak TLS Protocol Supported: {proto_display}",
                    severity=severity,
                    confidence="CONFIRMED",
                    category="TLS Configuration",
                    description=(
                        f"{host} supports {proto_display}, which is considered insecure. "
                        f"SSLv2/3 allow DROWN/POODLE attacks; TLS 1.0/1.1 are deprecated by PCI-DSS."
                    ),
                    evidence=[f"Protocol: {proto_display} — supported"],
                    remediation=f"Disable {proto_display} in server configuration. "
                                f"Require TLS 1.2 minimum; TLS 1.3 preferred.",
                    asset_keys=[f"domain:{host}"],
                    verified=True,
                    verification={"method": "tls_handshake_offer",
                                  "url": f"{host}:{port}"},
                )

        # 4. Weak cipher check: constrain the offered ciphers to weak-only
        # and read the NEGOTIATED cipher name. A handshake that completes
        # with a weak cipher is proof; banner-text matching is not.
        weak_cipher = await self._negotiated_weak_cipher(host, port)
        if weak_cipher:
            self.state.add_finding(
                title="Weak Cipher Suites Accepted",
                severity="HIGH",
                confidence="CONFIRMED",
                category="TLS Configuration",
                description=(f"{host} negotiated {weak_cipher} when offered "
                             f"only weak ciphers — DES/RC4/EXPORT/MD5-class "
                             f"suites are enabled."),
                evidence=[f"Negotiated weak cipher: {weak_cipher}"],
                remediation="Configure server to only accept strong cipher suites.",
                asset_keys=[f"domain:{host}"],
                verified=True,
                verification={"method": "weak_cipher_negotiation",
                              "url": f"{host}:{port}"},
            )

        # 4b. Nmap TLS script corroboration: named vulnerabilities beat
        # cipher-name debates. Bounded single invocation per endpoint.
        await self._nmap_tls_scripts(host, port)

        # 5. HSTS checks via the HTTP client (no shell). Preload absence
        # and missing TLS 1.3 are hygiene notes (INFO); a short max-age is
        # actionable (LOW).
        try:
            response = await curl(f"https://{host}/" if port == 443 else f"https://{host}:{port}/",
                                  output="headers", timeout=10)
            raw_headers = response.get("body", "") or ""
        except Exception:
            raw_headers = ""
        hsts_header = ""
        for line in str(raw_headers).splitlines():
            if line.lower().startswith("strict-transport-security"):
                hsts_header = line.strip()
                break
        if hsts_header:
            if "preload" not in hsts_header.lower():
                self.state.add_finding(
                    title="HSTS Missing preload Directive",
                    severity="INFO",
                    confidence="CONFIRMED",
                    category="TLS Configuration",
                    description="HSTS header present but missing 'preload' directive. "
                                "Domain not eligible for browser preload list.",
                    evidence=[f"Header: {hsts_header}"],
                    remediation="Add 'preload' to HSTS header and submit to hstspreload.org.",
                    verified=True,
                    verification={"method": "hsts_header_observed",
                                  "url": f"{host}:{port}"},
                )
            max_age_match = re.search(r"max-age=(\d+)", hsts_header.lower())
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 15768000:  # Less than 6 months
                    self.state.add_finding(
                        title="HSTS max-age Too Short",
                        severity="LOW",
                        confidence="CONFIRMED",
                        category="TLS Configuration",
                        description=f"HSTS max-age of {max_age} seconds is below "
                                    f"recommended minimum of 15768000 (6 months).",
                        evidence=[f"Header: {hsts_header}"],
                        remediation="Increase HSTS max-age to at least 31536000 (1 year).",
                        verified=True,
                        verification={"method": "hsts_header_observed",
                                      "url": f"{host}:{port}"},
                    )

        # 6. TLS 1.3 support check: hygiene note, not a LOW.
        if protocols.get("tls1_3") is False:
            self.state.add_finding(
                title="TLS 1.3 Not Supported",
                severity="INFO",
                confidence="CONFIRMED",
                category="TLS Configuration",
                description=f"{host} does not support TLS 1.3, the most secure TLS version.",
                evidence=["TLS 1.3 handshake failed"],
                remediation="Enable TLS 1.3 support for improved security and performance.",
                verified=True,
                verification={"method": "tls_handshake_offer",
                              "url": f"{host}:{port}"},
            )

        # 7. Certificate SANs: in-scope names become subdomain leads, and
        # the summary asset records the full picture per endpoint.
        sans = cert.get("san", []) or []
        for san in sans:
            name = str(san or "").strip().lower().lstrip("*.")
            if name and name.endswith(self.domain.lower()) and name != self.domain.lower():
                self.state.add_asset(
                    "subdomain",
                    f"sub:{name}",
                    name,
                    confidence="TENTATIVE",
                    sources=["tls san"],
                    attrs={"source": "certificate SAN", "host": host},
                )

        # Store TLS asset
        self.state.add_asset(
            "tls_config",
            f"tls:{host}:{port}",
            f"{host}:{port}",
            confidence="CONFIRMED",
            sources=["tls audit"],
            attrs={
                "certificate": cert,
                "protocols": protocols,
                "days_until_expiry": days_left,
                "hsts_header": hsts_header,
                "san_count": len(sans),
                "sans_sample": sans[:20],
            },
        )

        protocols_supported = [p for p, v in protocols.items() if v is True]
        self.log(
            f"TLS audit: {host}:{port} expiry={days_left}d | "
            f"protocols={protocols_supported} | "
            f"SANs={len(sans)}"
        )

    async def _nmap_tls_scripts(self, host: str, port: int) -> None:
        """Corroborate with named-vulnerability NSE scripts.

        openssl proves configuration; nmap names CVEs. A Heartbleed
        VULNERABLE is worth more than any cipher debate, and a clean
        script run corroborates the openssl side without filing.
        """
        from tools.external import tool_available
        if not tool_available("nmap"):
            return
        try:
            result = await run_command(
                ["nmap", "-p", str(port), "--script",
                 "ssl-enum-ciphers,ssl-heartbleed,ssl-ccs-injection,ssl-poodle",
                 "--script-timeout", "60s", host],
                timeout=150,
            )
        except Exception:
            return
        stdout = result.get("stdout", "") or ""
        if "Heartbleed: " in stdout and "VULNERABLE" in stdout:
            self._tls_vuln_finding(
                host, "TLS Heartbleed (CVE-2014-0160)", "CRITICAL",
                "nmap ssl-heartbleed reports VULNERABLE: heap memory readable.",
                stdout)
        if "CCS Injection: VULNERABLE" in stdout or (
                "ssl-ccs-injection" in stdout and "VULNERABLE" in stdout):
            self.state.add_finding(
                title="TLS CCS Injection (CVE-2014-0224)",
                severity="HIGH",
                confidence="FIRM",
                category="TLS Configuration",
                description=f"{host} is VULNERABLE to CCS injection per nmap.",
                evidence=["nmap ssl-ccs-injection: VULNERABLE"],
                remediation="Update OpenSSL; disable session ticket CCS.",
                asset_keys=[f"domain:{host}"],
            )
        grade = ""
        for line in stdout.splitlines():
            if "least strength:" in line.lower():
                grade = line.split(":", 1)[1].strip().upper()[:1]
        if grade in ("C", "D", "F"):
            self.state.add_finding(
                title=f"Weak TLS Configuration (Grade {grade})",
                severity="MEDIUM" if grade == "C" else "HIGH",
                confidence="FIRM",
                category="TLS Configuration",
                description=(f"nmap ssl-enum-ciphers grades {host} least "
                             f"strength {grade}. Corroborates weak "
                             f"protocol/cipher posture."),
                evidence=[f"nmap least strength: {grade}"],
                remediation="Disable legacy protocols and weak ciphers; "
                            "prefer TLS 1.2+ with AEAD suites.",
                asset_keys=[f"domain:{host}"],
            )

    def _tls_vuln_finding(self, host: str, title: str, severity: str,
                          description: str, stdout: str) -> None:
        lines = [line.strip() for line in stdout.splitlines()
                 if "VULNERABLE" in line or "State:" in line][:6]
        self.state.add_finding(
            title=f"{title}: {host}",
            severity=severity,
            confidence="FIRM",
            category="TLS Configuration",
            description=description,
            evidence=lines or ["nmap reported VULNERABLE"],
            remediation="Patch immediately; this is remotely exploitable.",
            asset_keys=[f"domain:{host}"],
            verified=False,
        )

    async def _negotiated_weak_cipher(self, host: str, port: int) -> str:
        """Offer only weak ciphers; return the negotiated name or ''."""
        try:
            result = await run_command(
                ["openssl", "s_client", "-connect", f"{host}:{port}",
                 "-servername", host, "-cipher", WEAK_CIPHER_STRING],
                timeout=20,
                stdin_data="\n",
            )
        except Exception:
            return ""
        stdout = result.get("stdout", "") or ""
        if "handshake failure" in stdout.lower():
            return ""
        match = re.search(r"^\s*Cipher\s*:\s*(\S+)", stdout, re.M)
        if not match:
            return ""
        cipher = match.group(1).strip()
        if cipher.upper() in ("(NONE)", "0000", "NONE"):
            return ""
        return cipher
