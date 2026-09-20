"""Stage 3: TLS/SSL Deep Audit — protocols, ciphers, certificates, HSTS preload."""

import re
from datetime import datetime, timezone
from modules.base import BaseModule
from tools.wrappers import cert_info, tls_protocols, bash, ssl_scan


WEAK_PROTOCOLS = {"ssl2": "CRITICAL", "ssl3": "HIGH", "tls1": "MEDIUM", "tls1_1": "MEDIUM"}


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
        host = self.domain
        port = 443
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
                )

        # 4. Weak cipher check
        weak_cipher_result = await bash(
            f"echo | openssl s_client -connect {host}:{port} "
            f"-cipher 'DES:RC4:EXPORT:MD5' -servername {host} 2>&1 | head -5",
        )
        if "handshake failure" not in weak_cipher_result["stdout"].lower():
            if "cipher" in weak_cipher_result["stdout"].lower():
                self.state.add_finding(
                    title=f"Weak Cipher Suites Accepted",
                    severity="HIGH",
                    confidence="FIRM",
                    category="TLS Configuration",
                    description=f"{host} may accept weak cipher suites (DES, RC4, EXPORT, or MD5-based).",
                    evidence=["openssl weak cipher handshake did not fail"],
                    remediation="Configure server to only accept strong cipher suites.",
                    asset_keys=[f"domain:{host}"],
                )

        # 5. HSTS preload check
        hsts_result = await bash(
            f"curl -s -I --max-time 5 https://{host}/ 2>/dev/null | grep -i strict-transport"
        )
        hsts_header = hsts_result["stdout"].strip()
        if hsts_header:
            if "preload" not in hsts_header.lower():
                self.state.add_finding(
                    title="HSTS Missing preload Directive",
                    severity="LOW",
                    confidence="CONFIRMED",
                    category="TLS Configuration",
                    description=f"HSTS header present but missing 'preload' directive. "
                                f"Domain not eligible for browser preload list.",
                    evidence=[f"Header: {hsts_header}"],
                    remediation="Add 'preload' to HSTS header and submit to hstspreload.org.",
                )
            if "max-age" in hsts_header.lower():
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
                        )

        # 6. TLS 1.3 support check
        if protocols.get("tls1_3") is False:
            self.state.add_finding(
                title="TLS 1.3 Not Supported",
                severity="LOW",
                confidence="CONFIRMED",
                category="TLS Configuration",
                description=f"{host} does not support TLS 1.3, the most secure TLS version.",
                evidence=["TLS 1.3 handshake failed"],
                remediation="Enable TLS 1.3 support for improved security and performance.",
            )

        # 7. Certificate SANs summary
        sans = cert.get("san", [])

        # Store TLS asset
        self.state.add_asset(
            "tls_config",
            f"tls:{host}",
            host,
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

        self.state.complete_module(self.id)
        protocols_supported = [p for p, v in protocols.items() if v is True]
        self.log(
            f"TLS audit: expiry={days_left}d | "
            f"protocols={protocols_supported} | "
            f"SANs={len(sans)}"
        )
        return "done"
