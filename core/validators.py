"""Read-only secret classification and structural validation."""

import base64
import ipaddress
import json
import re
from urllib.parse import urlparse, parse_qs, quote, urlencode


def is_routable_ip(ip: str) -> bool:
    """Is this an address whose reputation means anything about the target?

    A reputation vote on 127.0.0.1 is a fact about loopback and nothing
    else. Private, loopback and link-local addresses are not reachable
    from the internet, so nothing about them says how the target looks
    from outside.
    """
    try:
        return ipaddress.ip_address(str(ip or "").strip()).is_global
    except ValueError:
        return False


# TLDs that are not the public internet: DNS-empire modules (passive
# subdomain sources, takeover checks, ASN history, reputation feeds,
# mail security) return junk or hang on these, and findings like
# "No DMARC on localhost" are noise by construction.
_NON_PUBLIC_TLDS = {
    "localhost", "local", "invalid", "test", "example", "internal",
    "home", "lan", "corp", "intranet", "localdomain", "docker",
}


def is_public_target(host: str) -> bool:
    """Is this hostname on the public internet (FQDN, real TLD)?"""
    name = str(host or "").strip().lower().rstrip(".")
    if not name:
        return False
    try:
        if ipaddress.ip_address(name.split(":")[0].split("/")[0]).is_global:
            return True
    except ValueError:
        pass
    if "." not in name:
        return False
    tld = name.rsplit(".", 1)[-1]
    if not tld.isalpha() or len(tld) < 2 or tld in _NON_PUBLIC_TLDS:
        return False
    return True


# Response keys that must never leave the server, with the severity a
# live observation earns. Shared by response audits and JWT claim
# audits: a password hash in an API body and one in a token payload are
# the same exposure class.
RESPONSE_SENSITIVE_KEYS = {
    "password": "HIGH",
    "passwd": "HIGH",
    "passwordhash": "HIGH",
    "password_hash": "HIGH",
    "passhash": "HIGH",
    "secret": "HIGH",
    "client_secret": "HIGH",
    "private_key": "CRITICAL",
    "ssn": "HIGH",
    "social_security": "HIGH",
    "credit_card": "HIGH",
    "card_number": "HIGH",
    "cvv": "HIGH",
    "cvc": "HIGH",
    "bank_account": "HIGH",
    "api_key": "MEDIUM",
    "apikey": "MEDIUM",
    "auth_token": "MEDIUM",
    "access_token": "MEDIUM",
    "refresh_token": "MEDIUM",
    "session_token": "MEDIUM",
    "totp_secret": "HIGH",
    "totpsecret": "HIGH",
    "recovery_code": "MEDIUM",
    "backup_code": "MEDIUM",
}

_RESPONSE_DOCS_MARKERS = ("example", "test", "demo", "sample", "xxx",
                          "null", "undefined", "***", "redacted",
                          "hidden", "xxx-")


def looks_real_value(value) -> bool:
    """A value shaped like a genuine secret, not a placeholder."""
    text = str(value or "")
    if len(text) < 8:
        return False
    lowered = text.lower()
    if any(marker in lowered for marker in _RESPONSE_DOCS_MARKERS):
        return False
    if len(set(text)) < 5:
        return False
    return True


def walk_json(obj, path=""):
    """Yield (dotted.path, key, value) for every dict key in JSON."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            here = f"{path}.{key}" if path else str(key)
            yield here, key, value
            yield from walk_json(value, here)
    elif isinstance(obj, list):
        for index, value in enumerate(obj[:20]):
            yield from walk_json(value, f"{path}[{index}]")


def inject_param(url: str, param: str, value: str) -> str:
    """Replace a parameter's value regardless of its current value.

    Correctly handles URLs where the parameter doesn't yet appear, has a
    different value, or appears multiple times.  Use this everywhere a payload
    needs to be injected into a URL parameter — never str.replace().

    A placeholder in the **path** is filled in place rather than turned into a
    query parameter. Bundle-derived object references arrive as
    `/api/Users/{id}`, and appending gives `/api/Users/{id}?id=1'` — the hole
    stays open, the server serves its catch-all page, and every probe reports
    "no SQLi detected". That is a false negative manufactured by the injector,
    which is worse than the missing coverage it was meant to add: nine object
    references cleared on a URL that was never a real endpoint.
    """
    parsed = urlparse(url)
    placeholder = "{" + param + "}"

    if placeholder in parsed.path:
        # `quote` because a payload in a path segment must not be re-parsed as
        # structure: a bare `'` or `/` would change the path rather than the
        # value being tested.
        filled = parsed._replace(path=parsed.path.replace(
            placeholder, quote(value, safe="")))
        return filled.geturl()

    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_qs = urlencode(params, doseq=True)
    rebuilt = parsed._replace(query=new_qs)
    return rebuilt.geturl()


SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github_fine_grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("openai_project_key", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{32,}\b")),
    ("slack_token", re.compile(r"\bxox[bpoa]-[0-9A-Za-z-]{20,}\b")),
    ("stripe_live_key", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]


def extract_secrets(text: str) -> list[dict]:
    """Extract potential secrets with redacted values."""
    results = []
    seen = set()
    for secret_type, pattern in SECRET_PATTERNS:
        for match in pattern.findall(text or ""):
            value = match if isinstance(match, str) else match[0]
            key = (secret_type, value)
            if key in seen:
                continue
            seen.add(key)
            validation = validate_secret(secret_type, value)
            results.append({
                "type": secret_type,
                "redacted": redact_secret(value),
                "length": len(value),
                "validation": validation,
                # Full value for in-memory grading only (example-marker
                # checks, JWT expiry). Callers must never persist it:
                # reports and evidence files carry redacted form.
                "value": value,
            })
    return results


def validate_secret(secret_type: str, value: str) -> dict:
    """Perform structural validation only; no live credential use."""
    checks = {
        "format": bool(value),
        "entropy": _rough_entropy(value) >= 3.0,
        "live_check": "not_performed",
    }
    if secret_type == "jwt_token":
        checks["jwt_header"] = _valid_jwt_header(value)
    if secret_type == "aws_access_key":
        checks["prefix"] = value.startswith("AKIA")
    if secret_type in {"github_pat", "github_fine_grained"}:
        checks["prefix"] = value.startswith(("ghp_", "github_pat_"))
    verdict = "structurally_valid" if checks["format"] and checks["entropy"] else "weak_match"
    return {"verdict": verdict, "checks": checks}


def redact_secret(value: str) -> str:
    value = str(value or "")
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


# Substrings that mark a match as documentation, test fixture, or SDK
# bundle rather than a live credential. Shared by secret mining (JS,
# evidence files) and API audits so "example" is weak everywhere.
SECRET_EXAMPLE_MARKERS = (
    "example", "test", "demo", "sample", "xxx", "changeme", "placeholder",
    "your_", "fake", "dummy", "abcdef", "12345", "password123", "testkey",
    "public_key", "publickey",
)


def grade_secret_candidate(secret_type: str, value: str,
                           validation: Optional[dict] = None) -> tuple:
    """Plausible (real-shaped, worth rotating) vs weak (docs/test/expired).

    Read-only: shape, markers, and expiry only. Nothing here proves a
    credential works — that would require using it, which is out of
    scope — so callers must never file above MEDIUM on this alone.
    Returns (tier, reason).
    """
    text = str(value or "")
    lowered = text.lower()
    if any(marker in lowered for marker in SECRET_EXAMPLE_MARKERS):
        return "weak", "example/test marker in value"
    if validation and validation.get("verdict") not in (
            None, "structurally_valid"):
        return "weak", f"structural verdict: {validation.get('verdict')}"
    if secret_type == "jwt_token":
        verdict = analyze_jwt(text)
        if verdict["tier"] != "live_shaped":
            return "weak", verdict["reason"]
        return "plausible", "JWT decodes, unexpired, non-example"
    if "private_key" in secret_type:
        return "plausible", "private key block present (body not assessed)"
    if len(text) >= 12 and len(set(text)) >= 8:
        return "plausible", "real-shaped with no example markers"
    return "weak", "short/low-entropy match"


def _valid_jwt_header(value: str) -> bool:
    try:
        header = value.split(".", 1)[0]
        padded = header + "=" * (-len(header) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode()).decode(errors="ignore")
    except Exception:
        return False
    return decoded.strip().startswith("{") and '"alg"' in decoded


def analyze_jwt(value: str) -> dict:
    """Read-only JWT triage shared by secret mining and API audits.

    Returns {"tier", "reason", "claims", "expired"}. Tiers: "example"
    (docs/sample token), "expired", "live_shaped" (decodes, unexpired,
    non-example), "malformed". Nothing here proves the key behind the
    signature — that takes a replay, not a read.
    """
    text = str(value or "").strip()
    claims: dict = {}
    try:
        parts = text.split(".")
        if len(parts) != 3:
            return {"tier": "malformed", "reason": "not three segments",
                    "claims": {}, "expired": False}
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        decoded = base64.urlsafe_b64decode(payload_b64.encode()).decode()
        parsed = json.loads(decoded)
        claims = parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {"tier": "malformed", "reason": "payload does not decode",
                "claims": {}, "expired": False}
    lowered = text.lower()
    try:
        claims_text = json.dumps(claims).lower()
    except Exception:
        claims_text = ""
    if any(marker in lowered or marker in claims_text for marker in (
            "example", "sample", "test", "demo", "xxx", "abcdef",
            "john doe", "1234567890")):
        return {"tier": "example", "reason": "docs/sample marker in token",
                "claims": claims, "expired": False}
    header_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
    try:
        header = json.loads(base64.urlsafe_b64decode(header_b64.encode()).decode())
    except Exception:
        header = {}
    if isinstance(header, dict) and header.get("alg") == "none":
        return {"tier": "example", "reason": "unsigned (alg=none) token",
                "claims": claims, "expired": False}
    exp = claims.get("exp")
    if isinstance(exp, (int, float)):
        import time as _time
        if exp < _time.time():
            return {"tier": "expired", "reason": "exp is in the past",
                    "claims": claims, "expired": True}
    return {"tier": "live_shaped", "reason": "decodes, unexpired, non-example",
            "claims": claims, "expired": False}


def _rough_entropy(value: str) -> float:
    if not value:
        return 0.0
    unique = len(set(value))
    return min(8.0, unique.bit_length() + len(value).bit_length() / 8)
