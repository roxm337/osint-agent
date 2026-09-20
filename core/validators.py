"""Read-only secret classification and structural validation."""

import base64
import re
from urllib.parse import urlparse, parse_qs, urlencode


def inject_param(url: str, param: str, value: str) -> str:
    """Replace a query parameter's value regardless of its current value.

    Correctly handles URLs where the parameter doesn't yet appear, has a
    different value, or appears multiple times.  Use this everywhere a payload
    needs to be injected into a URL parameter — never str.replace().
    """
    parsed = urlparse(url)
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


def _valid_jwt_header(value: str) -> bool:
    try:
        header = value.split(".", 1)[0]
        padded = header + "=" * (-len(header) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode()).decode(errors="ignore")
    except Exception:
        return False
    return decoded.strip().startswith("{") and '"alg"' in decoded


def _rough_entropy(value: str) -> float:
    if not value:
        return 0.0
    unique = len(set(value))
    return min(8.0, unique.bit_length() + len(value).bit_length() / 8)
