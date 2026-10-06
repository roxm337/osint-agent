"""Stage 5: API response-key audit — excessive data exposure.

Endpoints that return password hashes, tokens, or secrets inside
otherwise-normal JSON are not misconfigured and not injectable: they
are over-exposed by design, and no payload fuzzer flags them because
nothing looks "wrong" in the status line. This module GETs discovered
JSON endpoints unauthenticated (plus once per captured identity) and
grades the KEYS of what comes back: a `password` field next to the
user object is the Password Hash Leak class, and it is HIGH the moment
it is observed, not after exploitation.
"""

import json as _json

from core.validators import (
    redact_secret,
    RESPONSE_SENSITIVE_KEYS as _SENSITIVE_KEYS,
    looks_real_value as _looks_real,
    walk_json as _walk,
)
from modules.base import BaseModule
from tools.wrappers import curl


class ResponseAudit(BaseModule):
    id = "response_audit"
    name = "API Response Key Audit"
    stage = 5
    detectability = "low"
    depends_on = ["parameter_discovery"]
    active = True

    async def run(self) -> str:
        targets = self._targets()
        if not targets:
            self.state.skip_module(self.id, "no JSON endpoints discovered")
            return "skipped"

        identities = self._identity_tokens()
        reported = 0
        for url in targets[:40]:
            finding = await self._audit_url(url, None)
            if finding:
                reported += 1
                continue
            # Unauthenticated silence is not proof of safety: the same
            # shape behind a session may over-share.
            for label, token in identities[:3]:
                finding = await self._audit_url(url, token)
                if finding:
                    reported += 1
                    break

        self.state.complete_module(self.id)
        self.log(f"Response audit: {reported} over-sharing endpoint(s)")
        return "done"

    def _targets(self) -> list:
        targets = []
        for asset in self.state.get_assets_by_type("api_endpoint"):
            value = str(asset.get("value", "") or "").strip()
            if value.startswith(("http://", "https://")) \
                    and value not in targets:
                targets.append(value)
        for asset in self.state.get_assets_by_type("endpoint"):
            value = str(asset.get("value", "") or "").strip()
            if value.startswith(("http://", "https://")) \
                    and value not in targets \
                    and "{id}" not in value:
                targets.append(value)
        return targets

    def _identity_tokens(self) -> list:
        tokens = []
        for asset in self.state.get_assets_by_type("identity_credential"):
            attrs = asset.get("attrs", {}) or {}
            token = str(attrs.get("token", "") or "")
            if token and not token.startswith("cookie:"):
                tokens.append((str(asset.get("value", "")), token))
        return tokens

    async def _audit_url(self, url: str, token: str | None) -> bool:
        headers = {"Authorization": f"Bearer {token}"} if token else None
        try:
            result = await curl(url, headers=headers, output="body",
                                timeout=15)
        except Exception:
            return False
        if result.get("status", 0) not in (200, 201):
            return False
        try:
            data = _json.loads(result.get("body", "") or "")
        except (ValueError, TypeError):
            return False
        hits = []
        for _path, key, value in _walk(data):
            severity = _SENSITIVE_KEYS.get(str(key).lower())
            if not severity or not isinstance(value, (str, int)):
                continue
            if _looks_real(value):
                hits.append((severity, key, value))
        if not hits:
            return False
        worst = max(hits, key=lambda hit: _rank(hit[0]))
        top_severity = worst[0]
        self.state.add_finding(
            title=f"Sensitive Keys in API Response: {url}",
            severity=top_severity,
            confidence="CONFIRMED",
            category="Sensitive Data Exposure",
            description=(
                f"GET {url} returns {len(hits)} sensitive field(s) "
                f"({', '.join(sorted({k for _, k, _ in hits}))}) with "
                f"real-shaped values"
                f"{' (authenticated session)' if token else ''}. "
                f"Clients receive more than they need."),
            evidence=[
                f"{key}: {redact_secret(value)}"
                for _, key, value in hits[:10]
            ] + [f"URL: {url}"],
            remediation="Strip sensitive fields from API responses; project "
                        "only the fields each client needs.",
            asset_keys=[f"url:{url}"],
            verified=True,
            verification={"method": "sensitive_response_keys",
                          "url": url},
        )
        return True


def _rank(severity: str) -> int:
    return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3,
            "CRITICAL": 4}.get(severity, 0)
