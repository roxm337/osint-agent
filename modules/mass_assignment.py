"""Stage 5: Mass assignment / over-posting on the attacker's own account.

An API that binds whatever the client sends lets a user set fields the UI never
exposes: `role=admin`, `is_verified=true`, `credits=999999`. The interesting
property is that it needs only *one* identity, because the test writes to the
attacker's own record. That is also the safety property: this module never
touches anybody else's object, so it cannot become an IDOR by accident.

Two things keep it honest:

- It only counts a field the server *echoes back* changed. An endpoint that
  silently drops unknown keys is the common case and must stay silent.
- It restores every value it changes and verifies the restore, so a probe
  cannot leave the operator's test account elevated.
"""

import json

from core.auth_harness import AuthHarness, Identity
from modules.base import BaseModule


# Fields a client has no business setting on itself. Split by what an accepted
# write actually means, because "I can set my own nickname" and "I can make
# myself an admin" are not the same report.
PRIVILEGE_FIELDS = {
    "admin": True, "is_admin": True, "role": True, "roles": True,
    "is_staff": True, "staff": True, "superuser": True, "is_superuser": True,
    "permissions": True, "is_verified": True,
    "verified": True, "email_verified": True, "account_type": True,
    "plan": True, "subscription": True, "tier": True, "is_premium": True,
    "premium": True, "credits": True, "balance": True, "quota": True,
    "limit": True, "seats": True, "discount": True, "price_cents": True,
    "owner_id": True, "user_id": True, "tenant_id": True, "org_id": True,
    "account_id": True, "group_id": True,
}

# Sentinels per JSON type. Each is chosen to be obviously synthetic so that a
# response echoing it back cannot be mistaken for real data.
PROBE_VALUES = {
    "bool": True,
    "int": 987654321,
    "string": "ma-probe-8f21c4",
}

# What gets written back afterwards. An endpoint that was willing to bind an
# arbitrary field is, almost by definition, doing a partial update, so simply
# omitting the key leaves the probe in place — the rollback has to name the
# field and ask for it to be reset.
NEUTRAL_VALUES = {
    "bool": False,
    "int": 0,
    "string": "",
}

SELF_PATHS = (
    "/api/me", "/api/user", "/api/profile", "/api/account",
    "/api/v1/me", "/api/v1/user", "/api/v1/profile",
    "/api/users/me", "/api/self", "/me", "/profile",
)


class MassAssignment(BaseModule):
    id = "mass_assignment"
    name = "Mass Assignment"
    stage = 5
    detectability = "medium"
    depends_on = ["idor_differ"]
    active = True

    async def run(self) -> str:
        cfg = self._cfg()
        if not cfg.get("enabled"):
            self.state.skip_module(
                self.id,
                "disabled — it writes to the configured account; set "
                "modules.mass_assignment.enabled: true to run",
            )
            return "skipped"

        harness = AuthHarness(self.config)
        identities = await harness.establish_all(self._base_url())
        if not identities:
            self.state.skip_module(self.id, "no verified identity to test with")
            return "skipped"

        attacker = identities[0]
        target = await self._self_endpoint(harness, attacker, cfg)
        if not target:
            self.state.skip_module(
                self.id,
                "no readable self-object endpoint (set modules.mass_assignment.endpoints)",
            )
            return "skipped"

        before = await self._get_json(harness, attacker.name, target)
        if not isinstance(before, dict):
            self.state.skip_module(self.id, f"self endpoint is not JSON: {target}")
            return "skipped"

        # Absolutised like the read target: a configured "write_endpoint" is
        # almost always written the way recon reports it, i.e. as a path, and a
        # relative path handed straight to the HTTP client resolves to nothing.
        write_url = self._absolute(str(cfg.get("write_endpoint") or target)) \
            or target
        method = str(cfg.get("method") or "PATCH").upper()
        if method not in ("PATCH", "PUT", "POST"):
            self.state.skip_module(self.id, f"unsupported method: {method}")
            return "skipped"

        findings = await self._probe_fields(
            harness, attacker, target, write_url, before, cfg, method,
        )
        for finding in findings:
            self.state.add_finding(**finding)

        self.state.complete_module(self.id)
        self.log(f"mass assignment: {len(findings)} writable field(s)")
        return "done"

    # ── Discovery ────────────────────────────────────────────────

    async def _self_endpoint(self, harness: AuthHarness, attacker: Identity,
                             cfg: dict) -> str:
        """The URL that returns the attacker's own record.

        A configured object URL is preferred: recon already knows it, and it
        doubles as the write target. Otherwise fall back to the usual `/me`
        shapes, which are cheap and get the baseline but are often read-only.
        """
        for candidate in cfg.get("endpoints") or []:
            url = self._absolute(str(candidate))
            if url:
                return url
        for path in SELF_PATHS:
            url = self._absolute(path)
            if not url:
                continue
            result = await self._get(harness, attacker.name, url)
            if result.get("status") == 200 and result.get("body"):
                return url
        return ""

    # ── Probing ──────────────────────────────────────────────────

    async def _probe_fields(self, harness: AuthHarness, attacker: Identity,
                            target: str, write_url: str, before: dict,
                            cfg: dict, method: str) -> list:
        findings = []
        candidates = self._candidates(before, cfg)
        for field in candidates:
            outcome = await self._probe_field(
                harness, attacker, target, write_url, before, field,
                cfg, method,
            )
            if outcome:
                findings.append(outcome)
        return findings

    def _candidates(self, before: dict, cfg: dict) -> list:
        """Fields worth trying, worst first.

        Anything the account can already see is skipped: `name` on a user
        object is not a finding, and re-setting it proves nothing.
        """
        configured = cfg.get("fields")
        fields = list(configured) if configured else list(PRIVILEGE_FIELDS)
        return [f for f in fields if f and f not in before]

    async def _probe_field(self, harness: AuthHarness, attacker: Identity,
                           target: str, write_url: str, before: dict,
                           field: str, cfg: dict, method: str):
        """Set one field, see whether it sticks, then put it back."""
        probe = PROBE_VALUES[str(cfg.get("probe_type") or "bool")]
        payload = dict(before)
        payload[field] = probe

        write = await self._write(harness, attacker.name, write_url,
                                  payload, method)
        if write.get("status", 0) >= 400:
            return None

        after = await self._get_json(harness, attacker.name, target)
        if not isinstance(after, dict) or after.get(field) != probe:
            # The server accepted the request but did not keep the value. That
            # is a working whitelist, not a finding.
            await self._restore(harness, attacker.name, write_url, after,
                                method, field, probe)
            return None

        restored = await self._restore(harness, attacker.name, write_url,
                                       after, method, field, probe)
        return self._finding(field, probe, before, after, restored, write_url,
                             method, target)

    async def _restore(self, harness: AuthHarness, identity_name: str,
                       write_url: str, current: dict, method: str,
                       field: str = "", probe=None):
        """Write the record back to a neutral value and confirm the probe is gone.

        `current` is the record as it stands *after* the probe, so the probe
        value is still in it. Writing that back verbatim would re-apply the very
        field this is undoing, and omitting the key does nothing at all against a
        partial update. So the field is named explicitly and set to its neutral
        value, and the result is re-read to check the sentinel is gone rather
        than assumed gone.
        """
        probe_type = str(self._cfg().get("probe_type") or "bool")
        payload = dict(current)
        if field:
            payload[field] = NEUTRAL_VALUES[probe_type]
        result = await self._write(harness, identity_name, write_url,
                                   payload, method)
        verified = await self._get_json(harness, identity_name, write_url)
        ok = isinstance(verified, dict)
        if ok and probe is not None:
            ok = verified.get(field) != probe
        return {
            "ok": ok,
            "field": field,
            "status": result.get("status", 0),
            "neutral_value": NEUTRAL_VALUES[probe_type] if field else None,
            "now": (verified or {}).get(field, "<absent>"),
        }

    def _finding(self, field: str, probe, before: dict, after: dict,
                 restored: dict, write_url: str, method: str,
                 target: str) -> dict:
        elevated = field in PRIVILEGE_FIELDS
        title = (f"Mass assignment: {field} is writable on the caller's own "
                 f"account ({write_url})")
        description = (
            f"The endpoint binds client-supplied fields without checking whether "
            f"the caller may set them. Sending {method} to {write_url} with "
            f"{field}={probe!r} changed the stored record: the value was absent "
            f"before the request and is now returned by {target}."
        )
        if not restored.get("ok"):
            description += (
                " The original value could NOT be restored automatically, so the "
                f"{field} field still needs a manual rollback."
            )
        elif restored.get("now") is not None:
            description += (
                f" The probe value was reset to {restored['now']!r}; the field may "
                "now exist on the account where it did not before."
            )
        return {
            "title": title,
            "severity": "CRITICAL" if elevated else "HIGH",
            "confidence": "CONFIRMED",
            "category": "Mass Assignment",
            "description": description,
            "evidence": [json.dumps({
                "endpoint": write_url,
                "method": method,
                "field": field,
                "probe_value": probe,
                "before": before.get(field, "<absent>"),
                "after": after.get(field),
                "restored": restored,
            })],
            "asset_keys": [f"url:{write_url}"],
            "remediation": (
                "Build the update payload from an explicit allowlist of the "
                "fields the caller is permitted to change, rather than binding "
                "the request body. Authorise every field, not just the resource."
            ),
            "verified": True,
        }

    # ── Plumbing ─────────────────────────────────────────────────

    def _base_url(self) -> str:
        return str(self.target.get("base_url")
                   or (f"https://{self.domain}" if self.domain else ""))

    def _absolute(self, path: str) -> str:
        path = (path or "").strip()
        if not path:
            return ""
        if path.startswith(("http://", "https://")):
            return path
        base = self._base_url().rstrip("/")
        return f"{base}/{path.lstrip('/')}" if base else ""

    async def _get(self, harness: AuthHarness, identity_name: str, url: str) -> dict:
        result = await harness.request(identity_name, url, method="GET")
        if result.get("status", 0) in self._waf_codes():
            self.state.record_waf_block(url, result.get("status", 0))
        return result

    async def _get_json(self, harness: AuthHarness, identity_name: str,
                        url: str):
        result = await self._get(harness, identity_name, url)
        if result.get("status", 0) != 200 or not result.get("body"):
            return None
        try:
            return json.loads(result["body"])
        except (TypeError, ValueError):
            return None

    async def _write(self, harness: AuthHarness, identity_name: str, url: str,
                     payload: dict, method: str) -> dict:
        result = await harness.request(
            identity_name, url, method=method,
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
        )
        if result.get("status", 0) in self._waf_codes():
            self.state.record_waf_block(url, result.get("status", 0))
        return result

    def _waf_codes(self) -> set:
        codes = (self.waf_config or {}).get("block_codes") or [429, 503]
        return set(codes) if isinstance(codes, (list, tuple, set)) else {429, 503}

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}
