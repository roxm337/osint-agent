"""Tests for modules/mass_assignment.py.

The module writes to the operator's own test account, so two things have to be
proven rather than assumed: a field is only reported when the server actually
stores it, and every probe is undone. A test account left with `role=admin`
because the restore silently failed would be worse than no module at all.
"""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

import pytest
from aiohttp import web

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.wrappers as wrappers
from modules.mass_assignment import PRIVILEGE_FIELDS, MassAssignment
from state.manager import StateManager
from tools.http_engine import HttpEngine


# ── Test application ──────────────────────────────────────────────


class ProfileApp:
    """A user object that either honours or ignores extra fields.

    `writable` is the set of fields the server binds from the request body.
    Anything outside it is accepted with a 200 and dropped, which is what a
    correct API does and must never produce a finding.

    `sticky` simulates a server that will not give a value back: omitting a
    field from a later payload leaves the previous one in place, so a restore
    cannot succeed no matter what the client sends.
    """

    def __init__(self, writable=frozenset(), sticky=frozenset(),
                 reject_writes=False):
        self.record = {"id": 7, "email": "attacker@example.test",
                       "name": "attacker"}
        self.writable = set(writable)
        self.sticky = set(sticky)
        self.reject_writes = reject_writes
        self._locked = set()
        self.writes = []
        self.requests = []
        self.app = web.Application()
        self.app.router.add_route("*", "/api/users/7", self._profile)
        self.app.router.add_route("*", "/api/me", self._profile)

    async def _profile(self, request):
        self.requests.append(f"{request.method} {request.path}")
        if request.method in ("PATCH", "PUT", "POST"):
            if self.reject_writes:
                return web.json_response({"error": "forbidden"}, status=403)
            try:
                sent = await request.json()
            except (ValueError, TypeError):
                return web.json_response({"error": "bad json"}, status=400)
            if not isinstance(sent, dict):
                return web.json_response({"error": "not an object"}, status=400)
            self.writes.append(sent)
            for key, value in sent.items():
                if key not in self.writable:
                    continue
                if key in self.sticky and key in self._locked:
                    continue  # write-once field: the rollback is refused
                self.record[key] = value
                if key in self.sticky:
                    self._locked.add(key)
        return web.json_response(dict(self.record))


class Env:
    def __init__(self, app, config_extra=None):
        self.runner = web.AppRunner(app.app)
        self.port = None

    async def __aenter__(self):
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.port = self.runner.addresses[0][1]
        self.base = f"http://127.0.0.1:{self.port}"
        return self

    async def __aexit__(self, *exc):
        await wrappers.close_engine()
        await self.runner.cleanup()


def _skip_reason(state):
    for entry in state.module["skipped"]:
        if entry.get("module_id") == "mass_assignment":
            return entry.get("reason", "")
    return ""


def _config(base, module_cfg):
    return {
        "target": {"domain": "127.0.0.1", "base_url": base},
        "paths": {"output_dir": tempfile.mkdtemp()},
        "modules": {"mass_assignment": module_cfg, "record_http_evidence": False},
        "auth": {"identities": {
            "attacker": {"cookies": {"session": "sess_attacker"},
                         "verify_url": f"{base}/api/me",
                         "success_marker": "attacker@example.test"},
        }},
    }


def _run(app, module_cfg):
    async def main():
        async with Env(app) as env:
            state = StateManager(env.base)
            state.add_asset("parameter", "url:x", "q", attrs={"url": env.base})
            config = _config(env.base, module_cfg)
            config["target"]["base_url"] = env.base
            module = MassAssignment(state, config)
            status = await module.run()
            return status, state, module
    wrappers._engine = HttpEngine(cookies_from_ip_hosts=True)
    wrappers.configure_http_limiter(max_concurrent=20, max_per_minute=100000)
    return asyncio.run(main())


# ── The gate ──────────────────────────────────────────────────────


def test_disabled_by_default():
    """It writes to a real account, so consent has to be explicit."""
    status, state, _ = _run(ProfileApp(writable={"role"}), {})

    assert status == "skipped"
    assert state.findings["findings"] == []
    assert "enabled" in _skip_reason(state)


def test_no_identity_means_skip():
    app = ProfileApp(writable={"role"})
    async def main():
        async with Env(app) as env:
            state = StateManager(env.base)
            config = _config(env.base, {"enabled": True})
            config["auth"] = {"identities": {}}
            module = MassAssignment(state, config)
            return await module.run(), state
    wrappers._engine = HttpEngine(cookies_from_ip_hosts=True)
    wrappers.configure_http_limiter(max_concurrent=20, max_per_minute=100000)
    status, state = asyncio.run(main())

    assert status == "skipped"
    assert "identity" in _skip_reason(state)


def test_missing_self_endpoint_is_skipped():
    status, state, _ = _run(ProfileApp(), {"enabled": True,
                                           "endpoints": ["/api/absent"],
                                           "fields": ["role"]})
    assert status == "skipped"
    reason = _skip_reason(state)
    assert "self endpoint" in reason or "self-object" in reason, reason


def test_unsupported_method_is_skipped():
    status, state, _ = _run(ProfileApp(writable={"role"}),
                            {"enabled": True, "method": "DELETE",
                             "endpoints": ["/api/users/7"]})
    assert status == "skipped"
    assert "unsupported method" in _skip_reason(state)


# ── Detection ─────────────────────────────────────────────────────


def test_a_writable_privilege_field_is_critical():
    status, state, _ = _run(ProfileApp(writable={"role"}),
                            {"enabled": True, "endpoints": ["/api/users/7"],
                             "fields": ["role"]})
    findings = state.findings["findings"]

    assert status == "done"
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["confidence"] == "CONFIRMED"
    assert "role" in findings[0]["title"]


def test_a_dropped_field_produces_nothing():
    """200 OK is not proof. The common case is a server that accepts the body
    and throws the unknown field away."""
    status, state, _ = _run(ProfileApp(writable=set()),
                            {"enabled": True, "endpoints": ["/api/users/7"],
                             "fields": ["role", "is_admin"]})

    assert status == "done"
    assert state.findings["findings"] == []


def test_a_field_the_account_already_has_is_not_a_candidate():
    """`email` is legitimately the caller's own field; re-setting it proves
    nothing and would bury the real finding in noise."""
    app = ProfileApp(writable={"name", "role"})
    status, state, _ = _run(app, {"enabled": True,
                                  "endpoints": ["/api/users/7"],
                                  "fields": ["name", "role"]})
    titles = [f["title"] for f in state.findings["findings"]]

    assert all("name" not in t for t in titles), titles
    assert any("role" in t for t in titles), titles


def test_severity_reflects_the_field():
    app = ProfileApp(writable={"role", "nickname"})
    status, state, _ = _run(app, {"enabled": True,
                                  "endpoints": ["/api/users/7"],
                                  "fields": ["role", "nickname"]})
    severities = {f["title"].split()[2]: f["severity"]
                  for f in state.findings["findings"]}

    assert severities["role"] == "CRITICAL"
    assert severities["nickname"] == "HIGH"


def test_the_fixture_reports_a_field_that_binds():
    """Baseline for the tests below: the write path really does reach the
    server, so a silent run elsewhere means a bug rather than a quiet API."""
    app = ProfileApp(writable={"role"})
    status, state, _ = _run(app, {"enabled": True,
                                  "endpoints": ["/api/users/7"],
                                  "fields": ["role"]})

    assert len(state.findings["findings"]) == 1
    # The stored value is the reset, not the probe: the module undoes what it did.
    assert app.writes[0]["role"] is True
    assert app.record["role"] is False


def test_a_rejected_write_is_not_a_finding():
    """A 403 is the authorisation layer working. Turning that into a
    mass-assignment report would be reporting the fix."""
    app = ProfileApp(writable={"role"}, reject_writes=True)
    status, state, _ = _run(app, {"enabled": True,
                                  "endpoints": ["/api/users/7"],
                                  "fields": ["role"]})

    assert status == "done"
    assert state.findings["findings"] == []
    assert app.requests.count("PATCH /api/users/7") == 1, app.requests


def test_a_rejected_write_costs_no_follow_up_requests():
    """Once the server refuses the write there is nothing to confirm, so the
    module must not keep reading the object back."""
    app = ProfileApp(writable={"role"}, reject_writes=True)
    _run(app, {"enabled": True, "endpoints": ["/api/users/7"],
               "fields": ["role", "is_admin", "plan"]})

    assert app.requests.count("GET /api/users/7") == 1, app.requests


# ── Restoring ─────────────────────────────────────────────────────


def test_the_probe_value_is_removed_again():
    """A partial-update endpoint keeps the old value when a key is omitted, so
    the restore has to name the field and reset it, not just drop it."""
    app = ProfileApp(writable={"role"})
    _run(app, {"enabled": True, "endpoints": ["/api/users/7"],
               "fields": ["role"]})

    assert app.record["role"] is not True, app.record
    assert app.record["role"] is False, app.record


def test_the_restore_is_reported_as_done():
    app = ProfileApp(writable={"role"})
    status, state, _ = _run(app, {"enabled": True,
                                  "endpoints": ["/api/users/7"],
                                  "fields": ["role"]})
    payload = json.loads(state.findings["findings"][0]["evidence"][0])

    assert payload["restored"]["ok"] is True
    assert payload["restored"]["field"] == "role"
    assert payload["restored"]["neutral_value"] is False
    assert "could NOT be restored" not in state.findings["findings"][0]["description"]


def test_a_failed_restore_is_called_out_loudly():
    """If the rollback does not take, the operator has to know before they
    hand the account to someone else."""
    app = ProfileApp(writable={"role"}, sticky={"role"})
    status, state, _ = _run(app, {"enabled": True,
                                  "endpoints": ["/api/users/7"],
                                  "fields": ["role"]})
    findings = state.findings["findings"]

    assert findings, "the probe still lands, so this must still be a finding"
    assert "could NOT be restored" in findings[0]["description"]
    assert app.record.get("role") is True


def test_a_failed_restore_is_marked_not_ok_in_the_evidence():
    app = ProfileApp(writable={"role"}, sticky={"role"})
    status, state, _ = _run(app, {"enabled": True,
                                  "endpoints": ["/api/users/7"],
                                  "fields": ["role"]})
    payload = json.loads(state.findings["findings"][0]["evidence"][0])

    assert payload["restored"]["ok"] is False


def test_restore_does_not_reapply_the_probe():
    """The last payload written for a field must be the reset, never a replay
    of the post-probe record — replaying it is how a probe ends up permanent."""
    app = ProfileApp(writable={"role", "credits"})
    _run(app, {"enabled": True, "endpoints": ["/api/users/7"],
               "fields": ["role", "credits"]})

    last = {"role": None, "credits": None}
    probes = set()
    for sent in app.writes:
        for field in last:
            if field in sent:
                last[field] = sent[field]
        probes.add((len(app.writes), frozenset(sent)))
    assert last["role"] is False, app.writes
    assert last["credits"] == 0, app.writes
    assert app.record["role"] is False
    assert app.record["credits"] == 0
    # Each field was probed exactly once and reset exactly once.
    assert len(app.writes) == 4, app.writes


# ── Self endpoint discovery ───────────────────────────────────────


def test_falls_back_to_api_me():
    app = ProfileApp(writable={"role"})
    status, state, _ = _run(app, {"enabled": True, "fields": ["role"]})

    assert len(state.findings["findings"]) == 1
    assert any(r.endswith("/api/me") for r in app.requests), app.requests


def test_a_separate_write_endpoint_is_honoured():
    app = ProfileApp(writable={"role"})
    app.app.router.add_route("*", "/api/elsewhere", app._profile)
    status, state, _ = _run(app, {"enabled": True,
                                  "endpoints": ["/api/users/7"],
                                  "write_endpoint": "/api/elsewhere",
                                  "fields": ["role"]})
    findings = state.findings["findings"]

    assert len(findings) == 1
    assert findings[0]["asset_keys"][0].endswith("/api/elsewhere")
    assert "PATCH /api/elsewhere" in app.requests


@pytest.mark.parametrize("probe_type,sent", [
    ("bool", True),
    ("int", 987654321),
    ("string", "ma-probe-8f21c4"),
])
def test_probe_value_follows_the_configured_type(probe_type, sent):
    app = ProfileApp(writable={"role"}, sticky={"role"})
    _run(app, {"enabled": True, "endpoints": ["/api/users/7"],
               "fields": ["role"], "probe_type": probe_type})

    # The first write carries the probe; the reset follows it.
    assert app.writes[0]["role"] == sent
    assert app.record["role"] == sent


def test_the_default_field_list_is_privilege_fields_only():
    module_fields = set(PRIVILEGE_FIELDS)
    assert "role" in module_fields and "admin" in module_fields
    assert "email" not in module_fields
    assert "name" not in module_fields
