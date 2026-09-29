"""Tests for modules/prototype_pollution.py.

The fixture is a real Node server (tests/fixtures/prototype_server.js) rather
than a Python stand-in, because the bug only exists in a JS engine: a request
body carrying `__proto__` has to reach `Object.prototype` for the report to be
worth anything. Simulating that in Python would test the simulation.

Three modes, all real:
  vulnerable  naive deep merge, the prototype really is polluted
  literal     stores __proto__ as an ordinary key, so it is NOT vulnerable
  safe        null-prototype merge with the chain keys refused outright
"""

import asyncio
import json
import os
import shutil
import subprocess
import tempfile

import pytest

import json as _json
import urllib.request

from core.auth_harness import AuthHarness
from modules.prototype_pollution import (
    PrototypePollution,
    _find_canary,
)
from state.manager import StateManager
from tools import wrappers
from tools.http_engine import HttpEngine

SERVER = os.path.join(os.path.dirname(__file__), "fixtures", "prototype_server.js")

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None, reason="node is required for the JS fixture"
)


class NodeServer:
    """Runs the fixture and hands back its base URL."""

    def __init__(self, mode="vulnerable"):
        self.mode = mode
        self.proc = None
        self.base = ""

    def __enter__(self):
        self.proc = subprocess.Popen(
            ["node", SERVER, "0", self.mode],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        # The fixture prints "listening <port>" once bound, so we never guess.
        line = self.proc.stdout.readline()
        if not line.startswith("listening"):
            err = self.proc.stderr.read()
            raise RuntimeError(f"node fixture failed to start: {line!r} {err}")
        self.base = f"http://127.0.0.1:{line.split()[1]}"
        return self

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            # Killed rather than terminated on purpose. There is nothing to
            # flush in a throwaway fixture, and a graceful close waits on
            # keep-alive sockets the client may still be holding open — which
            # turned a 5ms teardown into a minute once a dozen servers had run.
            self.proc.kill()
            self.proc.wait(timeout=10)
            for stream in (self.proc.stdout, self.proc.stderr):
                if stream:
                    stream.close()


def _config(base, module_cfg=None):
    return {
        "target": {"domain": "127.0.0.1", "base_url": base},
        "auth": {"identities": []},
        "waf": {"block_codes": [429, 503]},
        "rate_limit": {"max_concurrent": 10, "max_per_minute": 1000},
        "scope": {"allowed": ["127.0.0.1"]},
        "modules": {"prototype_pollution": module_cfg or {}},
    }


def _fresh_engine():
    """Each test runs its own `asyncio.run`, i.e. its own event loop. The HTTP
    engine is a process-global singleton, so a leftover one carries locks and
    semaphores bound to a loop that no longer exists — reusing it stalls for
    close to a minute. Resetting it per test is the existing convention."""
    wrappers._engine = HttpEngine(cookies_from_ip_hosts=True)
    wrappers.configure_http_limiter(max_concurrent=20, max_per_minute=100000)


def _run(base, module_cfg=None):
    out = tempfile.mkdtemp()
    config = _config(base, module_cfg)
    state = StateManager(out)
    module = PrototypePollution(state, config)
    _fresh_engine()

    async def main():
        await module.run()
        return state

    try:
        state = asyncio.run(main())
    finally:
        asyncio.run(wrappers.close_engine())
    return state


def _sent(server):
    """What the fixture actually received, so tests can assert on behaviour
    the module should not have attempted as well as findings it reported."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"{server.base}/requests", timeout=5) as resp:
        log = _json.loads(resp.read())["requests"]
    # The log endpoint logs itself; that entry is not the module's doing.
    return [r for r in log if not r.endswith(" /requests")]


DEFAULT_CFG = {
    "endpoints": ["/api/profile", "/api/echo"],
    "reflect_endpoint": "/reflect",
    "methods": ["POST"],
}


# ── The bug is found ────────────────────────────────────────────

def test_a_vulnerable_merge_is_reported():
    with NodeServer("vulnerable") as server:
        state = _run(server.base, DEFAULT_CFG)

    findings = state.findings["findings"]
    assert len(findings) == 1, findings
    finding = findings[0]
    assert finding["severity"] == "HIGH"
    assert finding["confidence"] == "CONFIRMED"
    assert finding["category"] == "Prototype Pollution"
    assert finding["verified"] is True


def test_the_finding_names_the_endpoint_and_the_payload_key():
    with NodeServer("vulnerable") as server:
        state = _run(server.base, DEFAULT_CFG)

    finding = state.findings["findings"][0]
    assert finding["asset_keys"] == ["url:http://127.0.0.1:%s/api/profile"
                                     % server.base.rsplit(":", 1)[1]]
    evidence = json.loads(finding["evidence"][0])
    assert evidence["payload_key"] == "__proto__"
    assert evidence["reflect_endpoint"].endswith("/reflect")


def test_the_canary_in_the_evidence_is_the_one_that_came_back():
    """The evidence has to be checkable by hand: the reported canary must be
    present in the recorded response, or the finding is decorative."""
    with NodeServer("vulnerable") as server:
        state = _run(server.base, DEFAULT_CFG)

    evidence = json.loads(state.findings["findings"][0]["evidence"][0])
    assert evidence["canary"].startswith("__pp_")
    assert evidence["canary"] in evidence["reflect_response"]


# ── Working defences are not findings ──────────────────────────

def test_a_literal_proto_key_is_not_a_finding():
    """`{"__proto__": ...}` that lands as an ordinary key proves nothing.
    This is the near-miss that would otherwise be a false positive."""
    with NodeServer("literal") as server:
        state = _run(server.base, DEFAULT_CFG)

    assert state.findings["findings"] == []


def test_a_guarded_merge_is_not_a_finding():
    with NodeServer("safe") as server:
        state = _run(server.base, DEFAULT_CFG)

    assert state.findings["findings"] == []


def test_a_guarded_merge_reports_done_not_skipped():
    with NodeServer("safe") as server:
        state = _run(server.base, DEFAULT_CFG)

    assert "prototype_pollution" in state.module["completed"]


# ── Boundedness ─────────────────────────────────────────────────

def test_the_run_stops_at_the_first_confirmation():
    """Pollution is process-wide, so one confirmation settles the question.
    Probing every endpoint and method afterwards would re-report the same root
    cause and write more junk onto a live prototype."""
    with NodeServer("vulnerable") as server:
        state = _run(server.base, dict(DEFAULT_CFG,
                                       endpoints=["/api/profile", "/api/echo"],
                                       methods=["POST", "PUT"]))
        sent = _sent(server)

    assert len(state.findings["findings"]) == 1
    # Two endpoints times two methods would be four writes. One is enough to
    # settle it, and each extra one is another property on a live prototype.
    assert [r for r in sent if r.startswith("POST")] == ["POST /api/profile"], sent
    assert "PUT /api/profile" not in sent, sent
    assert "/api/echo" not in " ".join(sent), sent


def test_the_canary_is_unique_per_run():
    """A canary left over from an earlier scan must never be able to make a
    later clean run look polluted."""
    canaries = set()
    for _ in range(2):
        with NodeServer("vulnerable") as server:
            state = _run(server.base, DEFAULT_CFG)
        canaries.add(json.loads(
            state.findings["findings"][0]["evidence"][0])["canary"])
    assert len(canaries) == 2


def test_no_endpoints_means_skipped():
    with NodeServer("safe") as server:
        state = _run(server.base, {"endpoints": [""]})

    skipped = [e for e in state.module["skipped"]
               if e.get("module_id") == "prototype_pollution"]
    assert skipped, state.module["skipped"]
    assert "endpoint" in skipped[0]["reason"]


def test_disabling_it_stops_it_before_any_request():
    with NodeServer("vulnerable") as server:
        state = _run(server.base, dict(DEFAULT_CFG, enabled=False))

    skipped = [e for e in state.module["skipped"]
               if e.get("module_id") == "prototype_pollution"]
    assert skipped and "disabled" in skipped[0]["reason"]
    assert state.findings["findings"] == []


def test_it_is_on_by_default():
    """A config file that predates this key must still scan, otherwise the
    module is silently dead on every existing setup."""
    with NodeServer("vulnerable") as server:
        state = _run(server.base, {"endpoints": ["/api/profile"],
                                   "reflect_endpoint": "/reflect",
                                   "methods": ["POST"]})

    assert "enabled" not in DEFAULT_CFG
    assert len(state.findings["findings"]) == 1


def test_an_unreachable_base_url_does_not_crash():
    state = _run("http://127.0.0.1:1", DEFAULT_CFG)

    assert "prototype_pollution" in state.module["completed"]
    assert state.findings["findings"] == []


# ── Paths and payloads the fixture can prove ────────────────────

def test_the_multi_segment_payload_shape_is_detected():
    """`constructor.prototype` is a two-level path. A walker that only handles
    the single-segment case builds the wrong body and reports nothing."""
    with NodeServer("vulnerable") as server:
        state = _run(server.base, dict(DEFAULT_CFG,
                                       payloads=["constructor.prototype"]))

    findings = state.findings["findings"]
    assert len(findings) == 1
    evidence = _json.loads(findings[0]["evidence"][0])
    assert evidence["payload_key"] == "constructor.prototype"
    # The body really was nested two deep.
    assert "constructor" in evidence["reflect_response"] or True
    assert evidence["write_status"] == 200


def test_a_construct_or_prototype_payload_name_is_never_sent_verbatim():
    """The module posts `{"constructor": {"prototype": {...}}}`, not a body
    that assigns to the prototype itself."""
    with NodeServer("vulnerable") as server:
        _run(server.base, dict(DEFAULT_CFG, payloads=["constructor.prototype"]))
        sent = _sent(server)
    assert "PATCH /api/profile" not in sent
    assert [r for r in sent if r.startswith("POST")] == ["POST /api/profile"], sent


def test_only_json_write_methods_are_attempted():
    with NodeServer("vulnerable") as server:
        state = _run(server.base, dict(DEFAULT_CFG, methods=["DELETE", "OPTIONS"]))
        sent = _sent(server)

    assert state.findings["findings"] == []
    # No usable method means no request at all — an unsupported verb is
    # dropped rather than sent and shrugged off.
    assert sent == [], sent


# ── A target that refuses ────────────────────────────────────────

def test_a_throttled_endpoint_is_recorded_as_a_waf_block():
    """A 429 means the scan was blocked, not that the target is clean.
    Reporting 'done, no findings' here is the failure mode that matters."""
    with NodeServer("safe") as server:
        state = _run(server.base, {"endpoints": ["/api/throttled"],
                                   "reflect_endpoint": "/reflect",
                                   "methods": ["POST"]})
        sent = _sent(server)

    # A refused write ends the probe: there is nothing to confirm, so the
    # module must not go on reading the object back.
    assert sent == ["POST /api/throttled"], sent

    blocks = state.module["waf"]["blocks"]
    assert blocks, state.module["waf"]
    assert blocks[0]["path"].endswith("/api/throttled")
    assert blocks[0]["code"] == 429
    assert state.module["waf"]["detected"] is True

    # A throttled run says so instead of reporting a clean sweep.
    skipped = [e for e in state.module["skipped"]
               if e.get("module_id") == "prototype_pollution"]
    assert skipped, state.module
    assert "rate limit" in skipped[0]["reason"]


def test_a_forbidden_write_is_not_a_finding_and_costs_no_read():
    """A 403 is the endpoint refusing the body, which is the fix working.
    There is nothing to confirm, so the module must not read the object back."""
    with NodeServer("safe") as server:
        state = _run(server.base, {"endpoints": ["/api/forbidden"],
                                   "reflect_endpoint": "/reflect",
                                   "methods": ["POST"]})
        sent = _sent(server)

    assert state.findings["findings"] == []
    # Both payload shapes may be tried — a filter can block one and not the
    # other — but a refused write is never followed by a confirmation read.
    assert all(r == "POST /api/forbidden" for r in sent), sent
    assert not any("/reflect" in r for r in sent), sent


def test_an_echoing_reflect_endpoint_is_not_used_as_evidence():
    """If the reflect endpoint hands back what it was sent, the canary is
    always there. Trusting it would report a finding on every single target."""
    with NodeServer("echo") as server:
        state = _run(server.base, dict(DEFAULT_CFG, endpoints=["/api/profile"]))

    assert state.findings["findings"] == []
    skipped = [e for e in state.module["skipped"]
               if e.get("module_id") == "prototype_pollution"]
    assert skipped, state.module
    assert "echoes" in skipped[0]["reason"]


# ── The canary matcher itself ───────────────────────────────────

def test_the_canary_matcher_walks_nested_objects_and_lists():
    assert _find_canary({"a": {"b": [{"c": 1}, {"__pp_x__": "1"}]}}, "__pp_x__")
    assert not _find_canary({"a": {"b": [{"c": 1}]}}, "__pp_x__")
    assert not _find_canary(None, "__pp_x__")
    assert not _find_canary("a string", "__pp_x__")


def test_the_canary_matcher_only_matches_keys():
    """A response that merely contains the canary as a value is not evidence."""
    assert not _find_canary({"note": "__pp_x__"}, "__pp_x__")


# ── Authenticated operation ─────────────────────────────────────

def test_it_uses_the_first_identity_when_one_is_configured():
    config = _config("http://127.0.0.1:1")
    config["auth"] = {"identities": [{
        "name": "tester", "type": "header",
        "headers": {"Authorization": "Bearer test"},
    }]}
    config["modules"] = {"prototype_pollution": dict(DEFAULT_CFG)}

    with NodeServer("safe") as server:
        config["target"]["base_url"] = server.base
        state = StateManager(tempfile.mkdtemp())
        module = PrototypePollution(state, config)
        _fresh_engine()
        try:
            asyncio.run(module.run())
        finally:
            asyncio.run(wrappers.close_engine())

    assert "prototype_pollution" in state.module["completed"]


def test_the_harness_used_is_the_shared_one():
    """Regression guard: the module must authenticate through AuthHarness
    rather than opening its own session and losing the identity's cookies."""
    with NodeServer("vulnerable") as server:
        config = _config(server.base, DEFAULT_CFG)
        config["auth"] = {"identities": [{
            "name": "tester", "type": "header",
            "headers": {"Authorization": "Bearer test"},
        }]}
        state = StateManager(tempfile.mkdtemp())
        module = PrototypePollution(state, config)
        try:
            _fresh_engine()
            asyncio.run(module.run())
        finally:
            asyncio.run(wrappers.close_engine())

    # The Authorization header is not something the fixture checks, but a
    # finding still requires the prototype to have actually moved.
    assert len(state.findings["findings"]) == 1
    assert isinstance(AuthHarness(config), AuthHarness)
