"""Tests for modules/cors_audit.py.

The fixture is a local CORS server with one endpoint per policy under test.
Exploitability is a property of three headers, so each mode below is a real
policy a real framework emits — the point is that the module grades the
difference between them rather than reporting every permissive header as
MEDIUM.
"""

import asyncio
import json
import tempfile

import pytest
from aiohttp import web

from core.auth_harness import AuthHarness
from modules.cors_audit import ATTACKER_ORIGIN, CORSAudit
from state.manager import StateManager
from tools import wrappers
from tools.http_engine import HttpEngine

SECRET = {"email": "victim@example.test", "balance": 90210,
          "session_token": "abc123"}


class CORSServer:
    """Serves /api/<mode> with a distinct CORS policy per mode."""

    def __init__(self, policy):
        self.policy = policy
        self.seen_origins = []
        self.runner = None
        self.base = ""

    async def __aenter__(self):
        app = web.Application(client_max_size=1 << 20)
        app.router.add_get("/api/{mode}", self._handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.base = f"http://127.0.0.1:{self.runner.addresses[0][1]}"
        return self

    async def __aexit__(self, *exc):
        await self.runner.cleanup()

    async def _handle(self, request):
        mode = request.match_info["mode"]
        origin = request.headers.get("Origin", "")
        self.seen_origins.append(origin)
        headers = {}

        if mode == "reflect_credentials":
            # The vulnerable one: whatever origin arrives is trusted.
            headers["Access-Control-Allow-Origin"] = origin or "*"
            headers["Access-Control-Allow-Credentials"] = "true"
            headers["Vary"] = "Origin"
        elif mode == "reflect_upper":
            # Some frameworks normalise the origin before echoing it.
            headers["Access-Control-Allow-Origin"] = (origin or "*").upper()
            headers["Access-Control-Allow-Credentials"] = "TRUE"
            headers["Vary"] = "Origin"
        elif mode == "reflect_no_vary":
            headers["Access-Control-Allow-Origin"] = origin or "*"
            headers["Access-Control-Allow-Credentials"] = "true"
        elif mode == "null_origin":
            headers["Access-Control-Allow-Origin"] = "null"
            headers["Access-Control-Allow-Credentials"] = "true"
        elif mode == "wildcard_credentials":
            # Browsers reject this pairing, so it is not a session theft.
            headers["Access-Control-Allow-Origin"] = "*"
            headers["Access-Control-Allow-Credentials"] = "true"
        elif mode == "reflect_public":
            headers["Access-Control-Allow-Origin"] = origin or "*"
            headers["Vary"] = "Origin"
        elif mode == "public_wildcard":
            headers["Access-Control-Allow-Origin"] = "*"
        elif mode == "allowlist":
            if origin == "https://app.example.test":
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
                headers["Vary"] = "Origin"
        elif mode == "no_cors":
            pass
        elif mode == "not_found":
            return web.json_response({"error": "nope"}, status=404,
                                     headers=headers)

        return web.json_response(SECRET, headers=headers)


def _fresh_engine():
    """Each test gets its own event loop, so the process-global HTTP engine
    has to be rebuilt rather than reused across loops."""
    wrappers._engine = HttpEngine(cookies_from_ip_hosts=True)
    wrappers.configure_http_limiter(max_concurrent=20, max_per_minute=100000)


def _run(policy, module_cfg=None, identity=None):
    out = tempfile.mkdtemp()
    config = {
        "target": {"domain": "127.0.0.1", "base_url": ""},
        "auth": {"identities": [identity] if identity else []},
        "waf": {"block_codes": [429, 503]},
        "rate_limit": {"max_concurrent": 10, "max_per_minute": 1000},
        "scope": {"allowed": ["127.0.0.1"]},
        "modules": {"cors_audit": dict(module_cfg or {})},
    }
    state = StateManager(out)

    async def main():
        async with CORSServer(policy) as server:
            config["target"]["base_url"] = server.base
            module = CORSAudit(state, config)
            _fresh_engine()
            await module.run()
            return server

    try:
        return asyncio.run(main()), state
    finally:
        asyncio.run(wrappers.close_engine())


# ── The exploitable case ────────────────────────────────────────

def test_reflected_credentials_is_a_confirmed_high():
    _, state = _run("reflect_credentials", {"endpoints": ["/api/reflect_credentials"]})
    findings = state.findings["findings"]

    assert len(findings) == 1, findings
    finding = findings[0]
    assert finding["severity"] == "HIGH"
    assert finding["confidence"] == "CONFIRMED"
    assert finding["category"] == "CORS Misconfiguration"
    assert finding["asset_keys"][0].endswith("/api/reflect_credentials")


def test_the_evidence_contains_both_headers_that_make_it_exploitable():
    _, state = _run("reflect_credentials", {"endpoints": ["/api/reflect_credentials"]})
    evidence = json.loads(state.findings["findings"][0]["evidence"][0])

    assert evidence["allow_origin"] == ATTACKER_ORIGIN
    assert evidence["allow_credentials"] is True
    assert evidence["status"] == 200
    assert evidence["probe_origin"] == ATTACKER_ORIGIN
    # The body has to be worth stealing, otherwise the finding is theatre.
    assert evidence["body_bytes"] > 0


def test_a_reflected_origin_is_sent_verbatim_so_the_check_is_replayable():
    server, _ = _run("reflect_credentials", {"endpoints": ["/api/reflect_credentials"]})
    assert ATTACKER_ORIGIN in server.seen_origins


# ── Grades that must not be rounded up ──────────────────────────

def test_wildcard_with_credentials_is_not_called_a_high():
    """Browsers reject `*` plus credentials. Reporting it as session theft
    would be the single easiest way to lose a triager's trust."""
    _, state = _run("wildcard_credentials",
                    {"endpoints": ["/api/wildcard_credentials"]})
    findings = state.findings["findings"]

    assert len(findings) == 1
    assert findings[0]["severity"] == "LOW", findings[0]["severity"]
    assert "not exploitable" in findings[0]["description"]


def test_a_wildcard_response_is_never_nagged_about_caches():
    """A constant `Access-Control-Allow-Origin: *` has nothing to vary, so a
    cache warning here would be advice the reporter does not believe. Pinning
    this keeps the missing-Vary note attached to echoed origins only."""
    _, state = _run("wildcard_credentials",
                    {"endpoints": ["/api/wildcard_credentials"]})
    description = state.findings["findings"][0]["description"]

    assert "Vary" not in description, description
    assert "cache" not in description.lower(), description


def test_reflection_without_credentials_is_only_informational():
    _, state = _run("reflect_public", {"endpoints": ["/api/reflect_public"]})
    findings = state.findings["findings"]

    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"


def test_a_null_origin_with_credentials_is_high():
    _, state = _run("null_origin", {"endpoints": ["/api/null_origin"]})
    findings = state.findings["findings"]

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "null origin" in findings[0]["title"].lower()


# ── Not findings ────────────────────────────────────────────────

def test_a_correct_allowlist_is_not_a_finding():
    _, state = _run("allowlist", {"endpoints": ["/api/allowlist"]})
    assert state.findings["findings"] == []


def test_no_cors_headers_is_not_a_finding():
    _, state = _run("no_cors", {"endpoints": ["/api/no_cors"]})
    assert state.findings["findings"] == []


def test_a_public_wildcard_without_credentials_is_not_a_finding():
    """`Access-Control-Allow-Origin: *` with no credentials is the default
    posture of most public APIs. Reporting it is noise."""
    _, state = _run("public_wildcard", {"endpoints": ["/api/public_wildcard"]})
    assert state.findings["findings"] == []


# ── Cache behaviour ─────────────────────────────────────────────

def test_a_missing_vary_origin_is_called_out_on_a_reflected_response():
    _, state = _run("reflect_no_vary", {"endpoints": ["/api/reflect_no_vary"]})
    description = state.findings["findings"][0]["description"]

    assert "Vary: Origin" in description
    assert "cache" in description.lower()


def test_vary_origin_is_not_mentioned_when_the_server_sets_it():
    _, state = _run("reflect_credentials",
                    {"endpoints": ["/api/reflect_credentials"]})
    assert "Vary" not in state.findings["findings"][0]["description"]


# ── Bookkeeping ─────────────────────────────────────────────────

def test_a_normalised_origin_and_TRUE_credentials_still_count():
    """Origin and credentials are compared case-insensitively. A server that
    answers `TRUE` and an uppercased origin has granted exactly as much as one
    that answers `true` in lower case."""
    _, state = _run("reflect_upper", {"endpoints": ["/api/reflect_upper"]})
    findings = state.findings["findings"]

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH", findings[0]
    evidence = json.loads(findings[0]["evidence"][0])
    assert evidence["allow_credentials"] is True
    assert evidence["allow_origin"] == ATTACKER_ORIGIN.upper()


def test_a_throttled_endpoint_is_recorded_rather_than_graded():
    _, state = _run("reflect_credentials", {"endpoints": ["/api/does_not_exist"]})
    # Nothing permissive came back, and the module still finished cleanly.
    assert state.findings["findings"] == []
    assert "cors_audit" in state.module["completed"]


def test_disabled_means_no_request():
    server, state = _run("reflect_credentials",
                         {"endpoints": ["/api/reflect_credentials"],
                          "enabled": False})

    assert state.findings["findings"] == []
    assert server.seen_origins == []
    skipped = [e for e in state.module["skipped"]
               if e.get("module_id") == "cors_audit"]
    assert skipped and "disabled" in skipped[0]["reason"]


def test_no_usable_endpoint_is_skipped():
    _, state = _run("reflect_credentials", {"endpoints": ["", "   "]})
    skipped = [e for e in state.module["skipped"]
               if e.get("module_id") == "cors_audit"]
    assert skipped, state.module
    assert "endpoint" in skipped[0]["reason"]


def test_no_base_url_is_skipped():
    """The reason has to name the base URL, not fall through to the endpoint
    check and blame the wrong thing."""
    config = {
        "target": {"domain": "", "base_url": ""},
        "auth": {"identities": []},
        "waf": {"block_codes": [429]},
        "modules": {"cors_audit": {}},
    }
    state = StateManager(tempfile.mkdtemp())
    module = CORSAudit(state, config)
    assert asyncio.run(module.run()) == "skipped"
    skipped = [e for e in state.module["skipped"]
               if e.get("module_id") == "cors_audit"]
    assert "base URL" in skipped[0]["reason"], skipped[0]


def test_no_base_url_is_skipped_again():
    config = {
        "target": {"domain": "", "base_url": ""},
        "auth": {"identities": []},
        "waf": {"block_codes": [429]},
        "modules": {"cors_audit": {}},
    }
    state = StateManager(tempfile.mkdtemp())
    module = CORSAudit(state, config)
    assert asyncio.run(module.run()) == "skipped"


def test_the_probe_uses_the_first_identity_when_configured():
    identity = {
        "name": "tester", "type": "header",
        "headers": {"Authorization": "Bearer test"},
    }
    server, state = _run("reflect_credentials",
                         {"endpoints": ["/api/reflect_credentials"]},
                         identity=identity)

    assert len(state.findings["findings"]) == 1
    assert ATTACKER_ORIGIN in server.seen_origins
    assert isinstance(AuthHarness({"auth": {"identities": [identity]}}),
                      AuthHarness)


@pytest.mark.parametrize("mode,expected", [
    ("reflect_credentials", "HIGH"),
    ("null_origin", "HIGH"),
    ("wildcard_credentials", "LOW"),
    ("reflect_public", "INFO"),
])
def test_each_policy_gets_its_own_grade(mode, expected):
    _, state = _run(mode, {"endpoints": [f"/api/{mode}"]})
    assert state.findings["findings"][0]["severity"] == expected
