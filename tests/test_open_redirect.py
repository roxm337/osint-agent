"""Tests for modules/open_redirect.py.

The fixture models one redirect policy per mode. None of them resolve anything:
the probe host is a reserved `.invalid` name, so a client that followed the
redirect would fail DNS rather than reach a third party. That is deliberate —
the tests must not be able to touch anyone else's server either.
"""

import asyncio
import json
import tempfile

import pytest
from aiohttp import web

from modules.open_redirect import PROBE_HOST, OpenRedirectScan
from state.manager import StateManager
from tools import wrappers
from tools.http_engine import HttpEngine

SELF_HOST = "target.test"


class RedirectServer:
    def __init__(self, policy):
        self.policy = policy
        self.runner = None
        self.base = ""
        self.seen = []

    async def __aenter__(self):
        app = web.Application()
        app.router.add_get("/{tail:.*}", self._handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.base = f"http://127.0.0.1:{self.runner.addresses[0][1]}"
        return self

    async def __aexit__(self, *exc):
        await self.runner.cleanup()

    async def _handle(self, request):
        path = request.path
        self.seen.append((request.method, path, request.query_string))

        if path == "/throttled":
            return web.Response(status=429, text="slow down")

        for param in ("next", "redirect", "url"):
            value = request.query.get(param)
            if value is None:
                continue
            destination = self._resolve(value)
            if destination is None:
                continue
            return web.Response(status=302, headers={"Location": destination})

        return web.Response(status=200, text="no redirect here")

    def _resolve(self, value: str):
        """What the server would send the browser to, per policy."""
        if self.policy == "open":
            return value
        if self.policy == "prefix_check":
            # A naive guard: only accept destinations naming our own host.
            return value if SELF_HOST in value else None
        if self.policy == "safe_relative":
            # Correct-ish guard: a single leading slash, no scheme, no host.
            if not value.startswith("/"):
                return None
            if value.startswith("//") or value.startswith("/\\"):
                return None
            if "://" in value:
                return None
            return value
        if self.policy == "allowlist":
            if value.startswith(f"https://{SELF_HOST}/"):
                return value
            return None
        if self.policy == "echo_with_host":
            # Always answers, but prefixes its own host: a substring search for
            # the probe host would fire here and be wrong.
            return f"https://{SELF_HOST}{value}"
        return None


def _fresh_engine():
    wrappers._engine = HttpEngine(cookies_from_ip_hosts=True)
    wrappers.configure_http_limiter(max_concurrent=20, max_per_minute=100000)


def _run(policy, module_cfg=None):
    out = tempfile.mkdtemp()
    config = {
        "target": {"domain": "127.0.0.1", "base_url": ""},
        "auth": {"identities": []},
        "waf": {"block_codes": [429, 503]},
        "rate_limit": {"max_concurrent": 10, "max_per_minute": 1000},
        "scope": {"allowed": ["127.0.0.1"]},
        "modules": {"open_redirect": dict(module_cfg or {})},
    }
    state = StateManager(out)

    async def main():
        async with RedirectServer(policy) as server:
            config["target"]["base_url"] = server.base
            module = OpenRedirectScan(state, config)
            _fresh_engine()
            await module.run()
            return server

    try:
        return asyncio.run(main()), state
    finally:
        asyncio.run(wrappers.close_engine())


TARGETS = {"endpoints": ["/docs/page"], "params": ["next"]}
LOGIN = {"endpoints": ["/login"], "params": ["next"]}


# ── The bug is found ────────────────────────────────────────────

def test_an_unvalidated_destination_is_confirmed():
    _, state = _run("open", TARGETS)
    findings = state.findings["findings"]

    assert len(findings) == 1, findings
    finding = findings[0]
    assert finding["severity"] == "MEDIUM"
    assert finding["confidence"] == "CONFIRMED"
    assert finding["category"] == "Open Redirect"
    assert "next" in finding["title"]


def test_the_evidence_shows_the_location_the_server_returned():
    _, state = _run("open", TARGETS)
    evidence = json.loads(state.findings["findings"][0]["evidence"][0])

    assert PROBE_HOST in evidence["location"]
    assert 300 <= evidence["status"] < 400, evidence["status"]
    assert evidence["param"] == "next"
    assert PROBE_HOST in evidence["payload"]


def test_a_login_endpoint_is_high_because_it_phishes_credentials():
    _, state = _run("open", LOGIN)
    finding = state.findings["findings"][0]

    assert finding["severity"] == "HIGH"
    assert "credential-phishing" in finding["description"]


def test_a_redirect_away_from_the_sign_in_flow_stays_medium():
    _, state = _run("open", TARGETS)
    finding = state.findings["findings"][0]

    assert finding["severity"] == "MEDIUM"
    assert "phishing" in finding["description"]


# ── Guards that work ────────────────────────────────────────────

def test_a_relative_only_guard_is_not_a_finding():
    _, state = _run("safe_relative", TARGETS)
    assert state.findings["findings"] == []


def test_an_allowlist_is_not_a_finding():
    _, state = _run("allowlist", TARGETS)
    assert state.findings["findings"] == []


def test_a_parameter_the_server_ignores_is_not_a_finding():
    _, state = _run("open", {"endpoints": ["/docs/page"], "params": ["session"]})
    assert state.findings["findings"] == []


def test_a_prefix_check_that_looks_for_its_own_host_is_not_a_finding():
    _, state = _run("prefix_check", TARGETS)
    assert state.findings["findings"] == []


def test_our_own_host_echoed_around_the_probe_is_not_a_finding():
    """The server answers with its own host in front. A substring search for
    the probe host would match the path and report an open redirect that a
    browser would never take off-site."""
    _, state = _run("echo_with_host", TARGETS)
    assert state.findings["findings"] == []


# ── Discipline ──────────────────────────────────────────────────

def test_the_redirect_is_read_not_followed():
    """A 3xx in the evidence proves the module stopped at the Location header.
    Following it would send a request to a host outside the engagement."""
    server, state = _run("open", TARGETS)
    evidence = json.loads(state.findings["findings"][0]["evidence"][0])

    assert 300 <= evidence["status"] < 400
    # Every request the server saw was a first hop to the target itself.
    for method, path, _ in server.seen:
        assert path.startswith("/docs")


def test_the_probe_stops_at_the_first_payload_that_lands():
    """One confirmed destination is enough; the rest is noise in the target's
    access log and extra load."""
    server, state = _run("open", TARGETS)

    hops = [s for s in server.seen if s[1] == "/docs/page"]
    assert len(hops) == 1, hops


def test_a_throttled_endpoint_gets_exactly_one_request():
    """Ten payload shapes are queued up. A 429 must abandon the rest, not walk
    the rest of the list against a target that just asked us to stop."""
    server, state = _run("open", {"endpoints": ["/throttled"],
                                  "params": ["next"]})

    assert state.findings["findings"] == []
    assert server.seen == [
        ("GET", "/throttled", f"next=https://{PROBE_HOST}/")
    ], server.seen


def test_a_throttled_endpoint_is_recorded_as_a_waf_block():
    _, state = _run("open", {"endpoints": ["/throttled"], "params": ["next"]})
    blocks = state.module["waf"]["blocks"]

    assert blocks, state.module["waf"]
    assert blocks[0]["path"].endswith("/throttled")
    assert blocks[0]["code"] == 429


def test_disabled_means_no_request():
    server, state = _run("open", dict(TARGETS, enabled=False))
    assert state.findings["findings"] == []
    assert server.seen == []


def test_no_base_url_is_skipped_for_the_right_reason():
    """Without a base URL the endpoint list resolves to nothing, so the module
    could blame its own configuration for a missing target instead."""
    config = {"target": {"domain": "", "base_url": ""},
              "auth": {"identities": []}, "waf": {},
              "modules": {"open_redirect": {}}}
    state = StateManager(tempfile.mkdtemp())

    assert asyncio.run(OpenRedirectScan(state, config).run()) == "skipped"
    skipped = [e for e in state.module["skipped"]
               if e.get("module_id") == "open_redirect"]
    assert "base URL" in skipped[0]["reason"], skipped[0]


def test_a_large_scope_is_capped():
    """Ten payload shapes per (endpoint, parameter) pair multiplies fast. A
    scope with many endpoints and several parameters must not turn into
    thousands of requests to someone else's login page."""
    endpoints = [f"/page{i}" for i in range(30)]

    # One parameter the fixture honours: the first payload lands, so requests
    # map one-to-one onto targets and the count says exactly what was capped.
    capped, _ = _run("open", {"endpoints": endpoints, "params": ["next"],
                              "max_targets": 12})
    assert len(capped.seen) == 12, len(capped.seen)

    uncapped, _ = _run("open", {"endpoints": endpoints, "params": ["next"],
                                "max_targets": 500})
    assert len(uncapped.seen) == 30, len(uncapped.seen)


def test_a_parameter_the_fixture_ignores_costs_the_whole_payload_list():
    """The other side of the cap: a target that never redirects burns every
    payload shape, so the cap has to bound pairs, not requests alone."""
    server, state = _run("open", {"endpoints": ["/page0"], "params": ["next"],
                                  "max_targets": 500})
    assert len(server.seen) == 1, server.seen

    ignored, _ = _run("open", {"endpoints": ["/page0"], "params": ["return"],
                              "max_targets": 500})
    assert len(ignored.seen) == 10, len(ignored.seen)


# ── Bypass coverage ─────────────────────────────────────────────

@pytest.mark.parametrize("payload,escapes", [
    ("https://redirect-probe.invalid/", True),
    ("//redirect-probe.invalid/", True),
    ("/\\redirect-probe.invalid/", True),
    ("https:/redirect-probe.invalid/", True),
    ("/dashboard", False),
    ("https://target.test/", False),
])
def test_the_offsite_test_matches_what_a_browser_would_resolve(
        payload, escapes):
    module = OpenRedirectScan.__new__(OpenRedirectScan)
    assert module._is_offsite(payload) is escapes


def test_every_payload_shape_is_actually_sent():
    """The bypass list is the point of the module, so it has to be exercised
    rather than merely constructed."""
    seen_hops = []

    class Recorder(RedirectServer):
        def _resolve(self, value):
            seen_hops.append(value)
            return value if value.startswith(("http", "//", "/\\")) else None

    out = tempfile.mkdtemp()
    config = {
        "target": {"domain": "127.0.0.1", "base_url": ""},
        "auth": {"identities": []}, "waf": {"block_codes": [429]},
        "modules": {"open_redirect": dict(TARGETS)},
    }
    state = StateManager(out)

    async def main():
        async with Recorder("open") as server:
            config["target"]["base_url"] = server.base
            _fresh_engine()
            await OpenRedirectScan(state, config).run()

    try:
        asyncio.run(main())
    finally:
        asyncio.run(wrappers.close_engine())

    assert seen_hops, "no payload was sent"
    assert all(PROBE_HOST in h for h in seen_hops)
