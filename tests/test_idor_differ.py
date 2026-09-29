"""Tests for the auth harness and the IDOR differ.

The differ's whole value proposition is that it separates a real cross-account
read from a 200 that looks identical on the wire. That property cannot be
tested against a mock, because a mock encodes the answer. So these tests run
against two local servers, one deliberately vulnerable and one correctly
enforcing authorisation, and assert on both directions:

  - the vulnerable server must produce a CONFIRMED finding
  - the hardened server must produce nothing

A differ that only ever says "yes" is the failure mode that matters here, so
the negative cases carry as much weight as the positive one.

The same local aiohttp server convention as test_http_engine is used, and
`asyncio.run()` per test, since there is no pytest-asyncio plugin.
"""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.wrappers as wrappers
from core.auth_harness import AuthHarness, Identity, fingerprint_body
from modules.idor_differ import (
    IdorDiffer,
    _extract_object_ids,
    _identity_markers,
    _looks_like_id,
    _swap_id,
    _template_key,
)
from state.manager import StateManager
from tools.http_engine import HttpEngine


# ── Local servers ────────────────────────────────────────────────


def _build_app(vulnerable: bool):
    """An app with two accounts and a per-invoice endpoint.

    Invoices 100/200 belong to alice/bob. When `vulnerable`, the object
    endpoint skips the ownership check; when not, it returns 403.
    """
    from aiohttp import web

    DB = {
        "100": {"invoice_id": "100", "owner_email": "alice@example.com",
                "customer": "alice@example.com", "amount": 120.0, "status": "paid"},
        "200": {"invoice_id": "200", "owner_email": "bob@example.com",
                "customer": "bob@example.com", "amount": 80.0, "status": "open"},
    }
    sessions = {
        "sess_alice": {"user": "alice", "email": "alice@example.com"},
        "sess_bob": {"user": "bob", "email": "bob@example.com"},
    }

    def current(request):
        return sessions.get(request.cookies.get("session"))

    async def dashboard(request):
        user = current(request)
        if not user:
            # A 200 that is really the login page — the trap the differ
            # has to see through.
            return web.Response(
                text='<h1>Sign in</h1><input type="password" name="password">',
                content_type="text/html",
            )
        return web.Response(
            text=f"<h1>Dashboard</h1><p>Welcome {user['user']}</p>"
                 "<a href='/logout'>Sign out</a>",
            content_type="text/html",
        )

    async def login(request):
        data = await request.post()
        sid = {"alice": "sess_alice", "bob": "sess_bob"}.get(data.get("user"))
        if not sid:
            raise web.HTTPUnauthorized(text="no")
        resp = web.HTTPFound("/dashboard")
        resp.set_cookie("session", sid, path="/")
        raise resp

    async def api_me(request):
        user = current(request)
        if not user:
            raise web.HTTPUnauthorized()
        return web.json_response({"email": user["email"], "user": user["user"]})

    async def collection(request):
        user = current(request)
        if not user:
            raise web.HTTPUnauthorized()
        owner = "100" if user["user"] == "alice" else "200"
        return web.json_response([DB[owner]])

    async def invoice(request):
        user = current(request)
        if not user:
            raise web.HTTPUnauthorized()
        inv = DB.get(request.match_info["id"])
        if not inv:
            raise web.HTTPNotFound(text="not found")
        if not vulnerable and inv["owner_email"] != user["email"]:
            # Correctly enforced: the object exists but is not theirs.
            raise web.HTTPForbidden(text="forbidden")
        return web.json_response(inv)

    app = web.Application()
    app.router.add_get("/", dashboard)
    app.router.add_get("/dashboard", dashboard)
    app.router.add_post("/login", login)
    app.router.add_get("/api/me", api_me)
    app.router.add_get("/api/invoices", collection)
    app.router.add_get("/api/invoices/{id}", invoice)
    app.router.add_get("/api/v1/invoices/{id}", invoice)
    return app


class _Env:
    """A running server, an engine, and a configured two-account harness."""

    def __init__(self, base, srv, engine, config, state):
        self.base = base
        self.srv = srv
        self.engine = engine
        self.config = config
        self.state = state

    async def run_module(self):
        module = IdorDiffer(self.state, self.config)
        return await module.run()

    def findings(self):
        return self.state.findings["findings"]

    def evidence(self):
        return self.state.evidence["items"]


def _harness(fn, *args, vulnerable=True, **kwargs):
    """Run a test body against a local server.

    `vulnerable` is keyword-only: pytest passes the test instance as the first
    positional argument, so a second positional parameter would silently bind
    the instance to the flag.
    """
    from aiohttp import web

    async def runner():
        app = _build_app(vulnerable)
        runner_ = web.AppRunner(app)
        await runner_.setup()
        site = web.TCPSite(runner_, "127.0.0.1", 0)
        await site.start()
        port = runner_.addresses[0][1]
        base = f"http://127.0.0.1:{port}"

        # Bare-IP cookies are refused by aiohttp unless the engine opts in.
        engine = HttpEngine(cookies_from_ip_hosts=True)
        wrappers._engine = engine
        # The per-minute cap is a real-target control. Loopback fixtures must
        # not queue behind it, or the suite spends a minute asleep.
        wrappers.configure_http_limiter(max_concurrent=20, max_per_minute=100000)

        out = tempfile.mkdtemp()
        config = {
            "target": {"domain": f"127.0.0.1:{port}"},
            "paths": {"output_dir": out},
            "auth": {"identities": {
                "alice": {"cookies": {"session": "sess_alice"},
                          "verify_url": f"{base}/dashboard",
                          "success_marker": "Sign out"},
                "bob": {"cookies": {"session": "sess_bob"},
                        "verify_url": f"{base}/dashboard",
                        "success_marker": "Sign out"},
            }},
            "modules": {"idor": {"endpoints": [
                f"{base}/api/invoices/100",
                f"{base}/api/invoices/200",
            ]}},
        }
        state = StateManager(str(out))
        env = _Env(base, app, engine, config, state)
        try:
            return await fn(*args, env)
        finally:
            await wrappers.close_engine()
            await runner_.cleanup()

    return asyncio.run(runner())


def served(fn):
    def wrapper(*args, **kwargs):
        return _harness(fn, *args, vulnerable=True, **kwargs)
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


def served_hardened(fn):
    """Same as `served`, but against the server that enforces authorisation."""
    def wrapper(*args, **kwargs):
        return _harness(fn, *args, vulnerable=False, **kwargs)
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


# ── Pure helpers ─────────────────────────────────────────────────


class TestHelpers:
    def test_numeric_uuid_and_opaque_ids_are_recognised(self):
        for good in ("42", "0", "3f8a1b2c-1111-2222-3333-444455556666",
                     "aB3dEfGhIjKlMnOp"):
            assert _looks_like_id(good), good
        for bad in ("", "main", "..", "3.5", "x" * 200, "2024-01-01"):
            assert not _looks_like_id(bad), bad

    def test_template_key_collapses_sibling_ids(self):
        assert _template_key("https://t/api/invoices/100") == \
               _template_key("https://t/api/invoices/200")

    def test_template_key_preserves_non_id_query_params(self):
        key = _template_key("https://t/api/x?id=7&format=json")
        assert "format=json" in key and "{id}" in key

    def test_swap_id_replaces_every_occurrence(self):
        out = _swap_id("https://t/api/9/x?id=9", "9", "77")
        # Both the path and the query must move together, or the test would
        # request a URL the application never serves.
        assert "9" not in out.replace("https://", "")
        assert out == "https://t/api/77/x?id=77"

    def test_object_ids_extracted_from_json(self):
        body = '{"data":[{"id":"1042"},{"order_id":"1043"},{"amount":9}]}'
        found = _extract_object_ids(body)
        assert "1042" in found and "1043" in found
        assert "9" not in found, "non-id field should not be harvested"

    def test_markers_exclude_generic_values(self):
        markers = _identity_markers(
            '{"email":"a@b.co","status":"active","name":"Ada Lovelace"}'
        )
        assert "a@b.co" in markers and "ada lovelace" in markers
        assert "active" not in markers, "generic values would defeat attribution"

    def test_short_values_are_too_weak_to_be_markers(self):
        """A three-character value matches too much to be evidence."""
        assert _identity_markers('{"name":"Ada"}') == set()

    def test_fingerprint_is_stable_across_processes(self):
        # _stable_digest must not use hash(), which is salted per run.
        assert fingerprint_body("abc")["digest"] == fingerprint_body("abc")["digest"]
        assert len(fingerprint_body("abc")["digest"]) == 16


# ── Auth harness ─────────────────────────────────────────────────


class TestAuthHarness:

    @served
    async def test_both_sessions_verify_and_stay_isolated(self, env):
        harness = AuthHarness(env.config)
        assert set(harness.identities) == {"alice", "bob"}
        await harness.establish_all(env.base)
        assert harness.has_pair(), "two verified accounts are required for IDOR"

        me_a = await harness.request("alice", f"{env.base}/api/me", output="body")
        me_b = await harness.request("bob", f"{env.base}/api/me", output="body")
        assert "alice@example.com" in me_a["body"]
        assert "bob@example.com" in me_b["body"], "cookie jars bled between identities"

    @served
    async def test_failed_login_is_not_mistaken_for_a_session(self, env):
        """A wrong session cookie must not verify just because it returns 200."""
        bad = Identity(name="mallory", cookies={"session": "nope"},
                       verify_url=f"{env.base}/dashboard",
                       success_marker="Sign out")
        assert await bad.establish() is False
        assert "marker" in bad.verification_note or "anonymous" in bad.verification_note

    @served
    async def test_missing_success_marker_fails_verification(self, env):
        """Guards against a session that is present but has no privileges."""
        weak = Identity(name="alice", cookies={"session": "sess_alice"},
                        verify_url=f"{env.base}/dashboard",
                        success_marker="Billing History")
        assert await weak.establish() is False
        assert "marker" in weak.verification_note

    @served
    async def test_scripted_login_adopts_session_cookie(self, env):
        identity = Identity(name="carol", verify_url=f"{env.base}/dashboard",
                            success_marker="Sign out",
                            login={"url": f"{env.base}/login",
                                   "data": {"user": "alice"}})
        assert await identity.establish() is True
        assert identity.cookies.get("session") == "sess_alice"

    @served
    async def test_anonymous_request_carries_no_session(self, env):
        harness = AuthHarness(env.config)
        await harness.establish_all(env.base)
        anon = await harness.request_anonymous(f"{env.base}/api/me", output="body")
        assert anon["status"] in (401, 403), "anonymous request inherited a cookie"

    def test_identities_accept_mapping_form(self):
        harness = AuthHarness({"auth": {"identities": {
            "a": {"cookies": {"s": "1"}}, "b": {"bearer_token": "t"}}}})
        assert set(harness.identities) == {"a", "b"}
        assert harness.identities["b"].request_headers()["Authorization"] == "Bearer t"

    def test_no_identities_yields_empty_harness(self):
        assert AuthHarness({}).identities == {}
        assert AuthHarness({"auth": {}}).identities == {}


# ── The differ: positive ─────────────────────────────────────────


class TestIdorDetected:

    @served
    async def test_cross_account_read_is_reported(self, env):
        result = await env.run_module()
        assert result == "done"
        findings = env.findings()
        # Both directions leak here, so both are reported.
        assert len(findings) == 2, f"expected one finding per direction, got {findings}"

        for finding in findings:
            assert finding["category"] == "broken-access-control"
            assert finding["confidence"] == "CONFIRMED", "leak must be attributed to a victim"
            assert finding["verified"] is True
            assert finding["severity"] == "high"

        # Each report must name the account whose data leaked, and both
        # accounts must be covered across the pair.
        blob = json.dumps(findings)
        assert "alice@example.com" in blob and "bob@example.com" in blob

    @served
    async def test_finding_records_the_victim_and_attacker(self, env):
        await env.run_module()
        subjects = [e["subject"] for e in env.evidence()
                    if e["type"] == "idor_cross_account"]
        assert any("alice" in s and "bob" in s for s in subjects), subjects

    @served
    async def test_evidence_carries_the_leaked_markers(self, env):
        await env.run_module()
        leaked = [e for e in env.evidence() if e["type"] == "idor_cross_account"]
        assert leaked, "a confirmed finding must have evidence"

        # `path` is stored relative to the run's output directory.
        for item in leaked:
            data = json.loads((Path(env.state.output_dir) / item["path"]).read_text())
            assert data["data"]["victim_markers_leaked"], "evidence must show what leaked"
            assert any("@" in marker
                       for marker in data["data"]["victim_markers_leaked"])


# ── The differ: negative ─────────────────────────────────────────
#
# A differ that only ever reports is worthless, so these matter as much as
# the positive cases.


class TestIdorNotReported:

    @served_hardened
    async def test_correct_authorisation_produces_no_finding(self, env):
        result = await env.run_module()
        assert result == "done"
        assert env.findings() == [], f"false positive: {env.findings()}"

    @served_hardened
    async def test_denied_object_is_not_evidence(self, env):
        await env.run_module()
        assert not [e for e in env.evidence() if e["type"] == "idor_cross_account"]


class TestNoFalsePositives:

    def test_login_page_returned_as_200_is_not_a_leak(self):
        """The classic trap: 200 OK, body is the sign-in form."""
        login_page = '<input type="password" name="password">'
        assert fingerprint_body(login_page)["has_login_form"] is True

    @served
    async def test_unverified_identities_abort_before_testing(self, env):
        """No verified session must mean no finding, not a guess."""
        env.config["auth"]["identities"] = {
            "ghost": {"cookies": {"session": "dead"},
                      "verify_url": f"{env.base}/dashboard",
                      "success_marker": "Sign out"},
        }
        assert await env.run_module() == "skipped"
        assert env.findings() == []

    @served
    async def test_single_account_cannot_prove_horizontal_access(self, env):
        """One account is not a comparison, so no IDOR may be claimed."""
        env.config["auth"]["identities"] = {
            "alice": {"cookies": {"session": "sess_alice"},
                      "verify_url": f"{env.base}/dashboard",
                      "success_marker": "Sign out"},
        }
        result = await env.run_module()
        assert result == "done"
        assert env.findings() == [], "IDOR requires two accounts"

    @served
    async def test_missing_config_is_skipped_not_crashed(self, env):
        env.config["auth"] = {}
        assert await env.run_module() == "skipped"
        assert env.findings() == []

    @served
    async def test_invalid_identity_shape_does_not_crash_the_module(self, env):
        env.config["auth"]["identities"] = [
            {"no_name": True}, "not-a-dict", {"name": "carol"},
        ]
        assert await env.run_module() in ("done", "skipped")
        assert env.findings() == []
