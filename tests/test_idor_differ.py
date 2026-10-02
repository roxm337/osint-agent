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
import base64
import contextlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.wrappers as wrappers
from tools.wrappers import curl
from core.auth_harness import AuthHarness, Identity, fingerprint_body
from aiohttp import web

from modules.idor_differ import (
    IdorDiffer,
    ObjectTemplate,
    _absent_ref,
    _extract_object_ids,
    _extract_refs,
    _identity_markers,
    _looks_like_id,
    _swap_id,
    _template_key,
)
from state.manager import StateManager
from tools.http_engine import HttpEngine


def _jwt(claims: dict) -> str:
    """A structurally valid JWT carrying `claims`.

    Nothing here verifies a signature — the harness reads an identity's own
    token only to ask it who it says it is — so an unsigned body is enough.
    """
    def seg(payload: dict) -> str:
        raw = json.dumps(payload).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{seg({'alg': 'none', 'typ': 'JWT'})}.{seg(claims)}.forged"


# ── Local servers ────────────────────────────────────────────────


def _build_app(vulnerable: bool, *, write_vulnerable: bool = False,
               public_ids=(), third_party=(), csrf: bool = False,
               orphaned=()):
    """An app with two accounts and a per-invoice endpoint.

    Invoices 100/200 belong to alice/bob. When `vulnerable`, the object
    endpoint skips the ownership check; when not, it returns 403.

    `write_vulnerable` controls the same check on PATCH/PUT/DELETE, which is
    usually enforced independently of the read path. `public_ids` are readable
    with no session at all. `third_party` adds records owned by an account
    that is not in the harness, for sequential-ID probing. `csrf` makes the
    login form carry a token the POST must echo back.
    """
    from aiohttp import web

    DB = {
        "100": {"invoice_id": "100", "owner_email": "alice@example.com",
                "customer": "alice@example.com", "amount": 120.0, "status": "paid"},
        "200": {"invoice_id": "200", "owner_email": "bob@example.com",
                "customer": "bob@example.com", "amount": 80.0, "status": "open"},
    }
    for inv_id in third_party:
        DB[str(inv_id)] = {
            "invoice_id": str(inv_id), "owner_email": "carol@example.com",
            "customer": "carol@example.com", "amount": 55.0, "status": "open",
        }
    for inv_id in orphaned:
        # An orphaned record: no owner field at all, so there is nothing for
        # an ownership check to compare against, and nothing in the payload
        # that says whose it was.
        DB[str(inv_id)] = {"invoice_id": str(inv_id), "status": "open",
                           "amount": 42.0}
    public_ids = {str(p) for p in public_ids}
    sessions = {
        "sess_alice": {"user": "alice", "email": "alice@example.com"},
        "sess_bob": {"user": "bob", "email": "bob@example.com"},
    }
    CSRF_TOKEN = "tok-abc-123"
    issued = set()

    def current(request):
        return sessions.get(request.cookies.get("session"))

    def owns(user, inv):
        return user and inv.get("owner_email") == user["email"]

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

    async def login_page(request):
        if not csrf:
            return web.Response(text="<h1>Sign in</h1>", content_type="text/html")
        return web.Response(
            text=f'<h1>Sign in</h1><form method="post">'
                 f'<input type="hidden" name="csrfmiddlewaretoken" '
                 f'value="{CSRF_TOKEN}">'
                 f'<input name="user"></form>',
            content_type="text/html",
        )

    async def login(request):
        data = await request.post()
        if csrf and data.get("csrfmiddlewaretoken") != CSRF_TOKEN:
            raise web.HTTPForbidden(text="bad csrf token")
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

    # A bearer-protected route. A cookie identity keeps its session in the
    # engine's per-identity jar, but a bearer identity has no jar: its
    # Authorization header *is* the credential, so anything that discards
    # that header authenticates nothing.
    BEARERS = {"tok-alice": "alice@example.com", "tok-bob": "bob@example.com"}

    async def vault(request):
        token = request.headers.get("Authorization", "")
        if token.startswith("Bearer "):
            token = token[len("Bearer "):]
        email = BEARERS.get(token)
        if not email:
            raise web.HTTPUnauthorized(text="No Authorization header was found")
        return web.json_response({"email": email, "role": "member"})

    async def collection(request):
        user = current(request)
        if not user:
            raise web.HTTPUnauthorized()
        owner = "100" if user["user"] == "alice" else "200"
        return web.json_response([DB[owner]])

    async def invoice(request):
        user = current(request)
        inv = DB.get(request.match_info["id"])
        if not inv:
            raise web.HTTPNotFound(text="not found")
        if "owner_email" not in inv:
            # No owner to check against. An application that lets this
            # through discloses a real record to every session.
            return web.json_response(inv)
        if not user:
            # Public records are readable by design; everything else is not.
            if request.match_info["id"] in public_ids:
                return web.json_response(inv)
            raise web.HTTPUnauthorized()
        if not vulnerable and not owns(user, inv):
            # Correctly enforced: the object exists but is not theirs.
            raise web.HTTPForbidden(text="forbidden")
        return web.json_response(inv)

    async def write_invoice(request):
        user = current(request)
        if not user:
            raise web.HTTPUnauthorized()
        inv = DB.get(request.match_info["id"])
        if not inv:
            raise web.HTTPNotFound(text="not found")
        if not write_vulnerable and not owns(user, inv):
            raise web.HTTPForbidden(text="forbidden")
        if request.method == "DELETE":
            del DB[request.match_info["id"]]
            issued.add(request.match_info["id"])
            return web.json_response({"deleted": True})
        payload = await request.json() if request.can_read_body else {}
        # Echo the victim's own values back so a caller can tell an accepted
        # write from a rejected one without changing anything meaningful.
        body = {**inv, **{k: v for k, v in (payload or {}).items()
                          if k in ("status", "reference")}}
        DB[request.match_info["id"]] = body
        issued.add(request.match_info["id"])
        return web.json_response(body)

    async def not_a_collection(request):
        raise web.HTTPNotFound(text="not found")

    # An object shape with no listing counterpart, like a shopping basket.
    # Neither account's view of it can be compared with the other's, so the
    # flat map puts every reference in both pockets at once and the
    # difference that proves privacy is empty.
    BASKETS = {
        "100": {"id": "100", "owner_email": "alice@example.com", "items": 3},
        "200": {"id": "200", "owner_email": "bob@example.com", "items": 1},
    }

    async def basket(request):
        user = current(request)
        record = BASKETS.get(request.match_info["id"])
        if not record:
            raise web.HTTPNotFound(text="not found")
        if not user:
            raise web.HTTPUnauthorized()
        if not vulnerable and not owns(user, record):
            raise web.HTTPForbidden(text="forbidden")
        return web.json_response(record)

    app = web.Application()
    app.router.add_get("/", dashboard)
    app.router.add_get("/dashboard", dashboard)
    app.router.add_get("/login", login_page)
    app.router.add_post("/login", login)
    app.router.add_get("/api/me", api_me)
    app.router.add_get("/api/vault", vault)
    app.router.add_get("/api/invoices", collection)
    app.router.add_get("/api/invoices/{id}", invoice)
    app.router.add_get("/api/v1/invoices/{id}", invoice)
    app.router.add_get("/api/baskets/{id}", basket)
    for method in ("PATCH", "PUT", "DELETE"):
        app.router.add_route(method, "/api/invoices/{id}", write_invoice)
    # A decoy so wordlist probing is not trivially all-404.
    app.router.add_get("/api/widgets", not_a_collection)
    return app


@contextlib.asynccontextmanager
async def _served_app(**app_kwargs):
    """Start a server on an ephemeral port and yield its base URL."""
    async with _served_app_with(_build_app(True, **app_kwargs)) as base:
        yield base


@contextlib.asynccontextmanager
async def _served_app_with(app):
    """Serve an already-configured app.

    Routes must be added before this is entered: aiohttp freezes the router
    during `AppRunner.setup()`, and a late `add_post` raises.
    """
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    base = f"http://127.0.0.1:{runner.addresses[0][1]}"
    wrappers._engine = HttpEngine(cookies_from_ip_hosts=True)
    wrappers.configure_http_limiter(max_concurrent=20, max_per_minute=100000)
    try:
        yield base
    finally:
        await wrappers.close_engine()
        await runner.cleanup()


@contextlib.asynccontextmanager
async def _csrf_app():
    async with _served_app(csrf=True) as base:
        yield base


@contextlib.asynccontextmanager
async def _tokenless_app():
    async with _served_app(csrf=False) as base:
        yield base


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


def _harness(fn, *args, vulnerable=True, app_kwargs=None, module_cfg=None,
             identities=None, **kwargs):
    """Run a test body against a local server.

    `vulnerable` is keyword-only: pytest passes the test instance as the first
    positional argument, so a second positional parameter would silently bind
    the instance to the flag. `app_kwargs` and `module_cfg` let a test switch
    on the optional behaviours (writes, public records, wordlists) without
    duplicating the whole fixture.
    """
    from aiohttp import web

    async def runner():
        app = _build_app(vulnerable, **(app_kwargs or {}))
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
        idor_cfg = {"endpoints": [
            f"{base}/api/invoices/100",
            f"{base}/api/invoices/200",
        ]}
        idor_cfg.update(module_cfg or {})
        config = {
            "target": {"domain": f"127.0.0.1:{port}"},
            "paths": {"output_dir": out},
            "auth": {"identities": identities if identities is not None else {
                "alice": {"cookies": {"session": "sess_alice"},
                          "verify_url": f"{base}/dashboard",
                          "success_marker": "Sign out"},
                "bob": {"cookies": {"session": "sess_bob"},
                        "verify_url": f"{base}/dashboard",
                        "success_marker": "Sign out"},
            }},
            "modules": {"idor": idor_cfg},
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


def variant(**app_kwargs):
    """Like `served`, but switches on optional server behaviour."""
    def wrapper(fn):
        def inner(*args, **kwargs):
            return _harness(fn, *args, vulnerable=True,
                            app_kwargs=app_kwargs, **kwargs)
        inner.__name__ = fn.__name__
        inner.__doc__ = fn.__doc__
        return inner
    return wrapper


def standalone(fn):
    """Run a bare `async def` test, since there is no pytest-asyncio here."""
    def wrapper(*args, **kwargs):
        return asyncio.run(fn(*args, **kwargs))
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

    @standalone
    async def test_anonymous_request_ignores_the_legacy_global_session(self):
        """The legacy single-session config must not authenticate every probe.

        Otherwise an ordinary authenticated read is reported as a public
        exposure, which is the worst kind of wrong for a finding that claims
        no credentials are needed.
        """
        async with _served_app() as base:
            wrappers.configure_http_session({"auth": {
                "cookies": {"session": "sess_alice"},
                "bearer_token": "legacy-token",
            }})
            try:
                harness = AuthHarness({"auth": {}})
                anon = await harness.request_anonymous(f"{base}/api/me",
                                                        output="body")
                assert anon["status"] in (401, 403), \
                    "a global cookie was sent on an anonymous request"
            finally:
                wrappers.configure_http_session({})

    def test_global_auth_headers_are_stripped_per_identity(self):
        wrappers.configure_http_session({"auth": {
            "cookies": {"session": "sess_alice"},
            "bearer_token": "legacy-token",
            "headers": {"User-Agent": "scanner", "X-Team": "research"},
        }})
        try:
            # A named identity supplies its own credential.
            scoped = wrappers._merge_session_headers({}, drop_auth=True)
            assert "Cookie" not in scoped and "Authorization" not in scoped
            # Non-auth headers still apply, or every probe looks synthetic.
            assert scoped["User-Agent"] == "scanner"
            assert scoped["X-Team"] == "research"

            # A bare request keeps the legacy behaviour other modules rely on.
            legacy = wrappers._merge_session_headers({})
            assert legacy["Authorization"] == "Bearer legacy-token"
            assert "session=sess_alice" in legacy["Cookie"]
        finally:
            wrappers.configure_http_session({})

    def test_identities_accept_mapping_form(self):
        harness = AuthHarness({"auth": {"identities": {
            "a": {"cookies": {"s": "1"}}, "b": {"bearer_token": "t"}}}})
        assert set(harness.identities) == {"a", "b"}
        assert harness.identities["b"].request_headers()["Authorization"] == "Bearer t"

    def test_no_identities_yields_empty_harness(self):
        assert AuthHarness({}).identities == {}
        assert AuthHarness({"auth": {}}).identities == {}

    def test_privilege_comes_from_config_or_the_tokens_own_claims(self):
        """Only the report's ordering depends on this, and only if it is known.

        An unknown role must count as ordinary: guessing that an account is
        privileged would bury the peer-to-peer direction of a real leak.
        """
        assert Identity(name="a", role="admin").privileged
        assert not Identity(name="b", role="customer").privileged
        assert not Identity(name="c").privileged
        assert Identity(name="d",
                        bearer_token=_jwt({"role": "root"})).privileged
        # Juice Shop nests its claims under `data`; the walk flattens them.
        assert Identity(name="e", bearer_token=_jwt(
            {"data": {"role": "admin"}})).privileged
        assert not Identity(name="f",
                            bearer_token=_jwt({"role": "customer"})).privileged


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
                    if e["type"] == "idor_read"]
        assert any("alice" in s and "bob" in s for s in subjects), subjects

    @served
    async def test_evidence_carries_the_leaked_markers(self, env):
        await env.run_module()
        leaked = [e for e in env.evidence() if e["type"] == "idor_read"]
        assert leaked, "a confirmed finding must have evidence"

        # `path` is stored relative to the run's output directory.
        for item in leaked:
            data = json.loads((Path(env.state.output_dir) / item["path"]).read_text())
            assert data["data"]["victim_markers_leaked"], "evidence must show what leaked"
            assert any("@" in marker
                       for marker in data["data"]["victim_markers_leaked"])

    @served
    async def test_the_headline_direction_is_between_peers(self, env):
        """The first entry in the report is what a triager reads."""
        await env.run_module()
        subjects = [e["subject"] for e in env.evidence()
                    if e["type"] == "idor_read"]
        assert subjects[0].startswith("alice->bob"), subjects

    @served
    async def test_a_privileged_account_is_not_the_headline_direction(self, env):
        """An administrator may be entitled to read any record; peers are not.

        Leading with an administrator's read would hand a triager the reason
        to close the ticket. Demoting the privileged account moves the peer
        pair to the front without dropping anything.
        """
        env.config["auth"]["identities"]["alice"]["role"] = "admin"
        await env.run_module()
        subjects = [e["subject"] for e in env.evidence()
                    if e["type"] == "idor_read"]
        assert subjects[0].startswith("bob->alice"), subjects
        assert len(subjects) == 2, subjects


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
        assert not [e for e in env.evidence() if e["type"] == "idor_read"]


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


# ── Bearer identities ─────────────────────────────────────────────


class TestBearerIdentities:
    """A bearer identity has no cookie jar, so its header is the session.

    The strip that protects isolated jars from the legacy global credential
    used to run over the identity's own headers as well, so every bearer
    request went out unauthenticated: objects came back 401, no ownership
    could be attributed, and the differ reported zero probes against a
    target whose baskets were readable by anyone — while the run still
    claimed verified sessions, because the fallback verify URL was public.
    """

    @staticmethod
    def _with_vault_identities(env, tokens):
        env.config["auth"]["identities"] = {
            name: {"bearer_token": token,
                   "verify_url": f"{env.base}/api/vault",
                   "success_marker": f"{name}@example.com"}
            for name, token in tokens.items()
        }

    @served
    async def test_verification_proves_the_header_was_sent(self, env):
        """The vault 401s without a token, so 200 means the header arrived."""
        self._with_vault_identities(env, {"alice": "tok-alice",
                                          "bob": "tok-bob"})
        assert await env.run_module() == "done"

    @served
    async def test_a_rejected_token_is_not_a_session(self, env):
        """The counterpart, or the test above would pass on a fluke."""
        self._with_vault_identities(env, {"ghost": "tok-nope"})
        assert await env.run_module() == "skipped"
        assert env.findings() == []

    def test_identity_headers_survive_the_legacy_session_strip(self):
        merged = wrappers._merge_session_headers(
            {"Authorization": "Bearer identity-token"}, drop_auth=True)
        assert merged["Authorization"] == "Bearer identity-token"

    def test_anonymous_strips_even_a_caller_supplied_credential(self):
        merged = wrappers._drop_auth_headers(
            {"Authorization": "Bearer identity-token", "Cookie": "session=1",
             "User-Agent": "scanner"})
        assert merged == {"User-Agent": "scanner"}


# ── Bug regressions: false-positive sources found in review ───────


class TestParameterAndUrlConfusion:

    def test_only_configured_codes_count_as_waf_blocks(self):
        """401/403 is the auth layer working; logging it as a WAF block lies."""
        from modules.idor_differ import IdorDiffer as D

        differ = D.__new__(D)
        differ.waf_config = {}
        assert differ._waf_codes() == {429, 503}

        differ.waf_config = {"block_codes": [403, 503]}
        assert differ._waf_codes() == {403, 503}

        differ.waf_config = {"block_codes": "garbage"}
        assert differ._waf_codes() == {429, 503}, "bad config must not crash the run"

    def test_pagination_and_sort_params_are_not_object_references(self):
        for url in ("https://t/api/x?page=2", "https://t/api/x?limit=50",
                    "https://t/api/x?offset=100", "https://t/api/x?sort=asc",
                    "https://t/api/x?order=desc", "https://t/api/x?cursor=abc"):
            assert _extract_object_ids(url) == [], url
            assert "{id}" not in _template_key(url), url

    def test_swapping_rewrites_the_id_query_param_and_leaves_the_rest(self):
        swapped = _swap_id("https://t/api/orders/7?page=7&order_id=7", "7", "100")
        assert swapped == "https://t/api/orders/100?page=7&order_id=100", swapped
        assert _swap_id("https://t/api/orders/7?page=7", "7", "100") == \
               "https://t/api/orders/100?page=7"

    def test_real_id_params_are_still_harvested(self):
        """The fix must not over-correct into ignoring genuine references."""
        for url in ("https://t/api/x?id=7", "https://t/api/x?invoice_id=1042",
                    "https://t/api/x/42"):
            assert _extract_refs(url), url
        assert _extract_object_ids('{"invoice_id":"1042"}') == ["1042"]

    def test_swap_does_not_mutate_version_or_year_segments(self):
        """A blind substring replace corrupted /api/v7 and /reports/2017."""
        assert _swap_id("https://t/api/v7/orders/7", "7", "77") == \
               "https://t/api/v7/orders/77"
        assert _swap_id("https://t/reports/2017/q3", "2017", "88") == \
               "https://t/reports/88/q3"

    def test_absent_reference_is_never_the_same_as_a_real_one(self):
        import re
        uuid = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
        for ref in ("0", "1", "42", "100", "aB3dEfGhIjKlMnOp",
                    "00000000-0000-0000-0000-000000000000",
                    "3f8a1b2c-1111-2222-3333-444455556666"):
            absent = _absent_ref(ref)
            assert absent != ref, ref
            # The baseline must keep the reference's shape, or the request it
            # produces is not the "same request with a different id" the
            # comparison depends on.
            if uuid.match(ref):
                assert uuid.match(absent), (ref, absent)


# ── Anonymous exposure ───────────────────────────────────────────


class TestAnonymousExposure:

    @served
    async def test_private_object_is_not_reported_without_opt_in(self, env):
        """Nothing on this server is public, so the probe must find nothing."""
        env.config["modules"]["idor"]["test_anonymous"] = True
        env.config["modules"]["idor"]["endpoints"] = [f"{env.base}/api/invoices/100"]
        assert await env.run_module() == "done"
        assert not [f for f in env.findings()
                    if "without authentication" in f["title"]], \
            f"nothing here is public: {env.findings()}"

    @variant(public_ids=["100"])
    async def test_anonymous_probe_is_off_unless_requested(self, env):
        """Record 100 *is* readable with no session, so the opt-in is the
        only thing standing between this run and a real finding."""
        env.config["modules"]["idor"]["endpoints"] = [f"{env.base}/api/invoices/100"]
        assert await env.run_module() == "done"
        assert not [f for f in env.findings()
                    if "without authentication" in f["title"]]

    @variant(public_ids=["100"])
    async def test_public_object_is_reported_when_enabled(self, env):
        env.config["modules"]["idor"]["test_anonymous"] = True
        env.config["modules"]["idor"]["endpoints"] = [f"{env.base}/api/invoices/100"]
        assert await env.run_module() == "done"

        anon = [f for f in env.findings() if "without authentication" in f["title"]]
        assert anon, env.findings()
        # Unauthenticated disclosure of a named customer's data is the worst
        # case, so it must not be filed as a medium.
        assert anon[0]["severity"] == "critical"
        assert "alice@example.com" in anon[0]["description"]


# ── Sequential / unknown-owner probing ───────────────────────────


class TestSequentialProbing:

    @variant(third_party=[101])
    async def test_third_party_record_is_reported(self, env):
        """The case two accounts cannot prove: a stranger's record."""
        env.config["modules"]["idor"]["id_probing"] = {
            "enabled": True, "radius": 3, "max": 20,
        }
        env.config["modules"]["idor"]["endpoints"] = [f"{env.base}/api/invoices/100"]
        assert await env.run_module() == "done"

        unknown = [f for f in env.findings() if "unowned record" in f["title"]]
        assert unknown, [f["title"] for f in env.findings()]
        # carol@example.com appears in no session, so it can only have come
        # from the other account's record.
        assert "carol@example.com" in unknown[0]["description"]
        assert unknown[0]["verified"] is True

    @variant(third_party=[101])
    async def test_probing_is_off_by_default(self, env):
        """A stranger's record sits one ID away, so only the opt-in stands
        between this run and reaching other people's data."""
        env.config["modules"]["idor"]["endpoints"] = [f"{env.base}/api/invoices/100"]
        assert await env.run_module() == "done"
        assert not [f for f in env.findings() if "unowned" in f["title"]]

    @variant(orphaned=[101, 102, 103, 104, 105, 106, 107, 108])
    async def test_probing_respects_its_budget(self, env):
        """Every candidate here exists, so each probe that runs is recorded.
        Counting 404s would pass even with no budget at all."""
        env.config["modules"]["idor"]["id_probing"] = {
            "enabled": True, "radius": 8, "max": 3,
        }
        env.config["modules"]["idor"]["endpoints"] = [f"{env.base}/api/invoices/100"]
        assert await env.run_module() == "done"
        probed = [e for e in env.evidence() if e["type"] == "idor_unattributed"]
        assert 0 < len(probed) <= 3, \
            f"the budget must bound the probes, got {len(probed)}"

    def _hardened_third_party(fn):
        def inner(*args, **kwargs):
            return _harness(fn, *args, vulnerable=False,
                            app_kwargs={"third_party": [101]})
        inner.__name__ = fn.__name__
        inner.__doc__ = fn.__doc__
        return inner

    @_hardened_third_party
    async def test_enforced_server_leaks_nothing_to_sequential_probing(self, env):
        env.config["modules"]["idor"]["id_probing"] = {
            "enabled": True, "radius": 3, "max": 20,
        }
        env.config["modules"]["idor"]["endpoints"] = [f"{env.base}/api/invoices/100"]
        assert await env.run_module() == "done"
        assert env.findings() == [], f"false positive: {env.findings()}"


# ── Write authorisation ──────────────────────────────────────────


class TestUnattributedLeaks:

    def test_orphaned_record_is_not_reported_without_proof_of_ownership(self):
        """A record that came back but cannot be tied to any account is a weak
        signal. Filing it as CONFIRMED would be a guess; it is still recorded."""
        async def body(env):
            env.config["modules"]["idor"]["endpoints"] = \
                [f"{env.base}/api/invoices/100"]
            assert await env.run_module() == "done"

            assert env.findings() == [], \
                f"an unattributable leak must not become a finding: {env.findings()}"
            recorded = [e for e in env.evidence()
                        if e["type"] == "idor_unattributed"]
            assert recorded, "the probe should still be recorded as evidence"

        # Enforced for the two known accounts, so the only thing that comes
        # back is the markerless stranger's record reached by probing.
        return _harness(body, vulnerable=False,
                        app_kwargs={"orphaned": [101]},
                        module_cfg={"id_probing":
                                    {"enabled": True, "radius": 1, "max": 5}})


class TestWriteAuthorisation:

    @variant(write_vulnerable=True)
    async def test_accepted_cross_account_write_is_critical(self, env):
        env.config["modules"]["idor"]["test_write_methods"] = ["PATCH"]
        # Only alice's own URL is known; bob's record must be reached by
        # substituting into the shape, which recon never observed directly.
        env.config["modules"]["idor"]["endpoints"] = [f"{env.base}/api/invoices/100"]
        assert await env.run_module() == "done"

        writes = [f for f in env.findings() if "can modify" in f["title"]]
        assert writes, [f["title"] for f in env.findings()]
        # A confirmed write is a data-integrity problem, not a read leak.
        assert writes[0]["severity"] == "critical"
        assert "PATCH" in writes[0]["title"]

    @variant(write_vulnerable=True)
    async def test_echoed_write_leaves_the_record_intact(self, env):
        """The probe must not quietly destroy the victim's data."""
        from tools.wrappers import curl

        env.config["modules"]["idor"]["test_write_methods"] = ["PUT"]
        env.config["modules"]["idor"]["endpoints"] = [f"{env.base}/api/invoices/100"]
        await env.run_module()

        after = await curl(f"{env.base}/api/invoices/200", identity="bob",
                           output="body")
        assert json.loads(after["body"])["amount"] == 80.0
        assert json.loads(after["body"])["status"] == "open"

    @variant(write_vulnerable=True)
    async def test_writes_are_off_by_default(self, env):
        env.config["modules"]["idor"]["endpoints"] = [f"{env.base}/api/invoices/200"]
        assert await env.run_module() == "done"
        assert not [f for f in env.findings() if "can modify" in f["title"]]

    @variant(write_vulnerable=True)
    async def test_delete_is_never_sent_without_destructive_consent(self, env):
        env.config["modules"]["idor"]["test_write_methods"] = ["DELETE"]
        env.config["modules"]["idor"]["endpoints"] = [f"{env.base}/api/invoices/100"]
        assert await env.run_module() == "done"

        after = await curl(f"{env.base}/api/invoices/200", identity="bob",
                           output="body")
        assert after["status"] == 200, "an unconsented DELETE destroyed the record"

    @served
    async def test_enforced_server_rejects_cross_account_writes(self, env):
        env.config["modules"]["idor"]["test_write_methods"] = ["PATCH", "PUT"]
        env.config["modules"]["idor"]["endpoints"] = [f"{env.base}/api/invoices/100"]
        assert await env.run_module() == "done"
        assert not [f for f in env.findings() if "can modify" in f["title"]]


# ── Collection discovery ─────────────────────────────────────────


class TestCollectionDiscovery:

    @served
    async def test_wordlist_finds_collections_and_synthesises_templates(self, env):
        """No object URL was ever observed; the run must still find records."""
        env.config["modules"]["idor"]["endpoints"] = []
        env.config["modules"]["idor"]["collection_paths"] = ["/api/invoices"]
        assert await env.run_module() == "done"

        titles = [f["title"] for f in env.findings()]
        assert any("IDOR" in t for t in titles), \
            f"collection-only discovery produced nothing: {titles}"

    @served
    async def test_404_collections_do_not_invent_endpoints(self, env):
        env.config["modules"]["idor"]["endpoints"] = []
        env.config["modules"]["idor"]["collection_paths"] = ["/api/widgets"]
        env.config["modules"]["idor"]["max_collections"] = 5
        assert await env.run_module() in ("done", "skipped")
        assert env.findings() == [], "a 404 is not an endpoint"


# ── Object shapes with no listing endpoint ───────────────────────


class TestOwnershipWithoutCollection:
    """Ownership for an object nobody ever listed, such as a basket.

    A collection response is where ownership normally comes from: alice's
    view of `/api/invoices` shows 100, bob's shows 200, and the difference is
    the proof. A basket has no listing endpoint, both accounts read it
    identically, and the flat map then hands every reference to both accounts
    at once — 1191 references were attributed that way on the live target
    without one of them ever being tested. These cases cover the fix: the
    payload's own owner field is what has to say whose record it is.
    """

    @staticmethod
    def _point_at_baskets(env):
        env.config["modules"]["idor"]["endpoints"] = [
            f"{env.base}/api/invoices/100",
            f"{env.base}/api/baskets/100",
        ]
        for name, email in (("alice", "alice@example.com"),
                            ("bob", "bob@example.com")):
            env.config["auth"]["identities"][name]["email"] = email

    @staticmethod
    def _evidence(env):
        """Every idor evidence record, payload included."""
        records = []
        for item in env.evidence():
            if not item["type"].startswith("idor_"):
                continue
            path = Path(env.state.output_dir) / item["path"]
            records.append(json.loads(path.read_text())["data"])
        return records

    @staticmethod
    def _for_endpoint(env, needle):
        return [e for e in TestOwnershipWithoutCollection._evidence(env)
                if needle in e.get("url", "")]

    @served
    async def test_unlisted_object_is_attributed_and_reported(self, env):
        """The endpoint that had no collection behind it must still land."""
        self._point_at_baskets(env)
        assert await env.run_module() == "done"

        basket = self._for_endpoint(env, "/api/baskets/")
        assert basket, f"no evidence for the unlisted object: " \
                       f"{[f['title'] for f in env.findings()]}"
        assert len(basket) == 2, f"expected one per direction: {basket}"
        # Invoices produce a pair as well, so four findings total: the pair
        # that had a collection behind it and the pair that had none.
        assert len(env.findings()) == 4, [f["title"] for f in env.findings()]

        for record in basket:
            assert record["victim_markers_leaked"], record
            assert record["victim"] in json.dumps(record["victim_markers_leaked"])

    @served_hardened
    async def test_authorised_unlisted_object_stays_silent(self, env):
        """Knowing who owns the record is not the same as a leak."""
        self._point_at_baskets(env)
        assert await env.run_module() == "done"
        assert self._for_endpoint(env, "/api/baskets/") == [], \
            "authorised reads were reported as IDOR"

    @served
    async def test_a_reference_seen_by_both_accounts_is_not_common_property(self,
                                                                          env):
        """One shared collection must not put a record in both pockets.

        Scoped per endpoint, `/api/invoices/100` belongs to alice alone even
        though the same value shows up in another account's view elsewhere.
        """
        self._point_at_baskets(env)
        assert await env.run_module() == "done"

        basket = self._for_endpoint(env, "/api/baskets/")
        assert basket, "the unlisted endpoint produced no evidence"
        pairs = {(e["attacker"], e["victim"]) for e in basket}
        # Each direction names the account whose marker came back, so a
        # shared flat map could never have produced this: it would have
        # called the record common property and probed nothing.
        assert pairs == {("alice", "bob"), ("bob", "alice")}, pairs
        for record in basket:
            assert record["victim"] in json.dumps(record["victim_markers_leaked"])


def test_ownership_is_scoped_to_the_endpoint_that_disclosed_it():
    """A shared collection must not make every reference common property."""
    module = IdorDiffer(StateManager(tempfile.mkdtemp()),
                        {"target": {}, "auth": {}, "modules": {}})
    module._owned_by_coll_identity = {
        "https://x.test/api/products": {"alice": {"100"}, "bob": {"100"}},
        "https://x.test/rest/basket": {"alice": {"6"}},
    }
    ownership = module._build_ownership([
        ObjectTemplate(url="https://x.test/api/products/100"),
        ObjectTemplate(url="https://x.test/rest/basket/6"),
    ])

    products = ownership["https://x.test/api/products/{id}"]
    assert products["alice"] == products["bob"] == {"100"}
    # Same reference value, different endpoint: only one account holds it.
    basket = ownership["https://x.test/rest/basket/{id}"]
    assert basket == {"alice": {"6"}}


def test_only_object_shapes_are_probed_for_ownership():
    """A command path such as /things/{id}/checkout has no id space to walk."""
    module = IdorDiffer(StateManager(tempfile.mkdtemp()),
                        {"target": {}, "auth": {}, "modules": {}})
    assert module._is_pure_object(ObjectTemplate(url="https://x.test/a/{id}"))
    assert not module._is_pure_object(
        ObjectTemplate(url="https://x.test/a/{id}/checkout"))


# ── CSRF-aware and Basic-auth identities ─────────────────────────


@contextlib.asynccontextmanager
async def _json_app():
    """A server that only accepts a JSON login body."""
    app = _build_app(True)

    async def json_login(request):
        try:
            data = await request.json()
        except Exception:
            raise web.HTTPUnsupportedMediaType(text="json required")
        sid = {"alice": "sess_alice", "bob": "sess_bob"}.get(data.get("username"))
        if not sid:
            raise web.HTTPUnauthorized(text="no")
        resp = web.json_response({"ok": True})
        resp.set_cookie("session", sid, path="/")
        return resp

    app.router.add_post("/auth/login", json_login)
    async with _served_app_with(app) as base:
        yield base


class TestLoginVariants:

    @standalone
    async def test_csrf_token_is_harvested_from_the_login_page(self):
        """A login form that demands a token must still work scripted."""
        async with _csrf_app() as base:
            identity = Identity(
                name="carol", verify_url=f"{base}/dashboard",
                success_marker="Sign out",
                login={"url": f"{base}/login", "data": {"user": "alice"}},
            )
            assert await identity.establish(base) is True, identity.verification_note
            assert identity.cookies.get("session") == "sess_alice"

    @standalone
    async def test_login_without_the_token_is_rejected(self):
        """Confirms the fixture actually enforces CSRF, so the test above bites."""
        async with _csrf_app() as base:
            bad = await curl(f"{base}/login", method="POST",
                             data={"user": "alice"}, output="body")
            assert bad["status"] == 403, "the CSRF fixture is not enforcing anything"

    @standalone
    async def test_csrf_can_be_disabled_for_tokenless_forms(self):
        """Not every login form has a CSRF field, and the GET must not break it."""
        async with _tokenless_app() as base:
            identity = Identity(
                name="carol", verify_url=f"{base}/dashboard",
                success_marker="Sign out",
                login={"url": f"{base}/login", "data": {"user": "alice"},
                       "csrf": False},
            )
            assert await identity.establish(base) is True, identity.verification_note

    @standalone
    async def test_json_login_sends_a_json_body(self):
        """A JSON login must not be form-encoded, and must not be CSRF-patched."""
        async with _json_app() as base:
            identity = Identity(
                name="api", verify_url=f"{base}/api/me",
                success_marker="alice@example.com",
                login={"url": f"{base}/auth/login", "content_type": "json",
                       "data": {"username": "alice", "password": "pw"},
                       "extract_token": False},
            )
            assert await identity.establish(base) is True, identity.verification_note
            assert identity.cookies.get("session") == "sess_alice"

    def test_basic_auth_identity_builds_the_header(self):
        identity = Identity(name="api", basic_auth=("user", "pw"))
        assert identity.request_headers()["Authorization"] == \
               "Basic dXNlcjpwdw=="

    def test_basic_auth_counts_as_a_credential(self):
        assert Identity(name="api", basic_auth=("u", "p")).has_credentials()
        assert not Identity(name="anon").has_credentials()

    def test_bearer_token_wins_over_basic_auth(self):
        identity = Identity(name="api", basic_auth=("u", "p"),
                            bearer_token="t")
        assert identity.request_headers()["Authorization"] == "Bearer t"


def test_csrf_hidden_field_parser_handles_attribute_order():
    from core.auth_harness import _hidden_form_fields

    html = (
        '<input value="tok-1" name="csrfmiddlewaretoken" type="hidden">'
        "<input type='hidden' name='authenticity_token' value='tok-2'>"
        '<input type="text" name="user">'
        '<input type="hidden">'
    )
    fields = _hidden_form_fields(html)
    assert fields == {"csrfmiddlewaretoken": "tok-1",
                      "authenticity_token": "tok-2"}, fields
