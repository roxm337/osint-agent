"""Tests for the pooled aiohttp HTTP engine.

The engine replaced a per-request `curl` subprocess, so the important property
is not "does it work" but "does it still look exactly like the wrapper it
replaced". These tests pin that contract: the return shape for all four output
modes, the raw-string header block that three call sites parse, and the
fail-open `{"status": 0}` shape on transport errors.

Network calls are served by a local aiohttp test server, so the suite stays
offline and deterministic. The project has no pytest-asyncio plugin, so each
test runs its coroutine through `asyncio.run()` inside the shared harness —
the same convention the rest of the suite uses.
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.wrappers as wrappers
from tools.http_engine import CookieJar, HttpEngine, _charset_from, _header_block


# ── Local test server ────────────────────────────────────────────


class _Server:
    """Minimal aiohttp app used to exercise the engine without internet."""

    def __init__(self):
        from aiohttp import web
        self.web = web
        self.app = web.Application()
        self.app.router.add_get("/", self._index)
        self.app.router.add_get("/redirect", self._redirect)
        self.app.router.add_get("/set-cookie", self._set_cookie)
        self.app.router.add_get("/whoami", self._whoami)
        self.app.router.add_get("/latin", self._latin)
        self.app.router.add_get("/big", self._big)
        self.app.router.add_post("/echo", self._echo)
        self.hits = 0

    async def _index(self, request):
        self.hits += 1
        return self.web.Response(
            text="hello world",
            headers={"X-Custom": "yes", "Content-Type": "text/plain"},
        )

    async def _redirect(self, request):
        raise self.web.HTTPFound("/")

    async def _set_cookie(self, request):
        resp = self.web.Response(text="ok")
        resp.set_cookie("sid", request.query.get("sid", "anon"))
        return resp

    async def _whoami(self, request):
        return self.web.json_response({"sid": request.cookies.get("sid", "none")})

    async def _latin(self, request):
        return self.web.Response(
            body="café".encode("latin-1"),
            headers={"Content-Type": "text/plain; charset=latin-1"},
        )

    async def _big(self, request):
        size = int(request.query.get("size", 1000))
        return self.web.Response(body=b"x" * size,
                                 headers={"Content-Type": "application/octet-stream"})

    async def _echo(self, request):
        return self.web.json_response({"method": request.method,
                                       "body": await request.text()})


def _harness(fn, *args, **kwargs):
    """Run an async test body against a live loopback server and a fresh engine."""
    from aiohttp import web

    async def runner():
        srv = _Server()
        runner_ = web.AppRunner(srv.app)
        await runner_.setup()
        site = web.TCPSite(runner_, "127.0.0.1", 0)
        await site.start()
        port = runner_.addresses[0][1]
        # The server binds 127.0.0.1, and aiohttp refuses cookies from bare IP
        # hosts by default — the flag is what makes session cookies stick here.
        engine = HttpEngine(cookies_from_ip_hosts=True)
        try:
            # `args` carries the test instance pytest passes as the first
            # positional to a method, so it has to lead.
            return await fn(*args, f"http://127.0.0.1:{port}", srv, engine)
        finally:
            await engine.close()
            await wrappers.close_engine()
            await runner_.cleanup()

    return asyncio.run(runner())


def served(fn):
    """Decorate an async `test_*(base, srv, engine)` body for asyncio.run().

    Deliberately does not use functools.wraps: copying `__wrapped__` makes
    pytest inspect the original signature and then demand fixtures named
    `base`, `srv`, and `engine`. The names are carried over explicitly
    instead, and the signature is erased.
    """
    def wrapper(*args, **kwargs):
        return _harness(fn, *args, **kwargs)
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


# ── Legacy contract parity ───────────────────────────────────────


class TestLegacyContract:
    """The old curl wrapper's return shape is load-bearing at 33 call sites."""

    @served
    async def test_status_mode_returns_code_and_empty_body(self, base, srv, engine):
        result = await engine.request(f"{base}/", output="status")
        assert result["status"] == 200
        assert result["body"] == ""

    @served
    async def test_body_mode_returns_body(self, base, srv, engine):
        result = await engine.request(f"{base}/", output="body")
        assert result["status"] == 200
        assert result["body"] == "hello world"

    @served
    async def test_full_mode_headers_are_a_raw_parseable_string(self, base, srv, engine):
        """actions/auth/jwt.py, modules/login_enum.py and tech_detect.py all
        do `result["headers"].splitlines()` and partition on ":". A dict here
        would break all three."""
        result = await engine.request(f"{base}/", output="full")
        assert isinstance(result["headers"], str)
        parsed = {}
        for line in result["headers"].splitlines():
            if ":" in line and not line.startswith("HTTP/"):
                k, _, v = line.partition(":")
                parsed[k.strip().lower()] = v.strip()
        assert parsed["x-custom"] == "yes"
        assert parsed["content-type"].startswith("text/plain")

    @served
    async def test_headers_mode_puts_headers_in_body(self, base, srv, engine):
        result = await engine.request(f"{base}/", output="headers")
        assert result["status"] == 200
        assert "X-Custom: yes" in result["body"]

    @served
    async def test_always_exposes_the_legacy_keys(self, base, srv, engine):
        """Every mode must carry the keys callers reach for."""
        for mode in ("status", "headers", "body", "full"):
            result = await engine.request(f"{base}/", output=mode)
            assert isinstance(result["status"], int)
            assert isinstance(result["body"], str)

    @served
    async def test_adds_timing_which_curl_never_returned(self, base, srv, engine):
        """curl could not report elapsed time, so DifferentialAnalyzer was
        fingerprinting every response with time_ms=0."""
        result = await engine.request(f"{base}/", output="body")
        assert result["time_ms"] > 0

    def test_transport_failure_is_fail_open_not_exception(self):
        """The old wrapper returned status 0 on error. Nothing may raise."""
        async def body():
            async with HttpEngine() as engine:
                return await engine.request("http://127.0.0.1:1/",
                                            output="body", timeout=2)
        result = asyncio.run(body())
        assert result["status"] == 0
        assert result["body"] == ""
        assert result["error"]

    @served
    async def test_post_body_is_sent(self, base, srv, engine):
        result = await engine.request(f"{base}/echo", method="POST",
                                      data="a=1&b=2", output="body")
        payload = json.loads(result["body"])
        assert payload["method"] == "POST"
        assert payload["body"] == "a=1&b=2"


# ── Redirects ────────────────────────────────────────────────────


class TestRedirects:
    @served
    async def test_follows_by_default_and_records_hops(self, base, srv, engine):
        result = await engine.request(f"{base}/redirect", output="body")
        assert result["status"] == 200
        assert result["body"] == "hello world"
        assert len(result["history"]) == 1
        assert result["history"][0]["status"] == 302

    @served
    async def test_final_url_is_reported(self, base, srv, engine):
        result = await engine.request(f"{base}/redirect", output="status")
        assert result["url"].endswith("/")

    @served
    async def test_follow_redirects_false_stops_at_hop(self, base, srv, engine):
        result = await engine.request(f"{base}/redirect", output="status",
                                      follow_redirects=False)
        assert result["status"] == 302


# ── Connection pooling ───────────────────────────────────────────


class TestPooling:
    @served
    async def test_repeated_requests_reuse_one_connection(self, base, srv, engine):
        for _ in range(5):
            await engine.request(f"{base}/", output="body")
        assert engine.connections_opened == 1
        assert engine.connections_reused == 4

    @served
    async def test_pool_survives_across_identities(self, base, srv, engine):
        """One connector backs every identity, so isolation does not mean
        paying a handshake per account."""
        await engine.request(f"{base}/", output="body", identity="user_a")
        await engine.request(f"{base}/", output="body", identity="user_b")
        assert engine.connections_opened == 1

    @served
    async def test_stats_reports_identity_list(self, base, srv, engine):
        await engine.request(f"{base}/", output="status", identity="solo")
        assert "solo" in engine.stats()["identities"]


# ── Per-identity cookie isolation ────────────────────────────────


class TestCookieIsolation:
    @served
    async def test_two_identities_do_not_share_cookies(self, base, srv, engine):
        """The precondition for two-account IDOR testing."""
        await engine.request(f"{base}/set-cookie?sid=AAA", identity="user_a")
        await engine.request(f"{base}/set-cookie?sid=BBB", identity="user_b")
        a = await engine.request(f"{base}/whoami", output="body", identity="user_a")
        b = await engine.request(f"{base}/whoami", output="body", identity="user_b")
        assert json.loads(a["body"])["sid"] == "AAA"
        assert json.loads(b["body"])["sid"] == "BBB"

    @served
    async def test_cookies_persist_within_an_identity(self, base, srv, engine):
        await engine.request(f"{base}/set-cookie?sid=KEEP", identity="u")
        again = await engine.request(f"{base}/whoami", output="body", identity="u")
        assert json.loads(again["body"])["sid"] == "KEEP"

    @served
    async def test_seeded_cookies_are_sent(self, base, srv, engine):
        engine.set_cookies({"sid": "SEEDED"}, identity="seeded")
        assert engine.cookies_for("seeded")["sid"] == "SEEDED"
        result = await engine.request(f"{base}/whoami", output="body", identity="seeded")
        assert json.loads(result["body"])["sid"] == "SEEDED"

    @served
    async def test_forget_identities_clears_cookies_but_keeps_pool(self, base, srv, engine):
        await engine.request(f"{base}/set-cookie?sid=GONE", identity="u")
        session = engine.session("u")
        engine.forget_identities()
        assert engine.cookies_for("u") == {}
        # The pool survives — this is a cookie reset, not a connection reset.
        assert engine.connections_opened == 1
        # The session is reused rather than orphaned: swapping it out leaks an
        # unclosed ClientSession and re-dials on the next request.
        assert engine.session("u") is session
        assert not session.closed
        assert engine.cookies_for("u") == {}

    @served
    async def test_forget_identities_resets_every_identity(self, base, srv, engine):
        for identity in ("alice", "bob"):
            engine.set_cookies({"sid": identity.upper()}, identity=identity)
        engine.forget_identities()
        for identity in ("alice", "bob"):
            assert engine.cookies_for(identity) == {}, identity
        # A request after the reset must not replay a pre-reset cookie.
        result = await engine.request(f"{base}/whoami", output="body", identity="alice")
        assert json.loads(result["body"])["sid"] == "none"

    def test_normalise_defaults_to_shared_identity(self):
        assert CookieJar.normalise(None) == "default"
        assert CookieJar.normalise("") == "default"
        assert CookieJar.normalise("user_a") == "user_a"


# ── Body handling ────────────────────────────────────────────────


class TestBodyHandling:
    @served
    async def test_large_body_is_capped_and_flagged(self, base, srv, engine):
        result = await engine.request(f"{base}/big?size=5000", output="body",
                                      max_body=1000)
        assert len(result["body"]) == 1000
        assert result["truncated"] is True

    @served
    async def test_body_under_cap_is_not_flagged(self, base, srv, engine):
        result = await engine.request(f"{base}/", output="body", max_body=1000)
        assert "truncated" not in result

    @served
    async def test_non_utf8_charset_is_decoded(self, base, srv, engine):
        result = await engine.request(f"{base}/latin", output="body")
        assert "café" in result["body"]

    def test_charset_parser_handles_quoting_and_junk(self):
        assert _charset_from("text/html; charset=latin-1") == "latin-1"
        assert _charset_from('text/html; charset="utf-8"') == "utf-8"
        assert _charset_from("text/html") == "utf-8"
        # An unknown charset must degrade, not raise.
        assert _charset_from("text/html; charset=not-a-real-codec") == "utf-8"


# ── Header rendering ─────────────────────────────────────────────


class TestHeaderBlock:
    def test_renders_key_value_lines(self):
        assert _header_block({"Server": "nginx", "X-A": "1"}) == "Server: nginx\nX-A: 1"

    def test_none_yields_empty_string(self):
        assert _header_block(None) == ""


# ── Loop lifecycle ───────────────────────────────────────────────


class TestLoopLifecycle:
    def test_survives_repeated_asyncio_run(self):
        """The suite calls asyncio.run() per test, so a cached connector bound
        to a dead loop must be rebuilt rather than raising."""
        async def body():
            from aiohttp import web
            srv = _Server()
            runner = web.AppRunner(srv.app)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            base = f"http://127.0.0.1:{runner.addresses[0][1]}"
            engine = HttpEngine()
            try:
                for _ in range(3):
                    result = await engine.request(f"{base}/", output="status")
                    assert result["status"] == 200
            finally:
                await engine.close()
                await runner.cleanup()
        asyncio.run(body())

    def test_close_is_idempotent(self):
        async def body():
            engine = HttpEngine()
            await engine.close()
            await engine.close()
        asyncio.run(body())

    @served
    async def test_context_manager_closes(self, base, srv, engine):
        async with HttpEngine() as eng:
            await eng.request(f"{base}/", output="status")
        assert eng._connector is None


# ── Wrapper delegation ───────────────────────────────────────────


class TestWrapperDelegation:
    @served
    async def test_curl_uses_the_pool(self, base, srv, engine):
        for _ in range(4):
            result = await wrappers.curl(f"{base}/", output="body")
            assert result["status"] == 200
        assert wrappers.engine_stats()["connections_opened"] == 1

    @served
    async def test_curl_with_status_returns_body_and_status(self, base, srv, engine):
        result = await wrappers.curl_with_status(f"{base}/")
        assert result["status"] == 200
        assert result["body"] == "hello world"
        assert result["time_ms"] > 0

    @served
    async def test_http1_0_falls_back_to_subprocess(self, base, srv, engine):
        """aiohttp cannot speak HTTP/1.0, so waf_module's protocol probe must
        still reach the curl path rather than break."""
        result = await wrappers.curl(f"{base}/", output="status", http1_0=True)
        assert result["status"] == 200

    @served
    async def test_identity_argument_is_threaded_through(self, base, srv, engine):
        await wrappers.curl(f"{base}/set-cookie?sid=X", identity="acct1")
        assert "acct1" in wrappers.engine_stats()["identities"]

    def test_engine_stats_when_engine_never_started(self):
        assert wrappers.engine_stats()["requests"] == 0

