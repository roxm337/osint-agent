"""Tests for modules/ssrf_scan.py.

The grading contract: a URL parameter is a candidate, and only a
callback distinguishes a server that fetches from one that stores or
reflects. HTTP interaction means HIGH/CONFIRMED; DNS-only means
MEDIUM/FIRM (egress without a proven fetch); a fetch error naming our
domain means MEDIUM/FIRM (attempted); silence files one aggregate LOW.
Without an OOB channel nothing is probed at all.
"""

import asyncio
import tempfile

import modules.ssrf_scan as ssrf_module
from modules.ssrf_scan import SSRFScan
from state.manager import StateManager


def _state():
    tmpdir = tempfile.mkdtemp()
    return StateManager(f"{tmpdir}/run/example.com")


def _seed_param(state, url, param):
    state.add_asset(
        "parameter", f"param:{url}:{param}", param,
        confidence="FIRM", sources=["test"],
        attrs={"url": url, "parameter": param, "source": "test"})


class FakeOOB:
    """Scripted interactions per path tag."""

    poll_interval = 0

    def __init__(self, hits=None):
        self.hits = hits or {}
        self.probed = []
        self.poll_timeout = 30.0

    async def register_callback(self, payload):
        return "corr12345678"

    def callback_url(self, corr_id, path="/"):
        return f"http://corr12345678.oob.test{path}"

    async def poll(self, corr_id):
        self.probed.append(corr_id)
        # No offset consumption: the interaction stays visible, like a
        # session log the module drains and re-reads by tag.
        return list(self.hits.get("next", []))


def _run(state, config, oob, curl_fn=None):
    import modules.ssrf_scan as mod
    module = SSRFScan(state, config)
    module.oob = lambda: oob
    calls = {}

    async def fake_curl(url, **kwargs):
        calls["url"] = url
        if curl_fn is not None:
            return await curl_fn(url, **kwargs)
        return {"status": 200, "body": "<html>ok</html>"}

    orig = mod.curl
    mod.curl = fake_curl
    try:
        result = asyncio.run(module.run())
    finally:
        mod.curl = orig
    return result, calls


def _config(**overrides):
    cfg = {"target": {"domain": "example.com",
                      "base_url": "https://example.com"},
           "modules": {"ssrf_scan": dict(overrides.get("ssrf", {}))}}
    return cfg


def test_http_callback_confirms():
    state = _state()
    _seed_param(state, "https://example.com/fetch?url=x", "url")
    oob = FakeOOB()
    oob.hits["next"] = [{"protocol": "http", "raw": "GET /ssrf-0-url HTTP/1.1"}]

    result, calls = _run(state, _config(), oob,
                         curl_fn=lambda url, **k: {"status": 200,
                                                  "body": "<html>ok</html>"})

    assert result == "done"
    from urllib.parse import unquote
    assert "corr12345678.oob.test/ssrf-0-url" in unquote(calls["url"])
    confirmed = [f for f in state.findings["findings"]
                 if f["title"] == "Blind SSRF Confirmed via OOB Callback"]
    assert len(confirmed) == 1
    assert confirmed[0]["severity"] == "HIGH"
    assert confirmed[0]["confidence"] == "CONFIRMED"
    assert confirmed[0]["verified"] is True
    assert confirmed[0]["verification"]["method"] == "oob_callback"


def test_dns_only_is_firm_egress_not_confirmed():
    state = _state()
    _seed_param(state, "https://example.com/fetch?url=x", "url")
    oob = FakeOOB()
    oob.hits["next"] = [{"protocol": "dns", "raw": "A corr12345678.oob.test"}]

    result, _ = _run(state, _config(), oob)

    assert result == "done"
    titles = [f["title"] for f in state.findings["findings"]]
    assert any("DNS Egress" in t for t in titles)
    assert not any("Confirmed" in t for t in titles)
    egress = [f for f in state.findings["findings"] if "DNS Egress" in f["title"]][0]
    assert egress["severity"] == "MEDIUM"
    assert egress["confidence"] == "FIRM"


def test_fetch_error_naming_our_domain_is_attempted():
    state = _state()
    _seed_param(state, "https://example.com/fetch?url=x", "url")
    oob = FakeOOB()

    async def error_curl(url, **kwargs):
        return {"status": 500,
                "body": "failed to fetch http://corr12345678.oob.test/ssrf-0-url: "
                        "getaddrinfo failed"}

    result, _ = _run(state, _config(), oob, curl_fn=error_curl)

    assert result == "done"
    attempted = [f for f in state.findings["findings"]
                 if "Attempted Fetch" in f["title"]]
    assert len(attempted) == 1
    assert attempted[0]["severity"] == "MEDIUM"
    assert attempted[0]["confidence"] == "FIRM"


def test_generic_error_without_our_domain_is_silence():
    """A bare 'timeout' proves nothing — the domain must be implicated."""
    state = _state()
    _seed_param(state, "https://example.com/fetch?url=x", "url")
    oob = FakeOOB()

    async def slow_curl(url, **kwargs):
        return {"status": 504, "body": "gateway timeout, try again later"}

    result, _ = _run(state, _config(), oob, curl_fn=slow_curl)

    assert result == "done"
    titles = [f["title"] for f in state.findings["findings"]]
    assert any("no server-side fetch" in t for t in titles)
    assert not any("Attempted" in t or "Confirmed" in t for t in titles)


def test_silence_files_one_aggregate_low():
    state = _state()
    _seed_param(state, "https://example.com/a?url=x", "url")
    _seed_param(state, "https://example.com/b?src=x", "src")

    result, _ = _run(state, _config(), FakeOOB())

    assert result == "done"
    assert len(state.findings["findings"]) == 1
    finding = state.findings["findings"][0]
    assert finding["severity"] == "LOW"
    assert finding["confidence"] == "TENTATIVE"


def test_without_oob_nothing_is_probed():
    """No channel means no requests: candidates file as one LOW and the
    target is never asked to fetch anything."""
    state = _state()
    _seed_param(state, "https://example.com/fetch?url=x", "url")
    sent = []

    async def watching_curl(url, **kwargs):
        sent.append(url)
        return {"status": 200, "body": "ok"}

    result, _ = _run(state, _config(), None, curl_fn=watching_curl)

    assert result == "done"
    assert sent == [], "without OOB no probe may leave the scanner"
    assert len(state.findings["findings"]) == 1
    assert "untested" in state.findings["findings"][0]["title"]


def test_non_url_params_are_ignored():
    state = _state()
    _seed_param(state, "https://example.com/search?q=x", "q")

    result, _ = _run(state, _config(), FakeOOB())

    assert result == "skipped"
    assert state.findings["findings"] == []


def test_disabled_by_config():
    state = _state()
    _seed_param(state, "https://example.com/fetch?url=x", "url")

    result, _ = _run(state, _config(ssrf={"enabled": False}), FakeOOB())

    assert result == "skipped"
