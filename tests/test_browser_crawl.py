"""Tests for the authenticated, deep browser_crawl.

Sessions must be verified to render as authenticated: an expired cookie
crawled as a user is a logged-out run mislabelled, the same failure
class as an expiring dalfox session reporting zero findings. Depth
follows same-origin links only — cross-origin targets are recorded,
never rendered.
"""

import asyncio
import tempfile

import modules.browser_crawl as crawl_module
from modules.browser_crawl import BrowserCrawl
from state.manager import StateManager


PAGES = {
    "https://example.com/": {
        "links": ["https://example.com/dashboard", "https://other.test/x"],
        "scripts": [], "forms": [], "source_maps": [], "dom_sinks": [],
    },
    "https://example.com/dashboard": {
        "links": ["https://example.com/settings"],
        "scripts": [], "forms": [], "scripts": [],
        "source_maps": [], "dom_sinks": [],
    },
    "https://example.com/settings": {
        "links": [], "scripts": [], "forms": [],
        "source_maps": [], "dom_sinks": [],
    },
}

RENDERED = []


async def fake_render(url, config, wait_ms=1500, cookies=None, headers=None):
    RENDERED.append({"url": url, "cookies": dict(cookies or {}),
                     "headers": dict(headers or {})})
    page = PAGES.get(url, {"links": [], "scripts": [], "forms": [],
                           "source_maps": [], "dom_sinks": []})
    return {**page, "error": None}


class FakeIdentity:
    def __init__(self, name, cookies, verified=True):
        self.name = name
        self.cookies = cookies
        self.headers = {}
        self.bearer_token = ""
        self.verified = verified


class FakeHarness:
    def __init__(self, identities):
        self._identities = identities

    def adopt_discovered(self, state, log=None):
        return 0

    async def establish_all(self, base_url):
        return [i for i in self._identities if i.verified]


def _run(monkeypatch, identities=None, crawl_cfg=None):
    tmpdir = tempfile.mkdtemp()
    state = StateManager(f"{tmpdir}/run/example.com")
    state.add_asset("url", "url:https://example.com/",
                    "https://example.com/", confidence="FIRM",
                    sources=["test"])
    config = {"target": {"domain": "example.com",
                         "base_url": "https://example.com"},
              "crawl": {"browser": dict(crawl_cfg or {})}}
    monkeypatch.setattr(crawl_module, "_playwright_available",
                        lambda: asyncio.sleep(0, result=True))
    monkeypatch.setattr(crawl_module, "_render_page", fake_render)
    monkeypatch.setattr(crawl_module, "AuthHarness",
                        lambda config: FakeHarness(identities or []))
    RENDERED.clear()
    result = asyncio.run(BrowserCrawl(state, config).run())
    return result, state


def test_anonymous_baseline_without_identities(monkeypatch):
    result, state = _run(monkeypatch)

    assert result == "done"
    # Default depth 1: the seed plus its same-origin links, nothing deeper.
    assert {r["url"] for r in RENDERED} == {"https://example.com/",
                                           "https://example.com/dashboard"}
    assert all(r["cookies"] == {} for r in RENDERED)
    summary = state.get_assets_by_type("browser_crawl_summary")[0]
    assert summary["attrs"]["contexts"][0]["identity"] == "anonymous"
    assert summary["attrs"]["contexts"][0]["authenticated"] is False


def test_verified_identity_gets_own_cookies(monkeypatch):
    identities = [FakeIdentity("alice", {"session": "abc123"})]
    result, state = _run(monkeypatch, identities=identities)

    assert result == "done"
    by_url = {}
    for entry in RENDERED:
        by_url.setdefault(entry["url"], []).append(entry["cookies"])
    assert by_url["https://example.com/"][0] == {}
    assert {"session": "abc123"} in by_url["https://example.com/"]
    names = {c["identity"] for c in
             state.get_assets_by_type("browser_crawl_summary")[0]
             ["attrs"]["contexts"]}
    assert names == {"anonymous", "alice"}


def test_unverified_identity_never_renders_authenticated(monkeypatch):
    identities = [FakeIdentity("mallory", {"session": "stale"}, verified=False)]
    result, state = _run(monkeypatch, identities=identities)

    assert result == "done"
    assert all(r["cookies"] == {} for r in RENDERED)
    names = [c["identity"] for c in
             state.get_assets_by_type("browser_crawl_summary")[0]
             ["attrs"]["contexts"]]
    assert names == ["anonymous"]


def test_depth_follows_same_origin_only(monkeypatch):
    result, state = _run(monkeypatch, crawl_cfg={"depth": 2})

    assert result == "done"
    urls = {r["url"] for r in RENDERED}
    assert urls == {"https://example.com/", "https://example.com/dashboard",
                    "https://example.com/settings"}
    # Cross-origin link recorded as an asset, never rendered.
    values = {a["value"] for a in state.get_assets_by_type("url")}
    assert "https://other.test/x" in values


def test_depth_zero_renders_seeds_only(monkeypatch):
    result, state = _run(monkeypatch, crawl_cfg={"depth": 0})

    assert result == "done"
    assert {r["url"] for r in RENDERED} == {"https://example.com/"}


def test_max_identities_caps_contexts(monkeypatch):
    identities = [FakeIdentity(f"user{i}", {"s": str(i)}) for i in range(4)]
    result, state = _run(monkeypatch, identities=identities,
                         crawl_cfg={"max_identities": 1})

    assert result == "done"
    names = [c["identity"] for c in
             state.get_assets_by_type("browser_crawl_summary")[0]
             ["attrs"]["contexts"]]
    assert names == ["anonymous", "user0"]


def test_disabled_by_config(monkeypatch):
    tmpdir = tempfile.mkdtemp()
    state = StateManager(f"{tmpdir}/run/example.com")
    config = {"target": {"domain": "example.com"},
              "crawl": {"browser": {"enabled": False}}}
    result = asyncio.run(BrowserCrawl(state, config).run())

    assert result == "skipped"
