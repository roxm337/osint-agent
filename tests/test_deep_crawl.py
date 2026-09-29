"""Tests for modules/deep_crawl.py.

The defect here is narrower than in content_discovery. A crawled URL is a real
observation — the crawler followed a link to it — so FIRM on the asset's
existence is correct and is left alone. What was wrong is the claim built on
top of it: "Crawl Discovered High-Value Endpoints" at LOW/FIRM asserted as fact
what is a substring guess, and the matchers were unanchored, so
/blog/manage-your-account scored as an admin endpoint.

These tests pin the segment matching, and that the finding now reads as
discovery rather than as a weakness.

No crawler fixture: katana and hakrawler are external binaries, and what is
being pinned is the classification of URLs they return, not link-following.
"""

import tempfile
from unittest.mock import AsyncMock, patch

import pytest

from modules.deep_crawl import DeepCrawl, _looks_admin, _looks_api
from state.manager import StateManager


def _config(depth=2):
    return {
        "target": {"domain": "example.test", "base_url": "https://example.test"},
        "auth": {"identities": []},
        "waf": {"block_codes": [429, 503]},
        "crawl": {"depth": depth},
        "modules": {},
    }


def _run(urls, tools=("katana",), module_cfg=None):
    import asyncio

    state = StateManager(tempfile.mkdtemp())
    module = DeepCrawl(state, _config())
    module.target = "https://example.test"

    async def fake_crawl(target, depth=2, timeout=180):
        return list(urls)

    with patch("modules.deep_crawl.tool_available",
               side_effect=lambda n: n in tools), \
         patch("modules.deep_crawl.katana_crawl", new=AsyncMock(
             side_effect=fake_crawl)), \
         patch("modules.deep_crawl.hakrawler_crawl", new=AsyncMock(
             side_effect=fake_crawl)):
        result = asyncio.run(module.run())
    return state, result


def _findings(state):
    return state.findings["findings"]


# --- the false positives ------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://x.test/blog/manage-your-account",
    "https://x.test/docs/dashboard-setup",
    "https://x.test/help/console-commands",
    "https://x.test/chapter/api-tales",
    "https://x.test/news/administrators-meet",
    "https://x.test/post/internals-of-c",
    "https://x.test/shop/management-guide",
])
def test_ordinary_pages_are_not_admin_or_api(url):
    """The regression: unanchored substring matching called a blog post about
    managing your account an admin endpoint."""
    assert not _looks_admin(url)
    assert not _looks_api(url)


@pytest.mark.parametrize("url", [
    "https://x.test/admin",
    "https://x.test/admin/",
    "https://x.test/wp-admin/index.php",
    "https://x.test/manage/orders",
    "https://x.test/api/v1/users",
    "https://x.test/graphql",
    "https://x.test/internal/status",
    "https://x.test/actuator/env",
])
def test_real_admin_and_api_paths_are_matched(url):
    assert _looks_admin(url) or _looks_api(url)


def test_admin_and_api_are_distinguished():
    assert _looks_admin("https://x.test/admin/users")
    assert not _looks_api("https://x.test/admin/users")
    assert _looks_api("https://x.test/api/users")
    assert not _looks_admin("https://x.test/api/users")


def test_query_string_is_not_matched():
    """`?next=/admin` is a parameter, not an admin path."""
    assert not _looks_admin("https://x.test/login?next=/admin")
    assert not _looks_api("https://x.test/callback?u=/api/v1")


def test_fragments_and_trailing_slashes():
    assert _looks_admin("https://x.test/panel/")
    assert _looks_admin("https://x.test/a/b/c/admin")


# --- the finding's claim ------------------------------------------------

def test_finding_is_info_and_tentative():
    state, _ = _run(["https://x.test/admin", "https://x.test/api/v1/users"])
    findings = _findings(state)
    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["confidence"] == "TENTATIVE"


def test_finding_does_not_claim_high_value():
    state, _ = _run(["https://x.test/admin"])
    title = _findings(state)[0]["title"]
    assert "High-Value" not in title
    assert "high-value" not in title
    assert "API-like" in title or "admin-like" in title


def test_finding_says_it_is_not_a_weakness():
    state, _ = _run(["https://x.test/admin"])
    description = _findings(state)[0]["description"]
    assert "not a weakness" in description
    assert "should have been" in description


def test_assets_stay_firm_on_existence():
    """A crawled URL was followed by the crawler, so its existence is
    established. That claim is legitimate and must not be weakened."""
    state, _ = _run(["https://x.test/api/v1/users"])
    assets = state.get_assets_by_type("api_endpoint")
    assert len(assets) == 1
    assert assets[0]["confidence"] == "FIRM"


def test_api_paths_become_api_endpoint_assets():
    state, _ = _run([
        "https://x.test/api/v1/users",
        "https://x.test/blog/post-1",
    ])
    assert len(state.get_assets_by_type("api_endpoint")) == 1
    assert len(state.get_assets_by_type("url")) == 1


def test_no_finding_for_ordinary_pages_only():
    state, _ = _run([
        "https://x.test/blog/manage-your-account",
        "https://x.test/about",
        "https://x.test/contact",
    ])
    assert _findings(state) == []


def test_summary_counts():
    state, _ = _run([
        "https://x.test/api/v1",
        "https://x.test/admin",
        "https://x.test/about",
    ])
    attrs = state.get_assets_by_type("crawl_summary")[0]["attrs"]
    assert attrs["urls"] == 3
    assert attrs["api_like"] == 1
    assert attrs["admin_like"] == 1


def test_skips_without_crawlers():
    state, result = _run([], tools=())
    assert result == "skipped"


def test_non_http_urls_are_ignored():
    state, _ = _run(["mailto:a@b.test", "javascript:void(0)", "ftp://x.test/f"])
    assert state.get_assets_by_type("crawl_summary")[0]["attrs"]["urls"] == 0
