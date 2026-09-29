"""Tests for modules/content_discovery.py.

The regression being pinned is a severity inversion. `classify_content_hit`
returned "protected" for 401/403, and the finding was built from every hit
whose category was not "discovered" — so a 403, meaning access control worked,
fed a MEDIUM finding titled "Interesting Web Paths Discovered". A 200 on /admin
and a 403 on /admin landed in the same object.

The second fix is the wildcard filter. ffuf was run without `-ac`, and its own
`-fc 404` filter cannot catch a site that answers 200 for everything, so a SPA
catch-all produced a hit for the whole wordlist.

There is no live ffuf fixture: the binary is external and the interesting
behaviour is the classification and the baseline comparison, both of which are
pure functions of ffuf's own output. Mocking the tool is what makes this a test
of the module rather than of ffuf.
"""

import tempfile
from unittest.mock import AsyncMock, patch

import pytest

from modules.content_discovery import (
    ContentDiscovery,
    classify_content_hit,
)
from state.manager import StateManager


def _config(words=("admin", "login", "backup"), module_cfg=None):
    return {
        "target": {"domain": "example.test", "base_url": "https://example.test"},
        "auth": {"identities": []},
        "waf": {"block_codes": [429, 503]},
        "wordlists": {"content_discovery": list(words)},
        "modules": {"content_discovery": dict(module_cfg or {})},
    }


def _ffuf_json(hits):
    import json
    return json.dumps({
        "results": [
            {
                "url": h["url"], "status": h.get("status", 200),
                "length": h.get("length", 500),
                "words": h.get("words", 50),
                "lines": h.get("lines", 10),
                "content-type": h.get("content_type", "text/html"),
                "redirectlocation": h.get("redirectlocation", ""),
            }
            for h in hits
        ]
    })


def _run(hits, words=("admin", "login", "backup"), module_cfg=None, present=True):
    import asyncio

    state = StateManager(tempfile.mkdtemp())
    module = ContentDiscovery(state, _config(words, module_cfg))
    module.target = "https://example.test"

    async def fake_ffuf(url_template, wordlist, output_file, rate=None,
                        timeout=240, extra_args=None):
        from pathlib import Path
        Path(output_file).write_text(_ffuf_json(hits))
        return {"available": present, "exit_code": 0, "stderr": "",
                "extra_args": extra_args or []}

    with patch("modules.content_discovery.tool_available",
               return_value=present), \
         patch("modules.content_discovery.ffuf", new=AsyncMock(
             side_effect=fake_ffuf)):
        result = asyncio.run(module.run())
    return state, result, module


def _findings(state):
    return state.findings["findings"]


# --- the severity inversion ---------------------------------------------

def test_403_is_info_not_a_vulnerability():
    """A 403 means the access control held. The old code fed it a MEDIUM."""
    state, _, _ = _run([{"url": "https://example.test/admin", "status": 403}])
    findings = _findings(state)
    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert "not a weakness" in findings[0]["description"]
    assert "No action required" in findings[0]["remediation"]


def test_200_on_sensitive_name_is_medium():
    state, _, _ = _run([{"url": "https://example.test/backup", "status": 200}])
    findings = _findings(state)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["confidence"] == "CONFIRMED"


def test_200_outranks_403():
    """Both used to produce one MEDIUM finding. Now only the 200 does."""
    state, _, _ = _run([
        {"url": "https://example.test/admin", "status": 200, "length": 9000},
        {"url": "https://example.test/backup", "status": 403, "length": 300},
    ])
    findings = {f["severity"] for f in _findings(state)}
    assert findings == {"MEDIUM", "INFO"}


def test_plain_200_produces_no_finding():
    state, _, _ = _run([{"url": "https://example.test/about", "status": 200}])
    assert _findings(state) == []


def test_redirect_produces_no_finding():
    state, _, _ = _run([{"url": "https://example.test/manage",
                         "status": 302, "length": 0}])
    assert _findings(state) == []


def test_assets_are_still_recorded_for_every_real_hit():
    state, _, _ = _run([
        {"url": "https://example.test/admin", "status": 200, "length": 9000},
        {"url": "https://example.test/backup", "status": 403, "length": 300},
        {"url": "https://example.test/about", "status": 200, "length": 1200},
    ])
    paths = {a["value"] for a in state.get_assets_by_type("web_path")}
    assert len(paths) == 3


# --- the wildcard filter ------------------------------------------------

def test_catch_all_site_yields_no_findings():
    """Every word returns the same 200 page. Without calibration the old module
    reported a MEDIUM for the entire wordlist."""
    state, _, _ = _run([
        {"url": f"https://example.test/{w}", "status": 200, "length": 5000,
         "words": 400}
        for w in ("admin", "login", "backup", "config", "env", "secret",
                  "test", "upload", "internal", "staging")
    ])
    assert _findings(state) == []


def test_catch_all_hits_are_filtered_from_assets():
    state, _, _ = _run([
        {"url": f"https://example.test/{w}", "status": 200, "length": 5000,
         "words": 400}
        for w in ("admin", "login", "backup", "config", "env", "secret",
                  "test", "upload", "internal", "staging")
    ])
    assert state.get_assets_by_type("web_path") == []


def test_genuine_hit_survives_among_soft_404s():
    """The realistic case: mostly catch-all, one real page. The real one must
    survive the filter."""
    hits = [{"url": f"https://example.test/{w}", "status": 200,
             "length": 5000, "words": 400}
            for w in ("login", "config", "env", "secret", "test", "upload",
                      "internal", "staging", "temp")]
    hits.append({"url": "https://example.test/backup", "status": 200,
                 "length": 88000, "words": 9000})
    state, _, _ = _run(hits)
    paths = {a["value"] for a in state.get_assets_by_type("web_path")}
    assert paths == {"https://example.test/backup"}
    assert _findings(state)[0]["severity"] == "MEDIUM"


def test_403_is_not_mistaken_for_wildcard():
    """A 403 differs from a 200 catch-all by status alone, so it must survive
    even with an identical body length. Four identical 200s make the catch-all
    unambiguous."""
    hits = [{"url": f"https://example.test/{w}", "status": 200,
             "length": 5000, "words": 400}
            for w in ("login", "panel", "console", "backend")]
    hits.append({"url": "https://example.test/admin", "status": 403,
                 "length": 5000, "words": 400})
    state, _, _ = _run(hits)
    paths = {a["value"] for a in state.get_assets_by_type("web_path")}
    assert paths == {"https://example.test/admin"}


def test_small_majority_is_not_treated_as_baseline():
    """A minority of identical responses is not a catch-all. Here three
    genuine pages differ from each other and two share a shape, so the
    majority is only 2 of 5 and nothing should be discarded."""
    hits = [{"url": f"https://example.test/p{i}", "status": 200,
             "length": 5000 + i, "words": 400} for i in range(3)]
    hits += [{"url": f"https://example.test/{w}", "status": 200,
              "length": 5000, "words": 400}
             for w in ("admin", "login")]
    state, _, _ = _run(hits)
    paths = {a["value"] for a in state.get_assets_by_type("web_path")}
    assert len(paths) == 5


# --- classification and filter units ----------------------------------

@pytest.mark.parametrize("url,status,expected", [
    ("https://x.test/admin", 200, "served"),
    ("https://x.test/.env", 200, "served"),
    ("https://x.test/backup.sql", 200, "served"),
    ("https://x.test/wp-config.php", 200, "served"),
    ("https://x.test/admin", 403, "protected"),
    ("https://x.test/admin", 401, "protected"),
    ("https://x.test/manage", 302, "redirected"),
    ("https://x.test/about", 200, "discovered"),
    ("https://x.test/blog/post-1", 200, "discovered"),
    ("https://x.test/", 204, "discovered"),
])
def test_classify(url, status, expected):
    assert classify_content_hit({"url": url, "status": status}) == expected




# --- config and skip paths ---------------------------------------------

def test_disabled_by_config():
    state, result, _ = _run([{"url": "https://example.test/admin"}],
                            module_cfg={"enabled": False})
    assert result == "skipped"
    assert _findings(state) == []


def test_skips_without_ffuf():
    state, result, _ = _run([], present=False)
    assert result == "skipped"


def test_skips_without_wordlist():
    state, result, _ = _run([], words=())
    assert result == "skipped"


def test_autocalibration_is_requested():
    """The fix is partly in how ffuf is invoked, so pin the argument."""
    state = StateManager(tempfile.mkdtemp())
    module = ContentDiscovery(state, _config())
    module.target = "https://example.test"
    mock_ffuf = AsyncMock(
        return_value={"available": True, "exit_code": 0, "stderr": ""})
    with patch("modules.content_discovery.tool_available", return_value=True), \
         patch("modules.content_discovery.ffuf", mock_ffuf):
        import asyncio
        asyncio.run(module.run())
    assert "-ac" in mock_ffuf.await_args.kwargs.get("extra_args", [])


def test_summary_asset_counts_by_category():
    state, _, _ = _run([
        {"url": "https://example.test/backup", "status": 200, "length": 9000,
         "words": 900},
        {"url": "https://example.test/admin", "status": 403, "length": 400,
         "words": 30},
        {"url": "https://example.test/manage", "status": 302, "length": 0},
        {"url": "https://example.test/about", "status": 200, "length": 1500,
         "words": 150},
    ])
    attrs = state.get_assets_by_type("content_discovery")[0]["attrs"]
    assert attrs["served"] == 1
    assert attrs["protected"] == 1
    assert attrs["redirected"] == 1
    assert attrs["hits"] == 4
