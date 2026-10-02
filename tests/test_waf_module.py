"""Tests for the WAF mapper's path classification.

`waf_mapping` filed "WAF Gap: Sensitive Paths Allowed" (MEDIUM, CONFIRMED)
against OWASP Juice Shop: a target with no WAF at all, on whose origin
`/.env`, `/wp-config.php` and `/.git/config` each return the same 9393-byte
`index.html` as `/`. Three sensitive paths "allowed" by rules that do not
exist, all three evidence of the SPA shell.

The shared fingerprinting in `core.response_fingerprint` exists precisely so
that no module repeats this — `response_fingerprint`'s own docstring says it
was written because the check "did not propagate to `fast_exposure_scan`,
`misconfig_probes` or `cms_deep_scan`". `waf_mapping` was the one it missed.
"""

import asyncio
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import pytest

from core.site_profile import clear_profiles
from modules.waf_module import WAFMapping
from state.manager import StateManager

SHELL = "<html><body>spa shell for every unknown path</body></html>"


@pytest.fixture(autouse=True)
def _no_cached_profiles():
    """Profiles are cached per origin across the process; two tests must not
    share one baseline."""
    clear_profiles()
    yield
    clear_profiles()


def _path_of(url: str) -> str:
    return urlparse(url).path or "/"


def _state(tmp_path):
    return StateManager(str(tmp_path / "run" / "example.com"))


def _patch_responses(monkeypatch, responses, default=(200, SHELL, "text/html")):
    """Serve `responses` through both HTTP entry points the module uses."""
    seen = []

    async def fake_http_get(self, url, **kwargs):
        status, body, ct = responses.get(_path_of(url), default)
        seen.append(_path_of(url))
        return {"status": status, "body": body, "content_type": ct}

    async def fake_curl(url, **kwargs):
        status, body, ct = responses.get(_path_of(url), default)
        seen.append(_path_of(url))
        return {"status": status, "body": body, "content_type": ct}

    monkeypatch.setattr(WAFMapping, "http_get", fake_http_get)
    monkeypatch.setattr("modules.waf_module.curl", fake_curl)
    return seen


def test_a_catch_all_200_is_not_an_allowed_sensitive_path(monkeypatch, tmp_path):
    """The regression: every unknown path is the homepage, so no path was
    served, so no WAF allowed anything."""
    _patch_responses(monkeypatch, {"/": (200, SHELL, "text/html")})
    state = _state(tmp_path)

    result = asyncio.run(WAFMapping(state, {"target": {"domain": "example.com"}}).run())

    assert result == "done"
    assert state.findings["findings"] == [], \
        "a catch-all must not manufacture a WAF gap"


def test_a_distinct_sensitive_response_still_reports_a_gap(monkeypatch, tmp_path):
    """The other half: filtering the catch-all must not swallow a real gap.
    A WAF blocks one sensitive path and serves another's own content."""
    _patch_responses(monkeypatch, {
        "/": (200, SHELL, "text/html"),
        "/.env": (503, "blocked by waf", "text/plain"),
        "/wp-config.php": (200, "<?php define('DB_PASSWORD', 'x');", "text/html"),
    })
    state = _state(tmp_path)

    result = asyncio.run(WAFMapping(state, {"target": {"domain": "example.com"}}).run())

    assert result == "done"
    titles = [f["title"] for f in state.findings["findings"]]
    assert "WAF Gap: Sensitive Paths Allowed" in titles


def test_no_waf_means_no_gap_even_when_paths_serve_their_own_content(
        monkeypatch, tmp_path):
    """A gap needs a WAF to be in. Without one the finding is a claim about
    a rule set that does not exist."""
    _patch_responses(monkeypatch, {
        "/": (200, SHELL, "text/html"),
        "/wp-config.php": (200, "<?php define('DB_PASSWORD', 'x');", "text/html"),
        "/.env": (200, "APP_KEY=base64:abc", "text/plain"),
    })
    state = _state(tmp_path)

    result = asyncio.run(WAFMapping(state, {"target": {"domain": "example.com"}}).run())

    assert result == "done"
    titles = [f["title"] for f in state.findings["findings"]]
    assert "WAF Gap: Sensitive Paths Allowed" not in titles
