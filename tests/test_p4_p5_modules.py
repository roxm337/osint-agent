"""Tests for P4/P5 roadmap modules."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules import MODULE_REGISTRY, STAGE_ORDER, get_all_module_ids
from modules.browser_crawl import BrowserCrawl
from modules.fast_exposure_scan import FastExposureScan
from modules.js_analysis import extract_dom_sinks
from modules.mobile_assets import MobileAssets
from modules.misconfig import MisconfigProbes
from modules.nuclei_scan import NucleiScan
from modules.parameter_discovery import ParameterDiscovery
from modules.xss_scan import XSSScan
from state.manager import StateManager


async def _async_value(value):
    return value


def test_parameter_discovery_uses_existing_urls_without_tools():
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    state.add_asset(
        "url",
        "url:https://example.com/search?q=test&next=/admin",
        "https://example.com/search?q=test&next=/admin",
    )

    result = asyncio.run(
        ParameterDiscovery(state, {"target": {"domain": "example.com"}}).run()
    )

    assert result == "done"
    params = state.get_assets_by_type("parameter")
    assert {item["value"] for item in params} == {"q", "next"}
    assert state.findings["findings"][0]["title"] == "Sensitive Parameter Names Discovered"


def test_xss_scan_detects_unsanitized_reflection_without_dalfox(monkeypatch):
    import modules.xss_scan as xss_module

    monkeypatch.setattr(xss_module, "tool_available", lambda name: False)
    monkeypatch.setattr(xss_module, "_playwright_available", lambda: _async_value(False))

    async def fake_curl(url, **kwargs):
        from urllib.parse import parse_qs, urlparse, unquote

        params = parse_qs(urlparse(url).query)
        value = unquote(params.get("q", [""])[0])
        return {"status": 200, "body": f"<html><body>{value}</body></html>"}

    monkeypatch.setattr(xss_module, "curl", fake_curl)
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    state.add_asset(
        "parameter",
        "param:https://example.com/search:q",
        "q",
        attrs={"url": "https://example.com/search"},
    )

    result = asyncio.run(XSSScan(state, {"target": {"domain": "example.com"}}).run())

    assert result == "done"
    assert state.findings["findings"][0]["title"] == "Reflected XSS Candidate"
    assert state.findings["findings"][0]["confidence"] == "FIRM"


def test_xss_scan_browser_confirmation(monkeypatch):
    import modules.xss_scan as xss_module

    monkeypatch.setattr(xss_module, "tool_available", lambda name: False)
    monkeypatch.setattr(xss_module, "_playwright_available", lambda: _async_value(True))

    async def fake_curl(url, **kwargs):
        from urllib.parse import parse_qs, urlparse, unquote

        params = parse_qs(urlparse(url).query)
        value = unquote(params.get("name", [""])[0])
        return {"status": 200, "body": f"<html><body>{value}</body></html>"}

    async def fake_browser_confirms(url, expected, config):
        return True

    monkeypatch.setattr(xss_module, "curl", fake_curl)
    monkeypatch.setattr(xss_module, "_browser_confirms_execution", fake_browser_confirms)
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))

    result = asyncio.run(
        XSSScan(
            state,
            {
                "target": {
                    "domain": "example.com",
                    "raw_url": "https://example.com/vulnerabilities/xss_r/?name=test",
                }
            },
        ).run()
    )

    assert result == "done"
    assert state.findings["findings"][0]["title"] == "Confirmed Reflected Cross-Site Scripting"
    assert state.findings["findings"][0]["confidence"] == "CONFIRMED"


def test_stage_order_and_active_modules_are_registered():
    assert STAGE_ORDER == [1, 2, 3, 4, 5, 6]

    for module_id in [
        "content_discovery",
        "nuclei_scan",
        "xss_scan",
        "sqli_scan",
        "cors_audit",
        "open_redirect",
        "http_smuggling",
    ]:
        entry = MODULE_REGISTRY[module_id]
        assert entry["stage"] == 5
        assert entry["requires_auth"] is True

    assert MODULE_REGISTRY["reporting"]["stage"] == 6
    assert MODULE_REGISTRY["risk_prioritization"]["stage"] == 6
    assert MODULE_REGISTRY["browser_crawl"]["stage"] == 4
    assert MODULE_REGISTRY["mobile_assets"]["stage"] == 4
    all_modules = get_all_module_ids()
    assert "fast_exposure_scan" in all_modules
    assert "misconfig_probes" in all_modules


def test_js_analysis_extracts_dom_sinks():
    sinks = extract_dom_sinks(
        "window.addEventListener('message', e => out.innerHTML = e.data);"
    )
    names = {item["sink"] for item in sinks}
    assert "postMessage-handler" in names
    assert "innerHTML" in names


def test_browser_crawl_skips_without_playwright(monkeypatch):
    import modules.browser_crawl as browser_module

    async def unavailable():
        return False

    monkeypatch.setattr(browser_module, "_playwright_available", unavailable)
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))

    result = asyncio.run(BrowserCrawl(state, {"target": {"domain": "example.com"}}).run())

    assert result == "skipped"
    assert state.module["skipped"][0]["module_id"] == "browser_crawl"


def test_nuclei_full_cve_only_on_confirmed_apex():
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    module = NucleiScan(state, {"target": {"domain": "example.com"}})

    assert not module._allow_full_cve_pass("https://example.com", [])
    assert module._allow_full_cve_pass(
        "https://example.com",
        [{"value": "https://example.com", "confidence": "CONFIRMED"}],
    )
    disabled = NucleiScan(
        state,
        {"target": {"domain": "example.com"}, "nuclei": {"full_cve": False}},
    )
    assert not disabled._allow_full_cve_pass(
        "https://example.com",
        [{"value": "https://example.com", "confidence": "CONFIRMED"}],
    )


def test_mobile_assets_records_android_and_ios_apps(monkeypatch):
    import modules.mobile_assets as mobile_module

    async def fake_curl(url, **kwargs):
        if url.endswith("assetlinks.json"):
            return {
                "status": 200,
                "body": '[{"relation":["delegate_permission/common.handle_all_urls"],'
                        '"target":{"namespace":"android_app","package_name":"com.example.app",'
                        '"sha256_cert_fingerprints":["AA:BB"]}}]',
            }
        if url.endswith("apple-app-site-association"):
            return {
                "status": 200,
                "body": '{"applinks":{"details":[{"appID":"TEAMID.com.example.ios","paths":["*"]}]}}',
            }
        return {"status": 404, "body": ""}

    monkeypatch.setattr(mobile_module, "curl_with_status", fake_curl)
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))

    result = asyncio.run(MobileAssets(state, {"target": {"domain": "example.com"}}).run())

    assert result == "done"
    values = {asset["value"] for asset in state.get_assets_by_type("mobile_app")}
    assert "com.example.app" in values
    assert "TEAMID.com.example.ios" in values


def test_misconfig_probes_are_bounded_and_detect_findings(monkeypatch):
    import modules.misconfig as misconfig_module

    async def fake_curl(url, **kwargs):
        if url.endswith("/.env"):
            return {"status": 200, "body": "APP_KEY=secret\n" * 10}
        return {"status": 404, "body": ""}

    monkeypatch.setattr(misconfig_module, "curl_with_status", fake_curl)
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    config = {
        "target": {"domain": "example.com"},
        "misconfig": {
            "concurrency": 4,
            "timeout": 1,
            "max_paths": 5,
            "max_consecutive_empty": 5,
            "progress_every": 2,
        },
        "wordlists": {
            "misconfig_paths": ["/missing1", "/missing2", "/.env", "/missing3", "/missing4", "/missing5"],
        },
    }

    result = asyncio.run(MisconfigProbes(state, config).run())

    assert result == "done"
    assert state.findings["findings"][0]["title"] == "Exposed Environment File"


def test_fast_exposure_scan_detects_exposed_env(monkeypatch):
    import modules.fast_exposure_scan as fast_module

    async def fake_curl(url, **kwargs):
        if kwargs.get("output") == "headers" and kwargs.get("headers"):
            return {"status": 200, "body": "HTTP/2 200\nAccess-Control-Allow-Origin: https://attacker.invalid\n"}
        return {"status": 200, "body": "HTTP/2 200\nserver: nginx\n"}

    async def fake_curl_with_status(url, **kwargs):
        if url.endswith("/.env"):
            return {"status": 200, "body": "APP_KEY=secret\nDATABASE_URL=mysql://x\n"}
        return {"status": 404, "body": ""}

    monkeypatch.setattr(fast_module, "curl", fake_curl)
    monkeypatch.setattr(fast_module, "curl_with_status", fake_curl_with_status)
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    result = asyncio.run(FastExposureScan(
        state, 
        {
            "target": {"domain": "example.com"},
            "fast_scan": {"paths": ["/.env", "/missing"], "timeout": 1, "concurrency": 2},
        },
    ).run())

    titles = {finding["title"] for finding in state.findings["findings"]}
    assert result == "done"
    assert "Exposed Environment File" in titles
    assert "Permissive CORS Behavior" in titles
