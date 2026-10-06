"""Verification-depth wave: prove before claiming.

Covers the uncommitted wave: headers_audit policy reads, nuclei
template re-run, nmap TLS corroboration, sourcemap JSON confirm,
wp-json users differential, CORS/api concretizing, prototype
discovered-surface priority, and CMS EPSS attach.
"""

import asyncio
import tempfile
from unittest.mock import AsyncMock, patch

from state.manager import StateManager


def _state(domain="example.test"):
    return StateManager(tempfile.mkdtemp() + f"/run/{domain}")


def _config(domain="example.test"):
    return {
        "target": {"domain": domain, "base_url": f"https://{domain}"},
        "auth": {"identities": []},
        "waf": {"block_codes": [429, 503]},
        "modules": {},
    }


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── headers_audit ──

def test_headers_audit_flags_weak_csp_and_cookie():
    import modules.headers_audit as ha
    from modules.headers_audit import HeadersAudit
    state = _state()
    state.add_asset("url", "url:https://example.test/",
                    "https://example.test/", confidence="FIRM",
                    sources=["test"])
    module = HeadersAudit(state, _config())

    async def fake_curl(url, **kwargs):
        if kwargs.get("method") == "OPTIONS":
            return {"status": 200, "headers": "Allow: GET, HEAD",
                    "body": ""}
        return {"status": 200,
                "headers": ("HTTP/1.1 200 OK\n"
                            "Content-Security-Policy: script-src * 'unsafe-inline'\n"
                            "Set-Cookie: sessionid=abc; Path=/\n"),
                "body": "<html></html>"}

    with patch.object(ha, "curl", new=fake_curl):
        assert _run(module.run()) == "done"
    titles = [f["title"] for f in state.findings["findings"]]
    assert "Weak Content-Security-Policy" in titles
    assert any("Session Cookie" in t for t in titles)


def test_headers_audit_quiet_on_tight_policy():
    import modules.headers_audit as ha
    from modules.headers_audit import HeadersAudit
    state = _state()
    state.add_asset("url", "url:https://example.test/",
                    "https://example.test/", confidence="FIRM",
                    sources=["test"])
    module = HeadersAudit(state, _config())

    async def fake_curl(url, **kwargs):
        if kwargs.get("method") == "OPTIONS":
            return {"status": 200, "headers": "Allow: GET, HEAD",
                    "body": ""}
        return {"status": 200,
                "headers": ("HTTP/1.1 200 OK\n"
                            "Content-Security-Policy: script-src 'self'; object-src 'none'\n"
                            "Set-Cookie: sessionid=abc; Path=/; HttpOnly; SameSite=Lax\n"),
                "body": ""}

    with patch.object(ha, "curl", new=fake_curl):
        assert _run(module.run()) == "done"
    assert state.findings["findings"] == []


# ── nuclei revalidation ──

def test_nuclei_revalidate_confirms_on_second_fire():
    import modules.nuclei_scan as ns
    from modules.nuclei_scan import NucleiScan
    state = _state()
    module = NucleiScan(state, _config())
    match = {"template_id": "t1", "matched_at": "https://example.test/",
             "severity": "HIGH"}

    async def fake_scan(target, **kwargs):
        assert kwargs.get("templates") == "t1"
        return {"results": [{"template_id": "t1",
                             "matched_at": target}], "exit_code": 0}

    with patch.object(ns, "nuclei_scan", new=fake_scan):
        confirmed, note = _run(module._revalidate_match(match, 10))
    assert confirmed is True
    assert "again" in note


def test_nuclei_revalidate_stays_firm_without_refire():
    import modules.nuclei_scan as ns
    from modules.nuclei_scan import NucleiScan
    state = _state()
    module = NucleiScan(state, _config())
    match = {"template_id": "t1", "matched_at": "https://example.test/",
             "severity": "HIGH"}

    async def fake_scan(target, **kwargs):
        return {"results": [], "exit_code": 0}

    with patch.object(ns, "nuclei_scan", new=fake_scan):
        confirmed, note = _run(module._revalidate_match(match, 10))
    assert confirmed is False
    assert "did not re-fire" in note


# ── tls nmap corroboration ──

def test_tls_nmap_heartbleed_files_critical():
    from modules.tls_audit import TLSAudit
    state = _state()
    module = TLSAudit(state, _config())
    fake_result = {"stdout": ("Host script results:\n"
                              "| ssl-heartbleed:\n"
                              "|   State: VULNERABLE\n"
                              "|   Heartbleed: VULNERABLE\n"),
                   "stderr": "", "exit_code": 0}
    with patch("tools.external.tool_available", return_value=True), \
         patch("modules.tls_audit.run_command",
               new=AsyncMock(return_value=fake_result)):
        _run(module._nmap_tls_scripts("example.test", 443))
    titles = [f["title"] for f in state.findings["findings"]]
    assert any("Heartbleed" in t for t in titles)


def test_tls_nmap_clean_writes_nothing():
    from modules.tls_audit import TLSAudit
    state = _state()
    module = TLSAudit(state, _config())
    fake_result = {"stdout": "least strength: A\n", "stderr": "",
                   "exit_code": 0}
    with patch("tools.external.tool_available", return_value=True), \
         patch("modules.tls_audit.run_command",
               new=AsyncMock(return_value=fake_result)):
        _run(module._nmap_tls_scripts("example.test", 443))
    assert state.findings["findings"] == []


# ── browser sourcemap confirm ──

def test_browser_sourcemap_with_content_is_medium():
    from modules.browser_crawl import BrowserCrawl
    state = _state()
    module = BrowserCrawl(state, _config())
    body = ('{"version":3,"sources":["src/app.ts"],'
            '"sourcesContent":["console.log(1)"]}')

    async def fake_curl(url, **kwargs):
        return {"status": 200, "body": body}

    import tools.wrappers as wrappers
    with patch.object(wrappers, "curl", new=fake_curl):
        _run(module._confirm_source_maps(
            ["https://example.test/app.js.map"]))
    assert len(state.findings["findings"]) == 1
    finding = state.findings["findings"][0]
    assert finding["severity"] == "MEDIUM"
    assert finding["verified"] is True


def test_browser_sourcemap_non_json_writes_nothing():
    from modules.browser_crawl import BrowserCrawl
    state = _state()
    module = BrowserCrawl(state, _config())

    async def fake_curl(url, **kwargs):
        return {"status": 200, "body": "<html>not a map</html>"}

    import tools.wrappers as wrappers
    with patch.object(wrappers, "curl", new=fake_curl):
        _run(module._confirm_source_maps(
            ["https://example.test/app.js.map"]))
    assert state.findings["findings"] == []


# ── cms EPSS attach ──

def test_cms_attach_epss_enriches_evidence():
    from modules.cms_deep_scan import CMSDeepScan
    state = _state()
    module = CMSDeepScan(state, _config())
    finding = {"title": "plugin: CVE-2024-0001",
               "description": "CVE-2024-0001",
               "evidence": ["CVE-2024-0001"],
               "verification": {}}
    import modules.cms_deep_scan as cms
    fake_scores = {"CVE-2024-0001": {"epss": 0.9, "percentile": 0.99,
                                    "date": "2026-01-01"}}
    with patch.object(cms, "epss_score",
                      new=AsyncMock(return_value=fake_scores)):
        _run(module._attach_epss(finding))
    assert any("EPSS CVE-2024-0001: 0.900" in e
               for e in finding["evidence"])
    assert finding["verification"]["epss"]["CVE-2024-0001"] == 0.9


def test_cms_attach_epss_no_cves_is_noop():
    from modules.cms_deep_scan import CMSDeepScan
    state = _state()
    module = CMSDeepScan(state, _config())
    finding = {"title": "unattributed", "description": "d",
               "evidence": [], "verification": {}}
    _run(module._attach_epss(finding))
    assert finding["evidence"] == []
    assert finding["verification"] == {}


# ── cors / prototype surface ──

def test_cors_discovered_concretizes_api_templates():
    from modules.cors_audit import CORSAudit
    state = _state()
    state.add_asset("api_endpoint",
                    "api_endpoint:https://example.test/api/{id}",
                    "https://example.test/api/{id}",
                    confidence="FIRM", sources=["test"])
    module = CORSAudit(state, _config())
    found = module._discovered()
    assert found == ["https://example.test/api/1"]


def test_prototype_prefers_discovered_write_surface():
    from modules.prototype_pollution import PrototypePollution
    state = _state()
    state.add_asset("api_endpoint",
                    "api_endpoint:https://example.test/api/{id}",
                    "https://example.test/api/{id}",
                    confidence="FIRM", sources=["test"],
                    attrs={"methods": ["POST"]})
    module = PrototypePollution(state, _config())
    urls = module._endpoints({}, "https://example.test")
    assert urls[0] == "https://example.test/api/1"


# ── graphql verified flags ──

def test_graphql_introspection_marks_verified():
    from modules.graphql_module import GraphQLAudit
    state = _state()
    module = GraphQLAudit(state, _config())
    schema = {"__schema": {"types": [
        {"name": "User", "kind": "OBJECT"},
        {"name": "Query", "kind": "OBJECT"},
    ]}, "mutationType": None}

    async def fake_curl(url, **kwargs):
        import json as _json
        data = kwargs.get("data", "") or ""
        if "invalidFieldNameXYZ" in data:
            return {"status": 200,
                    "body": '{"errors":[{"message":"Did you mean User?"}]}'}
        if isinstance(data, str) and data.startswith("["):
            return {"status": 200, "body": "[]"}
        if url.endswith("?query=%7B__typename%7D"):
            return {"status": 200, "body": "{}"}
        return {"status": 200,
                "body": _json.dumps({"data": {"__schema": schema["__schema"]}})}

    import modules.graphql_module as gm
    with patch.object(gm, "curl", new=fake_curl):
        _run(module._audit_endpoint("https://example.test/graphql"))
    by_title = {f["title"]: f for f in state.findings["findings"]}
    key = "GraphQL Introspection Enabled: https://example.test/graphql"
    assert key in by_title
    assert by_title[key]["verified"] is True
    assert by_title[key]["verification"]["method"] == \
        "introspection_schema_returned"


# ── reporting reproduce ──

def test_reporting_renders_reproduce_for_verified():
    from core.reporting import _render_finding
    finding = {"id": "FINDING-0001", "title": "GraphQL Batch",
               "severity": "MEDIUM", "confidence": "CONFIRMED",
               "category": "API Security", "description": "d",
               "evidence": [], "remediation": "r",
               "asset_keys": ["url:https://example.test/graphql"],
               "verified": True,
               "verification": {"method": "batch_query_accepted",
                                "url": "https://example.test/graphql"}}
    lines = _render_finding(finding, [])
    assert any("Reproduce" in line for line in lines)
    assert any("batch_query_accepted" in line for line in lines)


def test_reporting_no_reproduce_when_unverified():
    from core.reporting import _render_finding
    finding = {"id": "FINDING-0001", "title": "Inventory",
               "severity": "INFO", "confidence": "FIRM",
               "category": "Content Discovery", "description": "d",
               "evidence": [], "remediation": "r", "asset_keys": [],
               "verified": False, "verification": {}}
    lines = _render_finding(finding, [])
    assert not any("Reproduce" in line for line in lines)


# ── CONFIRMED means verified ──

def test_headers_audit_findings_carry_proof():
    import modules.headers_audit as ha
    from modules.headers_audit import HeadersAudit
    state = _state()
    state.add_asset("url", "url:https://example.test/",
                    "https://example.test/", confidence="FIRM",
                    sources=["test"])
    module = HeadersAudit(state, _config())

    async def fake_curl(url, **kwargs):
        if kwargs.get("method") == "OPTIONS":
            return {"status": 200, "headers": "Allow: GET, HEAD",
                    "body": ""}
        return {"status": 200,
                "headers": ("HTTP/1.1 200 OK\n"
                            "Content-Security-Policy: script-src * 'unsafe-inline'\n"
                            "Set-Cookie: sessionid=abc; Path=/\n"),
                "body": ""}

    with patch.object(ha, "curl", new=fake_curl):
        _run(module.run())
    assert state.findings["findings"], "weak policy must still file"
    for finding in state.findings["findings"]:
        assert finding["verified"] is True
        assert finding["verification"].get("method")


def test_js_sourcemap_requires_json_sources():
    import modules.js_analysis as js
    from modules.js_analysis import JSAnalysis
    from types import SimpleNamespace
    state = _state()
    state.add_asset("js_file", "js:https://example.test/app.js",
                    "https://example.test/app.js", confidence="FIRM",
                    sources=["test"])
    module = JSAnalysis(state, _config())

    async def fake_fetch(url, **kwargs):
        return {"status": 200, "body": "<html>catch-all shell</html>",
                "headers": "Content-Type: text/html"}

    async def fake_baseline(probe, base_url):
        return SimpleNamespace(root=None, describe=lambda: "mock",
                               catch_all=lambda fp: False)

    with patch.object(js, "curl_with_status", new=fake_fetch), \
         patch.object(js, "establish_baseline", new=fake_baseline):
        _run(module.run())
    assert not [f for f in state.findings["findings"]
                if "Source Map" in f["title"]], \
        "a 200 shell without JSON sources must not file"


def test_js_sourcemap_json_parse_files_verified():
    import modules.js_analysis as js
    from modules.js_analysis import JSAnalysis
    from types import SimpleNamespace
    state = _state()
    state.add_asset("js_file", "js:https://example.test/app.js",
                    "https://example.test/app.js", confidence="FIRM",
                    sources=["test"])
    module = JSAnalysis(state, _config())
    js_body = ("x" * 60 + "\n//# sourceMappingURL=app.js.map\n"
               + "y" * 60)
    map_body = ('{"version":3,"sources":["src/app.ts"],'
                '"sourcesContent":["console.log(1)"]}')

    async def fake_fetch(url, **kwargs):
        if url.endswith(".map"):
            return {"status": 200, "body": map_body,
                    "headers": "Content-Type: application/json"}
        if url.endswith(".js"):
            return {"status": 200, "body": js_body,
                    "headers": "Content-Type: application/javascript"}
        return {"status": 200, "body": "", "headers": ""}

    async def fake_baseline(probe, base_url):
        return SimpleNamespace(root=None, describe=lambda: "mock",
                               catch_all=lambda fp: False)

    with patch.object(js, "curl_with_status", new=fake_fetch), \
         patch.object(js, "establish_baseline", new=fake_baseline):
        _run(module.run())
    matches = [f for f in state.findings["findings"]
               if "Source Map" in f["title"]]
    assert len(matches) == 1
    assert matches[0]["severity"] == "MEDIUM"
    assert matches[0]["verified"] is True


def test_rest_users_enumeration_is_verified():
    import modules.rest_api as ra
    state = _state()
    from modules.rest_api import RestAPIAudit
    module = RestAPIAudit(state, _config())

    async def fake_json(url, **kwargs):
        if url.endswith("/wp-json/"):
            return {"namespaces": ["wp/v2"], "routes": {}}
        if "wp/v2/users" in url:
            return [{"slug": "admin"}, {"slug": "editor"}]
        return {}

    async def fake_status(url, **kwargs):
        return {"status": 404, "body": ""}

    with patch.object(ra, "curl_json", new=fake_json), \
         patch.object(ra, "curl_with_status", new=fake_status):
        _run(module._audit_wordpress_api("https://example.test"))
    match = next(f for f in state.findings["findings"]
                 if "Users Enumerated" in f["title"])
    assert match["verified"] is True
    assert match["verification"]["method"] == "rest_users_json"


def test_breach_hibp_is_verified():
    import modules.breach as breach_mod
    from modules.breach import BreachCheck
    state = _state()
    state.add_asset("email", "email:admin@example.test",
                    "admin@example.test", confidence="FIRM",
                    sources=["test"])
    config = _config()
    config["hibp_api_key"] = "test-key"
    module = BreachCheck(state, config)

    async def fake_curl(url, **kwargs):
        if "haveibeenpwned" in url:
            return {"status": 200,
                    "body": '[{"Name": "Adobe"}]'}
        return {"status": 200, "body": ""}

    with patch.object(breach_mod, "curl", new=fake_curl), \
         patch("asyncio.sleep", new=AsyncMock()):
        _run(module.run())
    match = next(f for f in state.findings["findings"] if "HIBP" in f["title"])
    assert match["verified"] is True


def test_tls_cert_expired_is_verified():
    from modules.tls_audit import TLSAudit
    state = _state()
    module = TLSAudit(state, _config())
    import modules.tls_audit as tls
    with patch.object(tls, "cert_info",
                      new=AsyncMock(return_value={"notafter": "Jan 01 00:00:00 2020 GMT"})), \
         patch.object(tls, "tls_protocols",
                      new=AsyncMock(return_value={})), \
         patch.object(tls, "curl",
                      new=AsyncMock(return_value={"body": ""})), \
         patch("tools.external.tool_available", return_value=False):
        _run(module._audit_endpoint("example.test", 443))
    match = next(f for f in state.findings["findings"] if "Expired" in f["title"])
    assert match["severity"] == "CRITICAL"
    assert match["verified"] is True
