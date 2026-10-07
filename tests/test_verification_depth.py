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
                            "Set-Cookie: sessionid=abc; Path=/; HttpOnly; SameSite=Lax; Secure\n"),
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


# ── severity calibration: shape and catalog matches are not vulns ──
def test_kev_exact_without_version_is_high_not_critical():
    from modules.exploit_lookup import ExploitLookup
    state = _state()
    state.add_asset("webapp", "webapp:https://example.test",
                    "https://example.test", confidence="FIRM",
                    sources=["test"], attrs={"cms": "WordPress"})
    module = ExploitLookup(state, _config())
    import modules.exploit_lookup as el

    async def fake_kev(terms):
        return [{"cve": "CVE-2024-0001", "product": "WordPress",
                 "name": "Test RCE", "match_strength": "exact",
                 "matched_term": "wordpress"}]

    async def fake_nvd(term):
        return []

    with patch.object(el, "check_cisa_kev", new=fake_kev), \
         patch.object(el, "nvd_cve_search", new=fake_nvd), \
         patch.object(el, "searchsploit", new=AsyncMock(return_value={"results": []})), \
         patch.object(el, "tool_available", return_value=False):
        _run(module.run())
    match = next(f for f in state.findings["findings"] if "KEV Match" in f["title"])
    assert match["severity"] == "HIGH", \
        "exact product without a fingerprinted version must not be CRITICAL"


def test_kev_exact_with_version_is_critical():
    from modules.exploit_lookup import ExploitLookup
    state = _state()
    state.add_asset("webapp", "webapp:https://example.test",
                    "https://example.test", confidence="FIRM",
                    sources=["test"],
                    attrs={"cms": "WordPress",
                           "product_versions": {"WordPress": "6.0"}})
    module = ExploitLookup(state, _config())
    import modules.exploit_lookup as el

    async def fake_kev(terms):
        return [{"cve": "CVE-2024-0001", "product": "WordPress",
                 "name": "Test RCE", "match_strength": "exact",
                 "matched_term": "wordpress"}]

    async def fake_nvd(term):
        return []

    with patch.object(el, "check_cisa_kev", new=fake_kev), \
         patch.object(el, "nvd_cve_search", new=fake_nvd), \
         patch.object(el, "searchsploit", new=AsyncMock(return_value={"results": []})), \
         patch.object(el, "tool_available", return_value=False):
        _run(module.run())
    match = next(f for f in state.findings["findings"] if "KEV Match" in f["title"])
    assert match["severity"] == "CRITICAL"


def test_kev_adjacent_and_nvd_are_medium_leads():
    from modules.exploit_lookup import ExploitLookup
    state = _state()
    state.add_asset("webapp", "webapp:https://example.test",
                    "https://example.test", confidence="FIRM",
                    sources=["test"], attrs={"cms": "WordPress"})
    module = ExploitLookup(state, _config())
    import modules.exploit_lookup as el

    async def fake_kev(terms):
        return [{"cve": "CVE-2024-0002", "product": "WordPress Plugin X",
                 "name": "Test bug", "match_strength": "substring",
                 "matched_term": "word"}]

    async def fake_nvd(term):
        return [{"id": "CVE-2024-0003", "cvss_score": 9.8,
                 "description": "x" * 120}]

    with patch.object(el, "check_cisa_kev", new=fake_kev), \
         patch.object(el, "nvd_cve_search", new=fake_nvd), \
         patch.object(el, "searchsploit", new=AsyncMock(return_value={"results": []})), \
         patch.object(el, "tool_available", return_value=False):
        _run(module.run())
    for f in state.findings["findings"]:
        if "Adjacent" in f["title"] or "Critical CVEs" in f["title"]:
            assert f["severity"] == "MEDIUM", \
                f"TENTATIVE lead must not outrank proven MEDIUM: {f['title']}"
            assert f["confidence"] == "TENTATIVE"


# ── autopilot hunt wave: Secure flag, throttle bypass, oracle, health ──

def test_cookie_missing_secure_on_https_is_medium():
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
                            "Set-Cookie: auth-token=abc; Path=/; HttpOnly; SameSite=Strict\n"),
                "body": ""}

    with patch.object(ha, "curl", new=fake_curl):
        _run(module.run())
    match = next(f for f in state.findings["findings"]
                 if "Session Cookie" in f["title"])
    assert match["severity"] == "MEDIUM"
    assert "Secure" in match["description"]
    assert match["verified"] is True


def test_cookie_secure_not_judged_on_plaintext():
    import modules.headers_audit as ha
    from modules.headers_audit import HeadersAudit
    state = _state("plain.test")
    state.add_asset("url", "url:http://plain.test/",
                    "http://plain.test/", confidence="FIRM",
                    sources=["test"])
    config = {"target": {"domain": "plain.test",
                         "base_url": "http://plain.test"},
              "auth": {"identities": []}, "waf": {},
              "modules": {}}
    module = HeadersAudit(state, config)

    async def fake_curl(url, **kwargs):
        if kwargs.get("method") == "OPTIONS":
            return {"status": 200, "headers": "Allow: GET, HEAD",
                    "body": ""}
        return {"status": 200,
                "headers": ("HTTP/1.1 200 OK\n"
                            "Set-Cookie: auth-token=abc; Path=/; HttpOnly; SameSite=Strict\n"),
                "body": ""}

    with patch.object(ha, "curl", new=fake_curl):
        _run(module.run())
    assert state.findings["findings"] == [], \
        "Secure on plaintext would break the site — not a finding"


def test_ratelimit_bypass_via_direct_port():
    import modules.auth_audit as aa
    from modules.auth_audit import AuthAudit
    state = _state()
    state.add_asset("port", "port:1.2.3.4:3000", "1.2.3.4:3000",
                    confidence="CONFIRMED", sources=["test"],
                    attrs={"ip": "1.2.3.4", "port": 3000,
                           "service": "http", "version": ""})
    module = AuthAudit(state, _config())

    async def fake_curl(url, **kwargs):
        if url.startswith("http://1.2.3.4:3000"):
            return {"status": 401, "body": '{"error":"Invalid credentials"}',
                    "headers": ""}
        return {"status": 429, "body": '{"error":"Too many attempts"}',
                "headers": ""}

    with patch.object(aa, "curl", new=fake_curl):
        _run(module._ratelimit_bypass_check(
            ["https://example.test/api/auth/login"]))
    match = next(f for f in state.findings["findings"]
                 if "Rate Limit Bypass" in f["title"])
    assert match["severity"] == "MEDIUM"
    assert match["verified"] is True
    assert match["verification"]["method"] == "ratelimit_differential"


def test_ratelimit_bypass_burst_trips_gate_on_sixth():
    """The gate trips on consecutive failures to ONE login."""
    import modules.auth_audit as aa
    from modules.auth_audit import AuthAudit
    state = _state()
    state.add_asset("port", "port:1.2.3.4:3000", "1.2.3.4:3000",
                    confidence="CONFIRMED", sources=["test"],
                    attrs={"ip": "1.2.3.4", "port": 3000,
                           "service": "http", "version": ""})
    module = AuthAudit(state, _config())
    calls = []

    async def fake_curl(url, **kwargs):
        calls.append(url)
        if url.startswith("http://1.2.3.4:3000"):
            return {"status": 401, "body": '{"error":"Invalid credentials"}',
                    "headers": ""}
        if len([u for u in calls if "example.test" in u]) >= 6:
            return {"status": 429, "body": '{"error":"Too many attempts"}',
                    "headers": ""}
        return {"status": 401, "body": '{"error":"Invalid credentials"}',
                "headers": ""}

    with patch.object(aa, "curl", new=fake_curl):
        _run(module._ratelimit_bypass_check(
            ["https://example.test/api/auth/login"]))
    match = next(f for f in state.findings["findings"]
                 if "Rate Limit Bypass" in f["title"])
    assert match["verified"] is True


def test_ratelimit_bypass_quiet_when_gate_holds():
    import modules.auth_audit as aa
    from modules.auth_audit import AuthAudit
    state = _state()
    state.add_asset("port", "port:1.2.3.4:3000", "1.2.3.4:3000",
                    confidence="CONFIRMED", sources=["test"],
                    attrs={"ip": "1.2.3.4", "port": 3000,
                           "service": "http", "version": ""})
    module = AuthAudit(state, _config())

    async def fake_curl(url, **kwargs):
        return {"status": 429, "body": '{"error":"Too many attempts"}',
                "headers": ""}

    with patch.object(aa, "curl", new=fake_curl):
        _run(module._ratelimit_bypass_check(
            ["https://example.test/api/auth/login"]))
    assert state.findings["findings"] == []


def test_register_oracle_opt_in_off_by_default():
    import modules.auth_audit as aa
    from modules.auth_audit import AuthAudit
    state = _state()
    state.add_asset("api_endpoint",
                    "api_endpoint:https://example.test/api/auth/register",
                    "https://example.test/api/auth/register",
                    confidence="FIRM", sources=["test"],
                    attrs={"methods": ["POST"]})
    module = AuthAudit(state, _config())
    touched = []

    async def fake_curl(url, **kwargs):
        touched.append((url, str(kwargs.get("data", ""))))
        return {"status": 404, "body": "<html>shell</html>", "headers": ""}

    with patch.object(aa, "curl", new=fake_curl):
        _run(module.run())
    assert not any("oracle-probe" in data for _, data in touched), \
        "opt-in off must not send registration bodies"


def test_register_oracle_proves_enumeration_when_enabled():
    import modules.auth_audit as aa
    from modules.auth_audit import AuthAudit
    state = _state()
    config = _config()
    config["modules"] = {"auth_audit": {"test_registration_oracle": True}}
    module = AuthAudit(state, config)
    calls = []

    async def fake_curl(url, **kwargs):
        import json as _json
        calls.append(_json.loads(kwargs.get("data", "{}")))
        if len(calls) == 1:
            return {"status": 200,
                    "body": '{"success":true,"user":{"id":"1"}}',
                    "headers": ""}
        return {"status": 200,
                "body": '{"error":"User already exists"}',
                "headers": ""}

    with patch.object(aa, "curl", new=fake_curl):
        _run(module._register_oracle())
    match = next(f for f in state.findings["findings"]
                 if "Registration Oracle" in f["title"])
    assert match["severity"] == "LOW"
    assert match["verified"] is True
    assert "Delete the test account" in match["description"]


def test_health_internals_files_info():
    import modules.fast_exposure_scan as fe
    from modules.fast_exposure_scan import FastExposureScan
    state = _state()
    module = FastExposureScan(state, _config())

    async def fake_curl(url, **kwargs):
        return {"status": 200,
                "body": '{"status":"ok","database":"connected","uptime":531407}',
                "headers": ""}

    with patch.object(fe, "curl", new=fake_curl):
        found = _run(module._check_health("https://example.test", 4))
    assert found["severity"] == "INFO"
    assert found["verified"] is True
    assert "database" in found["description"]


def test_health_bare_ok_stays_silent():
    import modules.fast_exposure_scan as fe
    from modules.fast_exposure_scan import FastExposureScan
    state = _state()
    module = FastExposureScan(state, _config())

    async def fake_curl(url, **kwargs):
        return {"status": 200, "body": '{"status":"ok"}', "headers": ""}

    with patch.object(fe, "curl", new=fake_curl):
        assert _run(module._check_health("https://example.test", 4)) is None

def test_direct_http_port_files_info_inventory():
    import tools.wrappers as wrappers
    from modules.port_scan_module import PortScan
    state = _state()
    module = PortScan(state, _config())

    async def fake_curl(url, **kwargs):
        return {"status": 200,
                "body": "<html><title>AI Content Agent Dashboard</title></html>",
                "headers": "Server: Next.js"}

    with patch.object(wrappers, "curl", new=fake_curl):
        _run(module._fingerprint_http_port("203.0.113.9", 3001))
    assert len(state.findings["findings"]) == 1
    finding = state.findings["findings"][0]
    assert finding["severity"] == "INFO"
    assert finding["verified"] is True
    assert "AI Content Agent Dashboard" in finding["description"]


def test_direct_http_port_empty_body_files_nothing():
    import tools.wrappers as wrappers
    from modules.port_scan_module import PortScan
    state = _state()
    module = PortScan(state, _config())

    async def fake_curl(url, **kwargs):
        return {"status": 200, "body": "", "headers": ""}

    with patch.object(wrappers, "curl", new=fake_curl):
        _run(module._fingerprint_http_port("203.0.113.9", 3001))
    assert state.findings["findings"] == []

def test_verified_low_on_webapp_stays_low_without_intel():
    from core.prioritization import prioritize_findings
    findings = [{
        "id": "F-1", "title": "Missing Security Headers", "severity": "LOW",
        "confidence": "CONFIRMED", "category": "Hardening Deficiency",
        "asset_keys": ["webapp:https://example.test"],
        "verified": True,
        "verification": {"method": "response_headers_observed"},
        "created_at": "2026-01-01",
    }]
    out = prioritize_findings(findings)
    assert out[0]["severity"] == "LOW", \
        "exposure alone must not rewrite the module's class judgment"
    assert out[0]["risk_score"] >= 15


def test_intel_backed_upgrade_still_promotes():
    from core.prioritization import prioritize_findings
    findings = [{
        "id": "F-1", "title": "KEV-listed CVE", "severity": "HIGH",
        "confidence": "FIRM", "category": "Exploit Intelligence",
        "asset_keys": ["webapp:https://example.test"],
        "intelligence": {"cvss": 9.8, "epss": 0.8, "kev": True},
        "created_at": "2026-01-01",
    }]
    assert prioritize_findings(findings)[0]["severity"] == "CRITICAL"


def test_origin_skips_high_on_direct_hosting():
    import modules.origin_discovery as od
    from modules.origin_discovery import OriginDiscovery
    state = _state()
    module = OriginDiscovery(state, _config())

    async def fake_curl(url, **kwargs):
        return {"status": 200, "body": "x" * 300,
                "headers": "server: nginx"}

    async def fake_gather(self, cdn):
        assert cdn is None
        return [{"ip": "1.2.3.4", "source": "subdomain:api.example.test"}]

    async def fake_verify(self, ip, base_hash):
        return ("confirmed", "byte-identical body")

    with patch.object(od, "curl", new=fake_curl), \
         patch.object(OriginDiscovery, "_gather_candidates",
                      new=fake_gather), \
         patch.object(OriginDiscovery, "_verify_origin",
                      new=fake_verify):
        _run(module.run())
    assert not [f for f in state.findings["findings"]
                if "Origin IP Discovered Behind" in f["title"]], \
        "direct hosting has no CDN to bypass — the asset suffices"

# ── MEDIUM wave: observations verified, names demoted ──

def test_sensitive_param_names_are_low_inventory():
    from modules.parameter_discovery import ParameterDiscovery
    import tempfile
    from pathlib import Path
    from state.manager import StateManager
    state = StateManager(str(Path(tempfile.mkdtemp()) / "run" / "example.com"))
    state.add_asset(
        "url",
        "url:https://example.com/search?q=test&api_key=xxx",
        "https://example.com/search?q=test&api_key=xxx",
    )
    _run(ParameterDiscovery(
        state, {"target": {"domain": "example.com"}}).run())
    match = next(f for f in state.findings["findings"]
                 if f["title"] == "Sensitive Parameter Names Discovered")
    assert match["severity"] == "LOW", \
        "names alone are an input list, not a vulnerability"


def test_origin_header_bypass_is_verified():
    import modules.origin_discovery as od
    from modules.origin_discovery import OriginDiscovery
    state = _state()
    module = OriginDiscovery(state, _config())

    async def fake_curl(url, **kwargs):
        if kwargs.get("headers", {}).get("X-Forwarded-For") == "127.0.0.1":
            return {"status": 200, "body": "o" * 1200,
                    "headers": "Server: nginx\nX-Backend: origin1"}
        return {"status": 200, "body": "b" * 600,
                "headers": "Server: cloudflare"}

    with patch.object(od, "curl", new=fake_curl):
        _run(module._test_cdn_bypass_headers("https://example.test"))
    match = next(f for f in state.findings["findings"]
                 if "Exposes Origin Markers" in f["title"])
    assert match["verified"] is True


def test_wayback_live_findings_carry_proof():
    import modules.wayback as wb
    from modules.wayback import WaybackMachine
    state = _state()
    module = WaybackMachine(state, _config())

    async def fake_cdx(domain, **kwargs):
        return [{"original": "https://example.test/dl?api_key=AKIAZZZZZZZZZZZZZZZZ",
                 "timestamp": "20200101"},
                {"original": "https://example.test/.env",
                 "timestamp": "20200101"}]

    async def fake_gau(domain, timeout=90):
        return []

    async def fake_fetch(url, timeout=10):
        if url == "https://example.test":
            return {"status": 200, "body": "BASE SHELL", "time_ms": 5,
                    "url": url}
        return {"status": 200, "body": "distinct live content " + "x" * 100,
                "time_ms": 5, "url": url}

    with patch.object(wb, "wayback_cdx", new=fake_cdx), \
         patch.object(wb, "gau_urls", new=fake_gau), \
         patch.object(wb, "curl_with_status", new=fake_fetch):
        _run(module.run())
    for f in state.findings["findings"]:
        if f["title"] in ("Live URLs With Secret-Shaped Parameter Values",
                          "Sensitive Files Reachable Now"):
            assert f["verified"] is True, f["title"]
            assert f["verification"].get("method"), f["title"]

# ── audit-clean wave: origin, tech, TLS hygiene, REST docs ──

def test_origin_confirmed_is_verified():
    import modules.origin_discovery as od
    from modules.origin_discovery import OriginDiscovery
    state = _state()
    module = OriginDiscovery(state, _config())

    async def fake_curl(url, **kwargs):
        return {"status": 200, "body": "x" * 300,
                "headers": "cf-ray: 1"}

    async def fake_gather(self, cdn):
        return [{"ip": "1.2.3.4", "source": "history"}]

    async def fake_verify(self, ip, base_hash):
        return ("confirmed", "byte-identical body")

    with patch.object(od, "curl", new=fake_curl), \
         patch.object(OriginDiscovery, "_gather_candidates",
                      new=fake_gather), \
         patch.object(OriginDiscovery, "_verify_origin",
                      new=fake_verify):
        _run(module.run())
    match = next(f for f in state.findings["findings"]
                 if "Origin IP Discovered" in f["title"])
    assert match["severity"] == "HIGH"
    assert match["verified"] is True


def test_tech_detect_observations_are_verified():
    import modules.tech_detect as td
    from modules.tech_detect import TechDetection
    state = _state()
    module = TechDetection(state, _config())

    async def fake_curl(url, **kwargs):
        return {"status": 200, "body": "<html></html>",
                "headers": "HTTP/1.1 200 OK\nServer: nginx/1.2.3\n"}

    with patch.object(td, "curl", new=fake_curl):
        _run(module.run())
    by_title = {f["title"]: f for f in state.findings["findings"]}
    assert "Missing Security Headers" in by_title
    assert "Server Version Disclosure" in by_title
    assert by_title["Missing Security Headers"]["verified"] is True
    assert by_title["Server Version Disclosure"]["verified"] is True


def test_tls_hsts_observations_are_verified():
    from modules.tls_audit import TLSAudit
    import modules.tls_audit as tls
    state = _state()
    module = TLSAudit(state, _config())
    headers = ("strict-transport-security: max-age=60\n")
    with patch.object(tls, "cert_info",
                      new=AsyncMock(return_value={})), \
         patch.object(tls, "tls_protocols",
                      new=AsyncMock(return_value={"tls1_3": True})), \
         patch.object(tls, "curl",
                      new=AsyncMock(return_value={"body": headers})), \
         patch("tools.external.tool_available", return_value=False):
        _run(module._audit_endpoint("example.test", 443))
    by_title = {f["title"]: f for f in state.findings["findings"]}
    assert "HSTS Missing preload Directive" in by_title
    assert "HSTS max-age Too Short" in by_title
    assert by_title["HSTS Missing preload Directive"]["verified"] is True
    assert by_title["HSTS max-age Too Short"]["verified"] is True


def test_rest_api_docs_exposed_is_verified():
    import modules.rest_api as ra
    from modules.rest_api import RestAPIAudit
    state = _state()
    module = RestAPIAudit(state, _config())

    async def fake_status(url, **kwargs):
        if url.endswith("/openapi.json"):
            return {"status": 200,
                    "body": '{"openapi":"3.0.0","paths":{"/a":{}}}',
                    "final_url": url}
        return {"status": 404, "body": "", "final_url": url}

    with patch.object(ra, "curl_with_status", new=fake_status):
        _run(module._discover_openapi("https://example.test"))
    match = next(f for f in state.findings["findings"]
                 if "API Documentation Exposed" in f["title"])
    assert match["verified"] is True
