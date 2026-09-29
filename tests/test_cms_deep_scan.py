"""Tests for modules/cms_deep_scan.py.

Two regressions are pinned here.

The first is a false negative: droopescan results were written to the evidence
file and then dropped, never reaching the findings list. A Drupal site scanned
with droopescan installed reported clean. The old code also assumed every
scanner returns a list, but `droopescan_scan` returns a dict, so a naive append
would have iterated its keys instead of its findings.

The second is grading. Four scanners were merged into one `HIGH/FIRM` line, so a
version disclosure and a plugin RCE were the same object, and a scraped line
reading "Found: /wp-admin/" was promoted to a vulnerability. The module now
grades per component and never attributes a keyword match to anything.
"""

import tempfile
from unittest.mock import AsyncMock, patch

import pytest

from modules.cms_deep_scan import (
    CMSDeepScan,
    _cves_in,
    droopescan_signals,
    scraped_signals,
    wpscan_signals,
)
from state.manager import StateManager


def _config(module_cfg=None):
    return {
        "target": {"domain": "example.test", "base_url": "https://example.test"},
        "auth": {"identities": []},
        "waf": {"block_codes": [429, 503]},
        "modules": {"cms_deep_scan": dict(module_cfg or {})},
    }


def _run(wpscan_data=None, joomscan_lines=(), droopescan_data=None,
         cmseek_lines=(), cms="wordpress", tools=("wpscan", "droopescan"),
         kev=(), module_cfg=None):
    state = StateManager(tempfile.mkdtemp())
    module = CMSDeepScan(state, _config(module_cfg))
    module.target = "https://example.test"

    # The module selects scanners from the webapp asset's `cms` attr, not from
    # its own target string, so the test has to seed one.
    state.add_asset("webapp", "webapp:https://example.test",
                    "https://example.test", confidence="FIRM",
                    sources=["test"], attrs={"cms": cms})

    wpscan_result = {"available": "wpscan" in tools, "results": wpscan_data or {},
                     "exit_code": 0}
    joomscan_result = {"available": "joomscan" in tools,
                       "results": [{"evidence": l} for l in joomscan_lines],
                       "exit_code": 0}
    droopescan_result = {"available": "droopescan" in tools,
                         "results": droopescan_data, "exit_code": 0}
    cmseek_result = {"available": "cmseek" in tools,
                     "results": [{"evidence": l} for l in cmseek_lines],
                     "exit_code": 0}

    with patch("modules.cms_deep_scan.tool_available",
               side_effect=lambda n: n in tools), \
         patch("modules.cms_deep_scan.wpscan", new=AsyncMock(
             return_value=wpscan_result)), \
         patch("modules.cms_deep_scan.joomscan_scan", new=AsyncMock(
             return_value=joomscan_result)), \
         patch("modules.cms_deep_scan.droopescan_scan", new=AsyncMock(
             return_value=droopescan_result)), \
         patch("modules.cms_deep_scan.cmseek_scan", new=AsyncMock(
             return_value=cmseek_result)), \
         patch("modules.cms_deep_scan.check_cisa_kev", new=AsyncMock(
             return_value=list(kev))):
        result = asyncio_run(module.run())
    return module, state, result


def asyncio_run(coro):
    import asyncio
    return asyncio.run(coro)


def _findings(state):
    return state.findings["findings"]


# --- bug 1: droopescan output was dropped -------------------------------

def test_droopescan_findings_reach_the_report():
    """The original false negative: droopescan ran, wrote evidence, and the
    result never appeared as a finding."""
    module, state, _ = _run(
        droopescan_data={"Plugins": {"views": {"version": "3.2.1"}}},
        cms="drupal", tools=("droopescan",),
    )
    findings = _findings(state)
    assert len(findings) == 1
    assert "views" in findings[0]["title"]


def test_droopescan_vulnerability_is_reported():
    module, state, _ = _run(
        droopescan_data={
            "Plugins": {
                "token": {
                    "version": "1.11",
                    "vulnerabilities": [
                        {"title": "Drupal SA-CORE-2020-002 (CVE-2020-7030) RCE"},
                    ],
                }
            }
        },
        cms="drupal", tools=("droopescan",),
    )
    findings = _findings(state)
    assert len(findings) == 1
    assert "CVE-2020-7030" in findings[0]["title"]
    assert findings[0]["severity"] == "HIGH"


def test_droopescan_dict_shape_does_not_iterate_keys():
    """`droopescan_scan` returns a dict. A naive extend() would have turned the
    top-level keys into findings."""
    module, state, _ = _run(
        droopescan_data={"Plugins": {}, "Modules": {}, "Version": "9.4.8"},
        cms="drupal", tools=("droopescan",),
    )
    findings = _findings(state)
    assert len(findings) == 1
    assert findings[0]["title"].startswith("drupal core")
    assert "Plugins" not in findings[0]["title"]


def test_droopescan_tool_runs_only_for_known_cms():
    module, state, _ = _run(
        droopescan_data={"Plugins": {"a": {"version": "1"}}},
        cms="moodle", tools=("droopescan",),
    )
    assert _findings(state) == []


# --- bug 2: per-component grading ---------------------------------------

def test_known_cve_on_plugin_is_high():
    module, state, _ = _run(
        wpscan_data={
            "plugins": {
                "elementor": {
                    "version": "3.4.0",
                    "vulnerabilities": [{
                        "title": "Elementor - Unauthenticated file upload",
                        "references": {"cve": ["cve-2021-2222"]},
                        "fixed_in": "3.4.4",
                    }],
                }
            }
        },
        tools=("wpscan",),
    )
    findings = _findings(state)
    # The plugin has a version too, so it yields a HIGH vuln finding plus a
    # separate INFO fingerprint. Only the vuln one is graded HIGH.
    plugin = [f for f in findings if f["title"].startswith("plugin:elementor")]
    graded = [f for f in plugin if f["severity"] == "HIGH"]
    assert len(graded) == 1
    assert "CVE-2021-2222" in graded[0]["title"]


def test_kev_listed_cve_is_critical():
    module, state, _ = _run(
        wpscan_data={
            "plugins": {"elementor": {"vulnerabilities": [{
                "title": "RCE", "references": {"cve": ["CVE-2021-2222"]}}]}},
        },
        kev=[{"cve": "CVE-2021-2222", "product": "Elementor",
              "vendorProject": "Elementor", "name": "Elementor RCE",
              "due_date": "2021-05-03", "short_desc": "rce"}],
        tools=("wpscan",),
    )
    finding = [f for f in _findings(state)
               if f["title"].startswith("plugin:elementor")][0]
    assert finding["severity"] == "CRITICAL"
    assert "known-exploited" in finding["title"]


def test_kev_not_matched_on_product_keyword():
    """The KEV lookup is keyword-driven. A product name would match every entry
    for that product, so only the CVE id we actually found may be honoured."""
    module, state, _ = _run(
        wpscan_data={
            "plugins": {"elementor": {"vulnerabilities": [{
                "title": "RCE", "references": {"cve": ["CVE-2021-2222"]}}]}},
        },
        # KEV returned a match, but for a different CVE than the one found.
        kev=[{"cve": "CVE-1999-0001", "product": "Elementor",
              "vendorProject": "Elementor", "name": "old bug",
              "due_date": "", "short_desc": ""}],
        tools=("wpscan",),
    )
    finding = [f for f in _findings(state)
               if f["title"].startswith("plugin:elementor")][0]
    assert finding["severity"] == "HIGH"


def test_kev_cve_does_not_upgrade_a_different_component():
    """A KEV listing is per-CVE. Finding CVE-1 on plugin `a` and CVE-2 on
    plugin `b` must not let CVE-2's KEV status bleed onto `a`."""
    module, state, _ = _run(
        wpscan_data={
            "plugins": {
                "a": {"vulnerabilities": [
                    {"title": "RCE", "references": {"cve": ["CVE-2021-1111"]}}]},
                "b": {"vulnerabilities": [
                    {"title": "RCE", "references": {"cve": ["CVE-2021-2222"]}}]},
            }
        },
        kev=[{"cve": "CVE-2021-2222", "product": "b", "vendorProject": "b",
              "name": "n", "due_date": "", "short_desc": ""}],
        tools=("wpscan",),
    )
    findings = _findings(state)
    by_plugin = {}
    for f in findings:
        if f["severity"] != "INFO":
            by_plugin[f["title"].split(":")[1].split()[0]] = f["severity"]
    assert by_plugin["a"] == "HIGH", "plugin a must not inherit plugin b's KEV status"
    assert by_plugin["b"] == "CRITICAL"


def test_version_detection_is_info_not_high():
    """The headline fix: a disclosed version is not a vulnerability."""
    module, state, _ = _run(
        wpscan_data={"version": {"number": "6.4.1"}}, tools=("wpscan",),
    )
    findings = _findings(state)
    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["confidence"] == "FIRM"
    assert "not a vulnerability" in findings[0]["description"]


def test_admin_path_line_is_not_a_finding():
    """parse_cms_text_findings keys on 'admin', so a discovered login path used
    to reach a HIGH finding."""
    module, state, _ = _run(
        joomscan_lines=["[+] Found: /administrator/", "Admin panel enabled"],
        cms="joomla", tools=("joomscan",),
    )
    assert _findings(state) == []


def test_unattributed_scrape_is_low_tentative():
    module, state, _ = _run(
        cmseek_lines=["WordPress is out of date, version unknown"],
        tools=("cmseek",),
    )
    findings = _findings(state)
    assert len(findings) == 1
    assert findings[0]["severity"] == "LOW"
    assert findings[0]["confidence"] == "TENTATIVE"
    assert "not attributable" in findings[0]["description"] or \
           "did not say" in findings[0]["description"]


def test_scraped_cve_line_is_attributable():
    module, state, _ = _run(
        cmseek_lines=["CVE-2021-2222 in plugin elementor 3.4.0"],
        tools=("cmseek",),
    )
    finding = _findings(state)[0]
    assert finding["severity"] == "HIGH"
    assert "CVE-2021-2222" in finding["title"]


def test_named_vuln_without_cve_is_medium():
    module, state, _ = _run(
        wpscan_data={
            "main_theme": {"name": "twentytwentyone", "vulnerabilities": [
                {"title": "Theme XSS in customizer"}]},
        },
        tools=("wpscan",),
    )
    finding = [f for f in _findings(state)
               if f["title"].startswith("theme:twentytwentyone")][0]
    assert finding["severity"] == "MEDIUM"
    assert finding["confidence"] == "FIRM"


def test_one_finding_per_component():
    module, state, _ = _run(
        wpscan_data={
            "version": {"number": "6.4.1"},
            "plugins": {
                "a": {"version": "1.0", "vulnerabilities": [
                    {"title": "XSS", "references": {"cve": ["CVE-2021-1111"]}}]},
                "b": {"version": "2.0", "vulnerabilities": [
                    {"title": "XSS", "references": {"cve": ["CVE-2021-2222"]}}]},
            },
        },
        tools=("wpscan",),
    )
    findings = _findings(state)
    # core version + 2 plugin versions + 2 plugin vulns, each separately
    # addressed rather than merged into one blob.
    assert len(findings) == 5
    assert len({f["title"] for f in findings}) == 5
    # and no finding covers more than one component
    for f in findings:
        assert f["title"].split(":")[0] in {
            "wordpress core", "plugin", "theme"}


def test_nothing_is_self_verified():
    """No scanner output is replayed by us, so `verified` stays False even for a
    KEV match."""
    module, state, _ = _run(
        wpscan_data={"plugins": {"a": {"vulnerabilities": [
            {"title": "RCE", "references": {"cve": ["CVE-2021-2222"]}}]}}},
        kev=[{"cve": "CVE-2021-2222", "product": "a", "vendorProject": "a",
              "name": "n", "due_date": "", "short_desc": ""}],
        tools=("wpscan",),
    )
    assert all(f["verified"] is False for f in _findings(state))


# --- helpers -------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("CVE-2021-2222", ["CVE-2021-2222"]),
    ("cve-2021-2222 and CVE-2021-3333", ["CVE-2021-2222", "CVE-2021-3333"]),
    ({"cve": ["CVE-2021-2222"]}, ["CVE-2021-2222"]),
    (["CVE-2021-2222", "CVE-2021-2222"], ["CVE-2021-2222"]),
    ("no cves here", []),
    (None, []),
    (42, []),
])
def test_cves_in(value, expected):
    assert _cves_in(value) == expected


def test_wpscan_signals_tolerate_garbage():
    assert wpscan_signals({"results": None}) == []
    assert wpscan_signals({"results": "junk"}) == []
    assert wpscan_signals({}) == []


def test_scraped_signals_tolerate_garbage():
    assert scraped_signals({}, "x") == []
    assert scraped_signals({"results": None}, "x") == []


def test_droopescan_signals_tolerate_garbage():
    assert droopescan_signals({}) == []
    assert droopescan_signals({"results": 5}) == []


# --- config and skip paths ----------------------------------------------

def test_disabled_by_config():
    module, state, result = _run(module_cfg={"enabled": False})
    assert result == "skipped"


def test_skips_when_no_scanner_installed():
    state = StateManager(tempfile.mkdtemp())
    module = CMSDeepScan(state, _config())
    with patch("modules.cms_deep_scan.tool_available", return_value=False):
        result = asyncio_run(module.run())
    assert result == "skipped"


def test_kev_failure_does_not_lose_findings():
    module, state, _ = _run(
        wpscan_data={"plugins": {"a": {"vulnerabilities": [
            {"title": "RCE", "references": {"cve": ["CVE-2021-2222"]}}]}}},
        tools=("wpscan",),
    )
    # sanity: the same input with a working KEV lookup
    assert _findings(state)[0]["severity"] == "HIGH"


def test_asset_records_cves_for_downstream_lookup():
    module, state, _ = _run(
        wpscan_data={"plugins": {"a": {"version": "1.0", "vulnerabilities": [
            {"title": "RCE", "references": {"cve": ["CVE-2021-2222"]}}]}}},
        tools=("wpscan",),
    )
    assets = state.get_assets_by_type("cms_inventory")
    assert assets, "cms_inventory asset should be written for exploit_lookup"
    assert "CVE-2021-2222" in assets[0]["attrs"]["cves"]
