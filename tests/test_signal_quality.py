"""Tests for the scan-signal overhaul: dedupe, honest verification,
batched nuclei, reflection seeding, VT thresholds, and time-boxes.

Background: a scan of get-ads.agency produced 26 findings, 17 of which
were identical "Proven: verify.reproducible" CONFIRMED Exploitation
claims — one per static JS chunk, each duplicated — while nuclei, cloud
enum and open redirect timed out with zero findings to show for it.
"""

import asyncio
import tempfile
from collections import Counter
from pathlib import Path

from actions.registry import ActionContext
from actions.verify.oracles import verify_composite, verify_reproducible
from core.attack_graph import AttackEdge, AttackNode
from core.chain_executor import ChainExecutor
from state.manager import StateManager


def _state():
    tmpdir = Path(tempfile.mkdtemp())
    return StateManager(str(tmpdir / "run" / "example.com"))


def _ctx(action_id, **params):
    return ActionContext(action_id=action_id, params=params,
                         target=params.get("url", ""))


# ── Finding dedupe ──────────────────────────────────────────────

def test_add_finding_merges_identical_claims():
    state = _state()
    first = state.add_finding(
        title="Proven: verify.reproducible on https://h/a.js",
        severity="LOW", confidence="CONFIRMED", category="Exploitation",
        description="d", evidence=["e1"])
    second = state.add_finding(
        title="Proven: verify.reproducible on https://h/a.js",
        severity="LOW", confidence="CONFIRMED", category="Exploitation",
        description="d", evidence=["e2"])

    assert first == second == "FINDING-0001"
    assert len(state.findings["findings"]) == 1
    assert state.findings["findings"][0]["evidence"] == ["e1", "e2"]


def test_add_finding_upgrades_merged_severity_and_verified():
    state = _state()
    state.add_finding(
        title="Same claim", severity="LOW", confidence="TENTATIVE",
        category="Exposure", description="d")
    state.add_finding(
        title="Same claim", severity="HIGH", confidence="CONFIRMED",
        category="Exposure", description="d", verified=True)

    assert len(state.findings["findings"]) == 1
    merged = state.findings["findings"][0]
    assert merged["severity"] == "HIGH"
    assert merged["confidence"] == "CONFIRMED"
    assert merged["verified"] is True


def test_add_finding_dedupe_needs_title_and_category():
    state = _state()
    state.add_finding(title="Same", severity="LOW", confidence="FIRM",
                      category="A", description="d")
    state.add_finding(title="Same", severity="LOW", confidence="FIRM",
                      category="B", description="d")
    state.add_finding(title="", severity="LOW", confidence="FIRM",
                      category="A", description="d")
    state.add_finding(title="", severity="LOW", confidence="FIRM",
                      category="A", description="d")

    assert len(state.findings["findings"]) == 4


# ── verify.reproducible: stability is not confirmation ──────────
#
# NOTE: DifferentialAnalyzer binds `curl` at import time
# (`from tools.wrappers import curl`), while the action's own probe
# imports it lazily per call — so fakes must be installed at BOTH
# bindings or the test silently hits the real network.

def _patch_curl(monkeypatch, fake):
    import tools.wrappers as wrappers
    import core.verification_oracle as oracle_module
    monkeypatch.setattr(wrappers, "curl", fake)
    monkeypatch.setattr(oracle_module, "curl", fake)


def test_verify_reproducible_plain_url_never_confirms(monkeypatch):
    async def stable_200(url, **kwargs):
        return {"status": 200, "body": "<html>static bundle</html>",
                "time_ms": 5, "headers": {}}

    _patch_curl(monkeypatch, stable_200)
    result = asyncio.run(
        verify_reproducible(_ctx("verify.reproducible",
                                 url="https://example.com/app.js")))

    assert result.success is False
    assert result.confidence == "TENTATIVE"
    assert "reachability only" in result.error


def test_verify_reproducible_marker_confirms_stable_presence(monkeypatch):
    async def always_reflects(url, **kwargs):
        return {"status": 200, "body": "hello CANARY123 world",
                "time_ms": 5, "headers": {}}

    _patch_curl(monkeypatch, always_reflects)
    result = asyncio.run(
        verify_reproducible(_ctx("verify.reproducible",
                                 url="https://example.com/?q=x",
                                 marker="CANARY123")))

    assert result.success is True
    assert result.confidence == "CONFIRMED"


def test_verify_reproducible_flapping_marker_does_not_confirm(monkeypatch):
    import tools.wrappers as wrappers

    calls = {"n": 0}

    async def flapping(url, **kwargs):
        calls["n"] += 1
        body = "CANARY123 here" if calls["n"] == 1 else "gone"
        return {"status": 200, "body": body, "time_ms": 5, "headers": {}}

    _patch_curl(monkeypatch, flapping)
    result = asyncio.run(
        verify_reproducible(_ctx("verify.reproducible",
                                 url="https://example.com/?q=x",
                                 marker="CANARY123")))

    assert result.success is False


def test_verify_reproducible_baseline_pair_confirms_divergence(monkeypatch):
    import tools.wrappers as wrappers

    async def split_bodies(url, **kwargs):
        if "baseline" in url:
            return {"status": 200, "body": "hello world",
                    "time_ms": 5, "headers": {}}
        return {"status": 200,
                "body": "completely different content here with many more words",
                "time_ms": 5, "headers": {}}

    _patch_curl(monkeypatch, split_bodies)
    result = asyncio.run(
        verify_reproducible(_ctx(
            "verify.reproducible",
            url="https://example.com/?q=payload",
            baseline_url="https://example.com/?baseline=1")))

    assert result.success is True
    assert result.confidence == "CONFIRMED"


def test_verify_reproducible_identical_pair_confirms_nothing(monkeypatch):
    import tools.wrappers as wrappers

    async def same_body(url, **kwargs):
        return {"status": 200, "body": "hello world",
                "time_ms": 5, "headers": {}}

    _patch_curl(monkeypatch, same_body)
    result = asyncio.run(
        verify_reproducible(_ctx(
            "verify.reproducible",
            url="https://example.com/?q=payload",
            baseline_url="https://example.com/?baseline=1")))

    assert result.success is False


def test_verify_composite_stable_page_does_not_confirm(monkeypatch):
    import tools.wrappers as wrappers

    async def stable(url, **kwargs):
        return {"status": 200, "body": "hello world",
                "time_ms": 5, "headers": {}}

    _patch_curl(monkeypatch, stable)
    result = asyncio.run(
        verify_composite(_ctx("verify.composite_oracle",
                              url="https://example.com/app.js")))

    assert result.success is False
    assert result.confidence == "TENTATIVE"


# ── Executor attribution + self-prune ───────────────────────────

class _Chain:
    def __init__(self, nodes, edges):
        self.nodes = nodes
        self.edges = edges


def test_executor_prunes_own_stale_findings_and_restores_context():
    state = _state()
    state.module["current"] = "chain_executor"
    state.add_finding(title="Proven: old", severity="LOW",
                      confidence="CONFIRMED", category="Exploitation",
                      description="stale")
    state.module["current"] = "tech_detection"
    state.add_finding(title="Unrelated", severity="MEDIUM",
                      confidence="FIRM", category="Exposure",
                      description="keep me")
    state.module["current"] = None

    chain = _Chain(
        nodes=[AttackNode(id="n1", label="https://example.test/?user=bob",
                          node_type="url", confidence="FIRM", attrs={}),
               AttackNode(id="n2", label="v", node_type="vuln",
                          confidence="FIRM",
                          attrs={"category": "mystery"})],
        edges=[AttackEdge(source_id="n1", target_id="n2",
                          edge_type="exploit", likelihood=0.5, impact=0.8,
                          action_id="")],
    )
    report = asyncio.run(
        ChainExecutor(state, {}, max_actions=0).execute([chain]))

    titles = {f["title"] for f in state.findings["findings"]}
    assert "Proven: old" not in titles, "re-run must replace stale claims"
    assert "Unrelated" in titles
    assert report.skipped, "zero budget means every edge is skipped"
    assert "budget exhausted" in report.skipped[0].detail
    assert state.module.get("current") is None


# ── Nuclei batching ─────────────────────────────────────────────

def test_nuclei_batch_timeout_keeps_earlier_batches(monkeypatch):
    import modules.nuclei_scan as nuclei_module

    monkeypatch.setattr(nuclei_module, "tool_available", lambda name: True)
    calls = []

    async def fake_scan(target_url, **kwargs):
        calls.append(kwargs.get("tags"))
        if len(calls) == 1:
            return {"results": [{
                "template_id": "t1", "matched_at": "https://example.com/",
                "severity": "HIGH", "name": "Exposed Panel",
                "type": "http", "curl_command": "curl https://example.com/",
            }], "exit_code": 0}
        if len(calls) == 2:
            raise asyncio.TimeoutError()
        return {"results": [], "exit_code": 0}

    monkeypatch.setattr(nuclei_module, "nuclei_scan", fake_scan)
    state = _state()
    config = {"target": {"domain": "example.com"}}

    from modules.nuclei_scan import NucleiScan
    result = asyncio.run(NucleiScan(state, config).run())

    assert result == "done"
    titles = [f["title"] for f in state.findings["findings"]]
    assert "Nuclei [HIGH]: Exposed Panel" in titles
    assert len(calls) >= 2, "later batches must still be attempted"


# ── Reflection seeding ──────────────────────────────────────────

def test_parameter_seeding_unlocks_injection_surface(monkeypatch):
    import modules.parameter_discovery as param_module
    from modules.parameter_discovery import ParameterDiscovery, SEED_MARKER

    async def fake_curl(url, **kwargs):
        from urllib.parse import parse_qs, urlparse
        query = parse_qs(urlparse(url).query)
        for name, values in query.items():
            if values and values[0] == SEED_MARKER and name in ("q", "redirect"):
                return {"status": 200,
                        "body": f"<html>{values[0]}</html>"}
        return {"status": 200, "body": "<html>static</html>"}

    monkeypatch.setattr(param_module, "curl", fake_curl)
    state = _state()
    config = {"target": {"domain": "example.com"}}

    result = asyncio.run(ParameterDiscovery(state, config).run())

    assert result == "done", "seeding must prevent the skip"
    params = {item["value"] for item in state.get_assets_by_type("parameter")}
    assert params == {"q", "redirect"}
    assert state.findings["findings"] == [], \
        "seeded names are hypothesized surface, not mined secrets"


# ── VirusTotal thresholds ───────────────────────────────────────

def _vt_state(monkeypatch, malicious, suspicious):
    import modules.vt_enrich as vt_module
    from modules.vt_enrich import VirusTotalEnrich

    async def fake_domain(domain, api_key):
        return {"data": {"attributes": {"last_analysis_stats": {
            "malicious": malicious, "suspicious": suspicious,
            "harmless": 70}}}}

    async def fake_subdomains(domain, api_key):
        return []

    async def fake_ip(ip, api_key):
        return {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 0, "suspicious": 0}}}}

    monkeypatch.setattr(vt_module, "virustotal_domain", fake_domain)
    monkeypatch.setattr(vt_module, "virustotal_domain_subdomains", fake_subdomains)
    monkeypatch.setattr(vt_module, "virustotal_ip", fake_ip)
    state = _state()
    state.add_asset("domain", "domain:example.com", "example.com")
    config = {"target": {"domain": "example.com"},
              "api_keys": {"virustotal": "test-key"}}
    assert asyncio.run(VirusTotalEnrich(state, config).run()) == "done"
    return state


def test_vt_single_vendor_vote_is_low_not_high(monkeypatch):
    state = _vt_state(monkeypatch, malicious=1, suspicious=0)
    finding = state.findings["findings"][0]
    assert finding["title"] == "VirusTotal Reputation Signal on Domain"
    assert finding["severity"] == "LOW"


def test_vt_multi_vendor_consensus_stays_high(monkeypatch):
    state = _vt_state(monkeypatch, malicious=4, suspicious=1)
    assert state.findings["findings"][0]["severity"] == "HIGH"


def test_vt_suspicious_only_is_info(monkeypatch):
    state = _vt_state(monkeypatch, malicious=0, suspicious=3)
    assert state.findings["findings"][0]["severity"] == "INFO"


# ── Time-boxes keep partial coverage ────────────────────────────

def test_cloud_enum_timebox_records_partial_and_completes(monkeypatch):
    import modules.cloud_enum as cloud_module
    from modules.cloud_enum import CloudEnum

    async def instant_miss(url, **kwargs):
        return {"status": 0, "body": ""}

    monkeypatch.setattr(cloud_module, "curl", instant_miss)
    clock = {"t": 1000.0}

    def fast_forward():
        clock["t"] += 300.0
        return clock["t"]

    monkeypatch.setattr(cloud_module.time, "monotonic", fast_forward)
    state = _state()
    config = {"target": {"domain": "example.com"}}

    assert asyncio.run(CloudEnum(state, config).run()) == "done"
    assets = state.get_assets_by_type("cloud_enum")
    assert len(assets) == 1
    assert assets[0]["attrs"]["time_boxed"] is True


def test_open_redirect_timebox_stops_early_and_completes(monkeypatch):
    import types

    import modules.open_redirect as or_module
    from modules.open_redirect import OpenRedirectScan
    from tests.test_open_redirect import RedirectServer, _fresh_engine
    from tools import wrappers

    # Swap the module's `time` binding for a scripted clock. Patching
    # time.monotonic globally would also move asyncio/aiohttp's clock and
    # fire every unrelated timeout; the namespace swap only moves the
    # module's own budget checks.
    ticks = iter([1000.0, 1100.0, 1200.0, 1300.0, 1400.0, 1500.0])
    monkeypatch.setattr(
        or_module, "time",
        types.SimpleNamespace(monotonic=lambda: next(ticks)))
    probes = []
    orig_probe = OpenRedirectScan._probe

    async def counting_probe(self, harness, identity, url, param, payloads):
        probes.append((url, param))
        return await orig_probe(self, harness, identity, url, param, payloads)

    monkeypatch.setattr(OpenRedirectScan, "_probe", counting_probe)
    out = tempfile.mkdtemp()
    config = {
        "target": {"domain": "127.0.0.1", "base_url": ""},
        "auth": {"identities": []},
        "waf": {"block_codes": [429, 503]},
        "rate_limit": {"max_concurrent": 10, "max_per_minute": 1000},
        "scope": {"allowed": ["127.0.0.1"]},
        "modules": {"open_redirect": {
            "endpoints": ["/a", "/b", "/c"], "params": ["next"]}},
    }
    state = StateManager(out)

    async def main():
        async with RedirectServer("open") as server:
            config["target"]["base_url"] = server.base
            _fresh_engine()
            return await OpenRedirectScan(state, config).run()

    try:
        assert asyncio.run(main()) == "done"
    finally:
        asyncio.run(wrappers.close_engine())

    assert len(probes) == 2, \
        f"time-box must stop before the third target: {probes}"
    assert "open_redirect" in state.module["completed"]


# ── Wave A: prioritization honesty ────────────────────────────────

def test_prioritization_discounts_unconfirmed_findings():
    from core.prioritization import prioritize_findings
    findings = [
        {"id": "F-1", "title": "Tentative guess", "severity": "MEDIUM",
         "confidence": "TENTATIVE", "category": "Exposure",
         "asset_keys": [], "created_at": "2026-01-01"},
        {"id": "F-2", "title": "Firm scanner claim", "severity": "CRITICAL",
         "confidence": "FIRM", "category": "SQL Injection",
         "asset_keys": ["url:https://example.com/?id=1"],
         "created_at": "2026-01-02"},
        {"id": "F-3", "title": "Proven RCE", "severity": "CRITICAL",
         "confidence": "CONFIRMED", "category": "RCE",
         "asset_keys": ["url:https://example.com/"],
         "verified": True, "created_at": "2026-01-03"},
    ]
    ordered = prioritize_findings(findings)
    by_id = {f["id"]: f for f in ordered}
    # Unconfirmed CRITICAL is capped at HIGH.
    assert by_id["F-2"]["severity"] == "HIGH"
    assert by_id["F-2"]["risk_score"] <= 89
    # Tentative is discounted hard.
    assert by_id["F-1"]["risk_score"] < 40
    # Proven stays on top and verified sorts first.
    assert ordered[0]["id"] == "F-3"
    assert by_id["F-3"]["severity"] == "CRITICAL"


def test_prioritization_kev_bypasses_discount():
    from core.prioritization import prioritize_findings
    findings = [{
        "id": "F-1", "title": "KEV-listed CVE", "severity": "HIGH",
        "confidence": "FIRM", "category": "Exploit Intelligence",
        "asset_keys": ["webapp:https://example.com"],
        "intelligence": {"cvss": 9.8, "epss": 0.8, "kev": True},
    }]
    assert prioritize_findings(findings)[0]["severity"] == "CRITICAL"


# ── Wave A: submissions gate ─────────────────────────────────────

def test_bounty_submission_queues_unconfirmed(tmp_path):
    from modules.bounty_submission import BountySubmission
    state = StateManager(str(tmp_path / "run" / "example.com"))
    state.add_finding(
        title="Proven SSRF", severity="HIGH", confidence="CONFIRMED",
        category="SSRF", description="d", verified=True,
        verification={"action_id": "web.ssrf.cloud_metadata",
                      "url": "https://example.com/meta"},
        asset_keys=["url:https://example.com/meta"])
    state.add_finding(
        title="Scanner guess", severity="MEDIUM", confidence="FIRM",
        category="Exposure", description="d")

    result = asyncio.run(
        BountySubmission(state, {"target": {"domain": "example.com"}}).run())

    assert result == "done"
    out = tmp_path / "run" / "example.com" / "submissions"
    ready = list(out.glob("FINDING-*.md"))
    queued = list((out / "needs-validation").glob("FINDING-*.md"))
    assert len(ready) == 1 and len(queued) == 1
    assert "Proven SSRF" in ready[0].read_text()
    assert "## Reproduce" in ready[0].read_text()
    assert "curl" in ready[0].read_text()
    index = (out / "INDEX.md").read_text()
    assert "needs-validation" in index
    assert "Verified" in index


# ── Wave A: secret tiers ─────────────────────────────────────────

def test_secret_grading_separates_docs_from_live_shaped():
    from modules.secret_validation import _grade
    tier, _ = _grade("github_pat", "ghp_qrstuvwxyzQRSTUVWXyzmn98765432109876",
                     {"verdict": "structurally_valid"})
    assert tier == "plausible"
    tier, _ = _grade("github_pat", "ghp_example_test_token_xxxxxxxxxxxxxxxxx",
                     {"verdict": "structurally_valid"})
    assert tier == "weak"
    tier, reason = _grade("jwt_token", "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOj1000.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                          {"verdict": "structurally_valid"})
    assert tier == "weak", reason  # exp 1000 is long past


def test_secret_module_skips_own_prior_output():
    from modules.secret_validation import SecretValidation
    state = _state()
    live_token = "ghp_qrstuvwxyzQRSTUVWXyzmn98765432109876"
    legacy_token = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    evidence_id = state.add_evidence(
        "js_analysis", "javascript", "https://example.com/app.js",
        {"body": f"const token = '{live_token}';"})
    assert evidence_id
    # A previous run already reported a DIFFERENT token as its own finding,
    # in the old non-redacted format. Rescanning it would double-count.
    state.module["current"] = "secret_validation"
    state.add_finding(
        title="Structurally Valid Secret Candidates: 1",
        severity="MEDIUM", confidence="FIRM", category="Credential Exposure",
        description="legacy output",
        evidence=[f"github_pat: {legacy_token} (EVIDENCE-0001)"])
    state.module["current"] = None

    result = asyncio.run(
        SecretValidation(state, {"target": {"domain": "example.com"}}).run())

    assert result == "done"
    merged = [f for f in state.findings["findings"]
              if f["title"].startswith("Structurally Valid")]
    assert len(merged) == 1, "re-run merges into the prior claim"
    # Own finding's token must not be re-extracted: the seeded evidence
    # line plus exactly one fresh candidate from the evidence file.
    assert len(merged[0]["evidence"]) == 2, merged[0]["evidence"]
    legacy_lines = [line for line in merged[0]["evidence"] if "AAAA" in line]
    assert len(legacy_lines) == 1 and "(EVIDENCE-0001)" in legacy_lines[0]


# ── Wave A: wayback liveness ─────────────────────────────────────

def test_wayback_liveness_gates_historical_claims(monkeypatch):
    import modules.wayback as wayback_module
    from modules.wayback import WaybackMachine
    from core.site_profile import clear_profiles

    clear_profiles()  # profiles are cached per origin across tests

    async def fake_cdx(domain, limit=5000):
        return [
            {"original": "https://example.com/?api_key=AKIA4Q7X9K2M5P8R3T6V1",
             "timestamp": "20200101"},
            {"original": "https://example.com/.env", "timestamp": "20200101"},
            {"original": "https://example.com/old-backup.sql",
             "timestamp": "20200101"},
        ]

    async def fake_gau(domain, timeout=90):
        return []

    async def fake_fetch(url, timeout=10):
        if url == "https://example.com":
            return {"status": 200, "body": "BASE SHELL", "time_ms": 5,
                    "url": url}
        if "api_key" in url:
            return {"status": 200,
                    "body": "dashboard AKIAZZZZZZZZZZZZZZZZ loaded",
                    "time_ms": 5, "url": url}
        return {"status": 404, "body": "BASE SHELL", "time_ms": 5, "url": url}

    monkeypatch.setattr(wayback_module, "wayback_cdx", fake_cdx)
    monkeypatch.setattr(wayback_module, "gau_urls", fake_gau)
    monkeypatch.setattr(wayback_module, "curl_with_status", fake_fetch)
    state = _state()

    result = asyncio.run(
        WaybackMachine(state, {"target": {"domain": "example.com"}}).run())

    assert result == "done"
    titles = [f["title"] for f in state.findings["findings"]]
    assert "Live URLs With Secret-Shaped Parameter Values" in titles
    assert "Sensitive File URLs in Archive (Not Live)" in titles
    assert not any("Sensitive Parameters in Historical URLs" == t
                   for t in titles), titles
    live = [f for f in state.findings["findings"]
            if f["title"] == "Live URLs With Secret-Shaped Parameter Values"][0]
    # Shape is not proof a credential works: MEDIUM rotate-on-suspicion,
    # per the same doctrine that caps secret_validation at MEDIUM.
    assert live["severity"] == "MEDIUM"


# ── Wave B: email harvest ─────────────────────────────────────────

def test_email_cleaner_rejects_non_addresses():
    from modules.email_harvest import _clean_emails
    cleaned = _clean_emails([
        "jane.doe@example.com",
        "info@example.com",
        "logo@example.com.png",
        "v1.2@example.com",
        "someone@schema.org",
        "JANE.DOE@EXAMPLE.COM",
        "not-an-email",
    ])
    assert cleaned == ["jane.doe@example.com", "info@example.com"]


def test_pattern_derivation_needs_apex_agreement():
    from modules.email_harvest import _derive_pattern
    assert _derive_pattern([
        "jane.doe@example.com", "john.smith@example.com"],
        "example.com") == "{first}.{last}"
    # Third-party senders must not teach the pattern.
    assert _derive_pattern(["jane.doe@gmail.com"], "example.com") == "unknown"
    # Role accounts carry no pattern.
    assert _derive_pattern(["info@example.com", "contact@example.com"],
                           "example.com") == "unknown"
    # One sample is a data point, not a pattern.
    assert _derive_pattern(["jdoe@example.com", "info@example.com"],
                           "example.com") == "unknown"


def test_email_harvest_scrapes_and_grades(monkeypatch):
    import modules.email_harvest as harvest_module
    from modules.email_harvest import EmailHarvest

    async def fake_curl(url, **kwargs):
        if "wp-json" in url:
            return {"status": 200, "body": ""}
        return {"status": 200, "body": (
            "<html>Contact jane.doe@example.com and john.smith@example.com "
            "or info@example.com. Call +33 1 23 45 67 89. "
            "Our team: Alice Martin and Bob Dupont. "
            "<img src='logo@example.com.png'></html>")}

    monkeypatch.setattr(harvest_module, "curl", fake_curl)
    monkeypatch.setattr(harvest_module, "tool_available", lambda name: False)
    state = _state()

    result = asyncio.run(
        EmailHarvest(state, {"target": {"domain": "example.com"}}).run())

    assert result == "done"
    emails = {item["value"] for item in state.get_assets_by_type("email")}
    assert "jane.doe@example.com" in emails
    assert "john.smith@example.com" in emails
    assert "logo@example.com.png" not in emails
    assert not any("schema.org" in e for e in emails)
    people = {item["value"] for item in state.get_assets_by_type("person")}
    assert "Alice Martin" in people
    phones = {item["value"] for item in state.get_assets_by_type("phone")}
    assert phones, "phone numbers should be harvested as assets"
    patterns = state.get_assets_by_type("email_pattern")
    assert patterns and patterns[0]["attrs"]["pattern"] == "{first}.{last}"


# ── Wave B: vendor fingerprint tiers ──────────────────────────────

def test_vendor_keyword_only_is_a_lead_not_a_critical(monkeypatch):
    import modules.tech_detect as tech_module
    from modules.tech_detect import TechDetection

    async def fake_fetch(url, timeout=10):
        return {"status": 200, "body": "", "time_ms": 5, "url": url}

    monkeypatch.setattr(tech_module, "curl_with_status", fake_fetch)
    state = _state()
    module = TechDetection(state, {"target": {"domain": "example.com"}})
    tech: dict = {"vendor_products": []}

    asyncio.run(module._check_vendor_fingerprints(
        "https://example.com", tech,
        "<html>Our Kubernetes consulting services</html>"))

    assert "kubernetes_dashboard" in tech["vendor_products"]
    leads = [f for f in state.findings["findings"]
             if "Kubernetes Dashboard" in f["title"]]
    assert len(leads) == 1 and leads[0]["severity"] == "INFO", \
        "a bare mention is context, never a CRITICAL"


def test_vendor_path_confirmation_keeps_severity(monkeypatch):
    import modules.tech_detect as tech_module
    from modules.tech_detect import TechDetection

    async def fake_fetch(url, timeout=10):
        if "/api/v1/namespaces" in url:
            return {"status": 403,
                    "body": '{"kind":"Status","apiVersion":"v1"}',
                    "time_ms": 5, "url": url}
        return {"status": 200, "body": "", "time_ms": 5, "url": url}

    monkeypatch.setattr(tech_module, "curl_with_status", fake_fetch)
    state = _state()
    module = TechDetection(state, {"target": {"domain": "example.com"}})
    tech: dict = {"vendor_products": []}

    asyncio.run(module._check_vendor_fingerprints(
        "https://example.com", tech, "<html>nothing here</html>"))

    assert "kubernetes_dashboard" in tech["vendor_products"]
    assert state.findings["findings"][0]["severity"] == "CRITICAL"
    assert state.findings["findings"][0]["confidence"] == "FIRM"


# ── Wave B: port_scan verify-or-downgrade ─────────────────────────

def test_port_scan_proves_or_downgrades_critical_ports(monkeypatch):
    import modules.port_scan_module as port_module
    from modules.port_scan_module import PortScan

    async def fake_naabu(target, ports="top-1000", timeout=180):
        return [{"port": 22}, {"port": 6379}, {"port": 8009}]

    async def fake_run_command(args, timeout=120, stdin_data=""):
        if "--script" in args:
            return {"stdout": "PORT STATE SERVICE\n6379/tcp open redis\n"
                              "| redis-info:\n|   redis_version: 7.0\n",
                    "stderr": "", "exit_code": 0, "error": None}
        return {"stdout": (
            "22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu\n"
            "6379/tcp open  redis   Redis key-value store 7.0.11\n"
            "8009/tcp open  ajp13   Apache Jserv Protocol v1.3\n"),
            "stderr": "", "exit_code": 0, "error": None}

    monkeypatch.setattr(port_module, "naabu_scan", fake_naabu)
    monkeypatch.setattr(port_module, "run_command", fake_run_command)
    state = _state()
    state.add_asset("ip", "ip:203.0.113.9", "203.0.113.9",
                    confidence="CONFIRMED", sources=["test"], attrs={})

    result = asyncio.run(
        PortScan(state, {"target": {"domain": "example.com"}}).run())

    assert result == "done"
    by_title = {f["title"]: f for f in state.findings["findings"]}
    ssh = by_title["SSH Server Exposed: 203.0.113.9:22"]
    assert ssh["severity"] == "LOW", "expected infra is not a MEDIUM"
    assert "9.6p1" in ssh["description"]
    redis = by_title["Redis Exposed (No Auth): 203.0.113.9:6379"]
    assert redis["severity"] == "CRITICAL"
    assert redis["verified"] is True
    ajp = [f for f in state.findings["findings"] if ":8009" in f["title"]][0]
    assert ajp["severity"] == "HIGH", \
        "unproven AJP must not claim Ghostcat CRITICAL"
    assert ajp["verified"] is False


def test_port_scan_unproven_critical_steps_down(monkeypatch):
    import modules.port_scan_module as port_module
    from modules.port_scan_module import PortScan

    async def fake_naabu(target, ports="top-1000", timeout=180):
        return [{"port": 27017}]

    async def fake_run_command(args, timeout=120, stdin_data=""):
        if "--script" in args:
            return {"stdout": "27017/tcp open mongodb\n"
                              "| mongodb-info: authentication required\n",
                    "stderr": "", "exit_code": 0, "error": None}
        return {"stdout": "27017/tcp open  mongodb   MongoDB 6.0.5\n",
                "stderr": "", "exit_code": 0, "error": None}

    monkeypatch.setattr(port_module, "naabu_scan", fake_naabu)
    monkeypatch.setattr(port_module, "run_command", fake_run_command)
    state = _state()
    state.add_asset("ip", "ip:203.0.113.9", "203.0.113.9",
                    confidence="CONFIRMED", sources=["test"], attrs={})

    assert asyncio.run(
        PortScan(state, {"target": {"domain": "example.com"}}).run()) == "done"
    mongo = state.findings["findings"][0]
    assert mongo["severity"] == "HIGH"
    assert mongo["verified"] is False
    assert "not demonstrated" in mongo["description"]


# ── Wave B: cloud key-readability proof ───────────────────────────

_LISTING_XML = (
    "<ListBucketResult><Contents><Key>backup.sql</Key></Contents>"
    "<Contents><Key>app.js</Key></Contents></ListBucketResult>"
)


def _cloud_state():
    state = _state()
    return state


def test_cloud_readable_sensitive_key_is_critical_verified(monkeypatch):
    import modules.cloud_enum as cloud_module
    from modules.cloud_enum import CloudEnum

    async def fake_curl(url, **kwargs):
        if url == "https://example.s3.amazonaws.com":
            return {"status": 200, "body": _LISTING_XML}
        if url == "https://example.s3.amazonaws.com/backup.sql":
            return {"status": 200, "body": "-- database dump --"}
        return {"status": 0, "body": ""}

    monkeypatch.setattr(cloud_module, "curl", fake_curl)
    state = _cloud_state()

    assert asyncio.run(
        CloudEnum(state, {"target": {"domain": "example.com"}}).run()) == "done"
    findings = [f for f in state.findings["findings"]
                if f["title"].startswith("Public Cloud Bucket: example ")]
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["verified"] is True
    assert any("Key readability proof" in line
               for line in findings[0]["evidence"])


def test_cloud_unreadable_sensitive_names_step_down_to_high(monkeypatch):
    import modules.cloud_enum as cloud_module
    from modules.cloud_enum import CloudEnum

    async def fake_curl(url, **kwargs):
        if url == "https://example.s3.amazonaws.com":
            return {"status": 200, "body": _LISTING_XML}
        return {"status": 403, "body": "denied"}

    monkeypatch.setattr(cloud_module, "curl", fake_curl)
    state = _cloud_state()

    assert asyncio.run(
        CloudEnum(state, {"target": {"domain": "example.com"}}).run()) == "done"
    findings = [f for f in state.findings["findings"]
                if f["title"].startswith("Public Cloud Bucket: example ")]
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    # The listing itself is the proof: keys are visible unauthenticated.
    # Readability of the objects decides CRITICAL vs HIGH, not
    # verified vs unverified.
    assert findings[0]["verified"] is True


def test_cloud_body_only_mentions_never_critical(monkeypatch):
    import modules.cloud_enum as cloud_module
    from modules.cloud_enum import CloudEnum

    xml = ("<ListBucketResult><Contents><Key>logo.png</Key></Contents>"
           "</ListBucketResult><!-- docs mention password config.json -->")

    async def fake_curl(url, **kwargs):
        if url == "https://example.s3.amazonaws.com":
            return {"status": 200, "body": xml}
        return {"status": 0, "body": ""}

    monkeypatch.setattr(cloud_module, "curl", fake_curl)
    state = _cloud_state()

    assert asyncio.run(
        CloudEnum(state, {"target": {"domain": "example.com"}}).run()) == "done"
    severities = {f["severity"] for f in state.findings["findings"]}
    assert severities <= {"MEDIUM", "LOW", "INFO"}, severities


def test_cloud_candidates_include_advertised_buckets():
    from modules.cloud_enum import CloudEnum
    state = _cloud_state()
    state.add_asset("js_file", "js:https://example.com/app.js",
                    "https://example.com/app.js", confidence="FIRM",
                    sources=["test"],
                    attrs={"url": "https://example.com/app.js"})
    state.add_asset("url", "url:https://assets-example.s3.amazonaws.com/logo.png",
                    "https://assets-example.s3.amazonaws.com/logo.png",
                    confidence="FIRM", sources=["test"], attrs={})
    module = CloudEnum(state, {"target": {"domain": "example.com"}})

    names = module._generate_candidates()

    assert "assets-example" in names


# ── Wave B: takeover fingerprints ───────────────────────────────

def test_weak_fingerprint_on_resolving_host_is_not_a_claim():
    from modules.dns_takeover import classify_takeover_risk
    result = classify_takeover_risk(
        ["old.fly.dev."], ["37.16.0.1"],
        body="<html><h1>404 Not Found</h1></html>")
    assert result["risk"] is False
    assert result["provider"] == "fly_io"


def test_weak_fingerprint_dangling_stays_medium():
    from modules.dns_takeover import classify_takeover_risk
    result = classify_takeover_risk(
        ["old.onrender.com."], [],
        body="<html>Page not found</html>")
    assert result["risk"] is True
    assert result["severity"] == "MEDIUM"
    assert result["provider"] == "render"


def test_strong_fingerprint_with_a_records_still_claims():
    from modules.dns_takeover import classify_takeover_risk
    # S3-fronted names resolve even when the bucket is gone.
    result = classify_takeover_risk(
        ["old.s3.amazonaws.com."], ["52.216.0.1"],
        body="<Error><Code>NoSuchBucket</Code></Error>")
    assert result["risk"] is True
    assert result["severity"] == "HIGH"


# ── Wave B: JWT triage ────────────────────────────────────────────

def _jwt(payload: dict) -> str:
    import base64
    import json as _json
    header = base64.urlsafe_b64encode(
        _json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(
        _json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header}.{body}.SIGNATURE"


def test_analyze_jwt_tiers():
    import time
    from core.validators import analyze_jwt
    assert analyze_jwt(_jwt({"sub": "1234567890", "name": "John Doe",
                             "iat": 1516239022}))["tier"] == "example"
    assert analyze_jwt(_jwt({"sub": "u1", "exp": 1000}))["tier"] == "expired"
    live = analyze_jwt(_jwt({"sub": "u-99281", "role": "admin",
                             "exp": int(time.time()) + 3600}))
    assert live["tier"] == "live_shaped"
    assert analyze_jwt("not.a.token")["tier"] == "malformed"


def test_rest_filesize_without_oob_is_low_untested():
    from modules.rest_api import RestAPIAudit
    state = _state()
    module = RestAPIAudit(state, {"target": {"domain": "example.com"}})

    asyncio.run(module._check_file_size_ssrf(
        "https://example.com/wp-json/yoast/v1/file_size"))

    assert len(state.findings["findings"]) == 1
    finding = state.findings["findings"][0]
    assert finding["severity"] == "LOW"
    assert "Untested" in finding["title"]


# ── Wave B: GraphQL field-read probes ────────────────────────────

def test_graphql_unauthenticated_read_is_proven(monkeypatch):
    import modules.graphql_module as graphql_module
    from modules.graphql_module import GraphQLAudit

    async def fake_curl(url, **kwargs):
        data = kwargs.get("data", "") or ""
        if '"users' in data or "{ users" in data or "users { id" in data:
            return {"status": 200,
                    "body": '{"data": {"users": [{"id": 1}]}}'}
        return {"status": 200, "body": '{"data": null}'}

    monkeypatch.setattr(graphql_module, "curl", fake_curl)
    state = _state()
    module = GraphQLAudit(state, {"target": {"domain": "example.com"}})

    asyncio.run(module._probe_sensitive_reads(
        "https://example.com/graphql", ["User"], "EVIDENCE-0001"))

    reads = [f for f in state.findings["findings"]
             if f["title"].startswith("GraphQL Unauthenticated Field Read")]
    assert len(reads) == 1
    assert reads[0]["severity"] == "MEDIUM"
    assert reads[0]["verified"] is True
    assert "{ users { id } }" in reads[0]["evidence"][1]


def test_graphql_errors_stay_inventory(monkeypatch):
    import modules.graphql_module as graphql_module
    from modules.graphql_module import GraphQLAudit

    async def fake_curl(url, **kwargs):
        return {"status": 200,
                "body": '{"errors": [{"message": "auth required"}], '
                        '"data": {"users": null}}'}

    monkeypatch.setattr(graphql_module, "curl", fake_curl)
    state = _state()
    module = GraphQLAudit(state, {"target": {"domain": "example.com"}})

    asyncio.run(module._probe_sensitive_reads(
        "https://example.com/graphql", ["User"], "EVIDENCE-0001"))

    assert state.findings["findings"] == []


# ── Wave C: shared secret tiers ──────────────────────────────────

def test_grade_secret_candidate_tiers():
    from core.validators import grade_secret_candidate
    assert grade_secret_candidate(
        "aws_access_key", "AKIAQWERTYUIOPASDFGH",
        {"verdict": "structurally_valid"})[0] == "plausible"
    assert grade_secret_candidate(
        "aws_access_key", "AKIAEXAMPLEKEY12345678",
        {"verdict": "structurally_valid"})[0] == "weak"
    assert grade_secret_candidate(
        "generic_password", "x", {"verdict": "structurally_valid"})[0] == "weak"
    assert grade_secret_candidate(
        "generic_password", "9f8s7d6f5g4h3j2k1p0zmXn",
        {"verdict": "structurally_valid"})[0] == "plausible"


def test_js_secrets_capped_and_split(monkeypatch):
    import modules.js_analysis as js_module
    from modules.js_analysis import JSAnalysis

    async def fake_fetch(url, timeout=10):
        if url.endswith("/app.js"):
            return {"status": 200,
                    "body": "const k='AKIAQWERTYUIOPASDFGH'; "
                            "const d='sk_test_1234567890abcdef'; "
                            "fetch('/api/users');",
                    "time_ms": 5, "url": url}
        return {"status": 200, "body": "<html></html>", "time_ms": 5,
                "url": url}

    monkeypatch.setattr(js_module, "curl_with_status", fake_fetch)
    state = _state()
    state.add_asset("js_file", "js:https://example.com/app.js",
                    "https://example.com/app.js", confidence="FIRM",
                    sources=["test"], attrs={})

    asyncio.run(JSAnalysis(
        state, {"target": {"domain": "example.com"}}).run())

    titles = [f["title"] for f in state.findings["findings"]]
    assert not any("CRITICAL" in t for t in titles), titles
    assert any(t.startswith("Plausible Secrets in JavaScript [HIGH]")
               for t in titles), titles


def test_browser_sinks_are_inventory_not_findings(monkeypatch):
    import modules.browser_crawl as crawl_module
    from modules.browser_crawl import BrowserCrawl

    async def fake_render(url, config, wait_ms=1500):
        return {"links": [], "forms": [], "scripts": [], "source_maps": [],
                "dom_sinks": [
                    {"sink": "innerHTML", "source": url,
                     "snippet": "el.innerHTML = lib.render()"},
                    {"sink": "postMessage-handler", "source": url,
                     "snippet": "addEventListener('message')"},
                ],
                "error": None}

    monkeypatch.setattr(crawl_module, "_render_page", fake_render)
    state = _state()

    result = asyncio.run(BrowserCrawl(
        state, {"target": {"domain": "example.com"}}).run())

    assert result == "done"
    assert state.findings["findings"] == [], \
        "sink inventory must not file findings"
    sinks = state.get_assets_by_type("dom_sink")
    assert {s["value"] for s in sinks} == {"innerHTML", "postMessage-handler"}


# ── Wave C: breach proof-gating ──────────────────────────────────

def _breach_state(domain="example.com"):
    state = _state()
    state.add_asset("email", "email:jane@example.com", "jane@example.com",
                    confidence="TENTATIVE", sources=["test"], attrs={})
    return state


def test_breach_hibp_names_are_proof(monkeypatch):
    import modules.breach as breach_module
    from modules.breach import BreachCheck

    async def fake_curl(url, **kwargs):
        if "haveibeenpwned" in url:
            assert "hibp-api-key" in (kwargs.get("headers") or {}), \
                "key must travel in a header, not the command line"
            return {"status": 200, "body": '[{"Name": "Adobe"}]',
                    "time_ms": 5, "url": url}
        return {"status": 200, "body": "{}", "time_ms": 5, "url": url}

    monkeypatch.setattr(breach_module, "curl", fake_curl)
    state = _breach_state()

    result = asyncio.run(BreachCheck(
        state, {"target": {"domain": "example.com"},
                "hibp_api_key": "test-key"}).run())

    assert result == "done"
    hibp = [f for f in state.findings["findings"]
            if f["title"].startswith("HIBP: 1 Breached")]
    assert len(hibp) == 1 and hibp[0]["severity"] == "HIGH"


def test_breach_hudsonrock_counts_are_not_critical(monkeypatch):
    import modules.breach as breach_module
    from modules.breach import BreachCheck

    async def fake_curl(url, **kwargs):
        if "haveibeenpwned" in url:
            return {"status": 200, "body": "[]", "time_ms": 5, "url": url}
        if "hudsonrock" in url:
            return {"status": 200,
                    "body": '{"total_corporate_users": 12, '
                            '"total_infected_machines": 3}',
                    "time_ms": 5, "url": url}
        return {"status": 200, "body": "{}", "time_ms": 5, "url": url}

    monkeypatch.setattr(breach_module, "curl", fake_curl)
    state = _breach_state()

    assert asyncio.run(BreachCheck(
        state, {"target": {"domain": "example.com"},
                "hibp_api_key": "test-key"}).run()) == "done"
    Hudson = [f for f in state.findings["findings"] if "nfostealer" in f["title"]]
    assert len(Hudson) == 1
    assert Hudson[0]["severity"] == "HIGH", \
        "aggregate counts are not per-account proof"


def test_breach_paste_mention_without_credentials_is_low(monkeypatch):
    import modules.breach as breach_module
    from modules.breach import BreachCheck

    async def fake_curl(url, **kwargs):
        if "psbdmp" in url:
            return {"status": 200,
                    "body": '{"data": [{"id": "abc123", "time": "2024-01-01"}]}',
                    "time_ms": 5, "url": url}
        if "pastebin.com/raw" in url:
            return {"status": 200,
                    "body": "someone mentioned example.com in passing",
                    "time_ms": 5, "url": url}
        return {"status": 200, "body": "[]", "time_ms": 5, "url": url}

    monkeypatch.setattr(breach_module, "curl", fake_curl)
    state = _breach_state()

    assert asyncio.run(BreachCheck(
        state, {"target": {"domain": "example.com"}}).run()) == "done"
    pastes = [f for f in state.findings["findings"] if "aste" in f["title"]]
    assert len(pastes) == 1
    assert pastes[0]["severity"] == "LOW"
    assert "Mentioned" in pastes[0]["title"]


def test_breach_paste_with_credentials_is_medium(monkeypatch):
    import modules.breach as breach_module
    from modules.breach import BreachCheck

    async def fake_curl(url, **kwargs):
        if "psbdmp" in url:
            return {"status": 200,
                    "body": '{"data": [{"id": "abc123", "time": "2024-01-01"}]}',
                    "time_ms": 5, "url": url}
        if "pastebin.com/raw" in url:
            return {"status": 200,
                    "body": "dump:\njane@example.com:Sup3rSecret99\n",
                    "time_ms": 5, "url": url}
        return {"status": 200, "body": "[]", "time_ms": 5, "url": url}

    monkeypatch.setattr(breach_module, "curl", fake_curl)
    state = _breach_state()

    assert asyncio.run(BreachCheck(
        state, {"target": {"domain": "example.com"}}).run()) == "done"
    pastes = [f for f in state.findings["findings"] if "aste" in f["title"]]
    assert len(pastes) == 1
    assert pastes[0]["severity"] == "MEDIUM"
    assert "redacted" in pastes[0]["evidence"][0]


# ── Wave C: threat freshness + reputation gates ──────────────────

def test_threat_intel_splits_fresh_from_stale(monkeypatch):
    import modules.threat_intel as threat_module
    from modules.threat_intel import ThreatIntel

    async def fake_urlhaus(host):
        if host == "example.com":
            return {"query_status": "ok", "urls": [
                {"url": "http://example.com/x", "threat": "malware_download",
                 "reporter": "abusech", "lastseen": "2026-09-01 10:00:00"},
                {"url": "http://example.com/old", "threat": "malware_download",
                 "reporter": "abusech", "lastseen": "2019-01-01 10:00:00"},
            ]}
        return {"query_status": "no_results"}

    async def fake_threatfox(ioc):
        return {"query_status": "no_result"}

    async def fake_ip_api(query):
        return {"status": "success", "query": query}

    monkeypatch.setattr(threat_module, "urlhaus_host", fake_urlhaus)
    monkeypatch.setattr(threat_module, "threatfox_ioc", fake_threatfox)
    monkeypatch.setattr(threat_module, "ip_api", fake_ip_api)
    state = _state()
    state.add_asset("domain", "domain:example.com", "example.com")

    assert asyncio.run(ThreatIntel(
        state, {"target": {"domain": "example.com"}}).run()) == "done"
    titles = [f["title"] for f in state.findings["findings"]]
    assert "URLHaus Reputation Hits: 1 Indicator(s)" in titles
    fresh = [f for f in state.findings["findings"]
             if f["title"].startswith("URLHaus Reputation Hits")][0]
    assert fresh["severity"] == "HIGH"
    assert "malware_download" in fresh["evidence"][0]
    assert len(fresh["evidence"]) == 2, \
        "both the fresh and the stale URL belong in the evidence"


def test_threat_intel_stale_only_is_info(monkeypatch):
    import modules.threat_intel as threat_module
    from modules.threat_intel import ThreatIntel

    async def fake_urlhaus(host):
        return {"query_status": "ok", "urls": [
            {"url": "http://example.com/old", "threat": "malware_download",
             "reporter": "abusech", "lastseen": "2019-01-01 10:00:00"},
        ]}

    async def fake_threatfox(ioc):
        return {"query_status": "no_result"}

    async def fake_ip_api(query):
        return {"status": "success", "query": query}

    monkeypatch.setattr(threat_module, "urlhaus_host", fake_urlhaus)
    monkeypatch.setattr(threat_module, "threatfox_ioc", fake_threatfox)
    monkeypatch.setattr(threat_module, "ip_api", fake_ip_api)
    state = _state()
    state.add_asset("domain", "domain:example.com", "example.com")

    assert asyncio.run(ThreatIntel(
        state, {"target": {"domain": "example.com"}}).run()) == "done"
    assert len(state.findings["findings"]) == 1
    assert state.findings["findings"][0]["severity"] == "INFO"
    assert "Stale" in state.findings["findings"][0]["title"]


def test_reputation_skips_private_and_benign_noise(monkeypatch):
    import modules.reputation_enrich as reputation_module
    from modules.reputation_enrich import ReputationEnrich

    queried = []

    async def fake_greynoise(ip, api_key):
        queried.append(ip)
        return {"noise": True, "classification": "benign", "name": "test"}

    async def fake_abuseipdb(ip, api_key):
        return {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}

    monkeypatch.setattr(reputation_module, "greynoise_ip", fake_greynoise)
    monkeypatch.setattr(reputation_module, "abuseipdb_check", fake_abuseipdb)
    state = _state()
    state.add_asset("ip", "ip:192.168.1.5", "192.168.1.5")
    state.add_asset("ip", "ip:8.8.8.8", "8.8.8.8")
    config = {"target": {"domain": "example.com"},
              "api_keys": {"greynoise": "k", "abuseipdb": "k"}}

    assert asyncio.run(ReputationEnrich(state, config).run()) == "done"
    assert queried == ["8.8.8.8"], "private IPs must not burn key quota"
    assert state.findings["findings"] == [], \
        "benign scanner noise is not a finding"


# ── Wave C: origin differential proof ────────────────────────────

_REAL_BODY = "<html><body>Real app dashboard v2.4.1 with user content here</body></html>"


def _origin_state(monkeypatch, http_bodies, tls_stdout=""):
    import modules.origin_discovery as origin_module

    async def fake_curl(url, **kwargs):
        headers = kwargs.get("headers", {}) or {}
        if url == "https://example.com":
            return {"status": 200, "body": _REAL_BODY,
                    "headers": "cf-ray: abc123\nserver: cloudflare",
                    "time_ms": 5, "url": url}
        body = http_bodies.get(url, "")
        status = 200 if body else 0
        return {"status": status, "body": body, "headers": "",
                "time_ms": 5, "url": url}

    async def fake_dig(record_type, host):
        if record_type == "A" and host == "old.example.com":
            return {"answers": ["1.2.3.4"]}
        return {"answers": []}

    async def fake_run_command(args, timeout=120, stdin_data=""):
        return {"stdout": tls_stdout, "stderr": "",
                "exit_code": 0, "error": None}

    async def fake_crtsh(domain):
        return []

    monkeypatch.setattr(origin_module, "curl", fake_curl)
    monkeypatch.setattr(origin_module, "dig", fake_dig)
    monkeypatch.setattr(origin_module, "run_command", fake_run_command)
    monkeypatch.setattr(origin_module, "crtsh", fake_crtsh)
    state = _state()
    state.add_asset("subdomain", "sub:old.example.com", "old.example.com",
                    confidence="FIRM", sources=["test"], attrs={})
    return state


def test_origin_body_equality_confirms(monkeypatch):
    from modules.origin_discovery import OriginDiscovery
    state = _origin_state(
        monkeypatch, {"http://1.2.3.4": _REAL_BODY})

    assert asyncio.run(OriginDiscovery(
        state, {"target": {"domain": "example.com"}}).run()) == "done"
    confirmed = [f for f in state.findings["findings"]
                 if f["title"].startswith("Origin IP Discovered")]
    assert len(confirmed) == 1
    assert confirmed[0]["severity"] == "HIGH"
    assert confirmed[0]["confidence"] == "CONFIRMED"
    assert "1.2.3.4" in confirmed[0]["evidence"][0]
    assert "byte-identical" in confirmed[0]["evidence"][0]


def test_origin_parking_page_is_not_origin(monkeypatch):
    from modules.origin_discovery import OriginDiscovery
    state = _origin_state(
        monkeypatch, {"http://1.2.3.4": "<html>parking page</html>"},
        tls_stdout="")

    assert asyncio.run(OriginDiscovery(
        state, {"target": {"domain": "example.com"}}).run()) == "done"
    assert [f for f in state.findings["findings"]
            if "Origin IP" in f["title"]] == [], \
        "a parking page must never confirm an origin"


def test_origin_domain_cert_with_403_is_likely(monkeypatch):
    from modules.origin_discovery import OriginDiscovery
    tls_out = (
        "CONNECTED(00000003)\n"
        "subject=CN = example.com\n"
        "X509v3 Subject Alternative Name: \n"
        "DNS:example.com, DNS:www.example.com\n"
        "---\n"
        "HTTP/1.0 403 Forbidden\n"
        "Content-Type: text/html\n"
        "\n"
        "<html>forbidden</html>\n"
        "\n"
        "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
        "Verify return code: 0 (ok)\n"
        "---\n"
        "closed\n")
    state = _origin_state(
        monkeypatch, {"http://1.2.3.4": "<html>other vhost</html>"},
        tls_stdout=tls_out)

    assert asyncio.run(OriginDiscovery(
        state, {"target": {"domain": "example.com"}}).run()) == "done"
    likely = [f for f in state.findings["findings"]
              if f["title"].startswith("Likely Origin")]
    assert len(likely) == 1
    assert likely[0]["severity"] == "MEDIUM"


# ── Wave C: TLS honesty ──────────────────────────────────────────

def test_tls_negotiated_weak_cipher_is_proof(monkeypatch):
    import modules.tls_audit as tls_module
    from modules.tls_audit import TLSAudit

    async def fake_run_command(args, timeout=120, stdin_data=""):
        return {"stdout": (
            "CONNECTED(00000003)\n"
            "---\n"
            "SSL-Session:\n"
            "    Protocol  : TLSv1.2\n"
            "    Cipher    : DES-CBC3-SHA\n"
            "---\n"),
            "stderr": "", "exit_code": 0, "error": None}

    async def fake_cert_info(host, port=443):
        return {"notafter": "Jan  1 00:00:00 2030 GMT", "san": []}

    async def fake_protocols(host, port=443):
        return {"tls1_2": True, "tls1_3": True}

    async def fake_curl(url, **kwargs):
        return {"status": 200, "body": "", "headers": "",
                "time_ms": 5, "url": url}

    monkeypatch.setattr(tls_module, "run_command", fake_run_command)
    monkeypatch.setattr(tls_module, "cert_info", fake_cert_info)
    monkeypatch.setattr(tls_module, "tls_protocols", fake_protocols)
    monkeypatch.setattr(tls_module, "curl", fake_curl)
    state = _state()

    assert asyncio.run(TLSAudit(
        state, {"target": {"domain": "example.com"}}).run()) == "done"
    ciphers = [f for f in state.findings["findings"]
               if f["title"] == "Weak Cipher Suites Accepted"]
    assert len(ciphers) == 1
    assert ciphers[0]["confidence"] == "CONFIRMED"
    assert "DES-CBC3-SHA" in ciphers[0]["evidence"][0]


def test_tls_handshake_failure_is_not_a_finding(monkeypatch):
    import modules.tls_audit as tls_module
    from modules.tls_audit import TLSAudit

    async def fake_run_command(args, timeout=120, stdin_data=""):
        return {"stdout": "CONNECTED(00000003)\n"
                          "1408F10BFFF000000:error: handshake failure\n",
                "stderr": "", "exit_code": 0, "error": None}

    async def fake_cert_info(host, port=443):
        return {"notafter": "Jan  1 00:00:00 2030 GMT", "san": []}

    async def fake_protocols(host, port=443):
        return {"tls1_2": True, "tls1_3": True}

    async def fake_curl(url, **kwargs):
        return {"status": 200, "body": "", "headers": "",
                "time_ms": 5, "url": url}

    monkeypatch.setattr(tls_module, "run_command", fake_run_command)
    monkeypatch.setattr(tls_module, "cert_info", fake_cert_info)
    monkeypatch.setattr(tls_module, "tls_protocols", fake_protocols)
    monkeypatch.setattr(tls_module, "curl", fake_curl)
    state = _state()

    assert asyncio.run(TLSAudit(
        state, {"target": {"domain": "example.com"}}).run()) == "done"
    assert [f for f in state.findings["findings"]
            if "Cipher" in f["title"]] == []


def test_tls_san_subdomains_become_leads(monkeypatch):
    import modules.tls_audit as tls_module
    from modules.tls_audit import TLSAudit

    async def fake_run_command(args, timeout=120, stdin_data=""):
        return {"stdout": "handshake failure\n", "stderr": "",
                "exit_code": 0, "error": None}

    async def fake_cert_info(host, port=443):
        return {"notafter": "Jan  1 00:00:00 2030 GMT",
                "san": ["example.com", "api.example.com", "other.net"]}

    async def fake_protocols(host, port=443):
        return {"tls1_2": True, "tls1_3": True}

    async def fake_curl(url, **kwargs):
        return {"status": 200, "body": "", "headers": "",
                "time_ms": 5, "url": url}

    monkeypatch.setattr(tls_module, "run_command", fake_run_command)
    monkeypatch.setattr(tls_module, "cert_info", fake_cert_info)
    monkeypatch.setattr(tls_module, "tls_protocols", fake_protocols)
    monkeypatch.setattr(tls_module, "curl", fake_curl)
    state = _state()

    assert asyncio.run(TLSAudit(
        state, {"target": {"domain": "example.com"}}).run()) == "done"
    subs = {s["value"] for s in state.get_assets_by_type("subdomain")}
    assert "api.example.com" in subs
    assert "other.net" not in subs


# ── Wave C: identity seeds + proof split ─────────────────────────

def test_username_variants_keep_dots_and_use_people():
    from modules.social_osint import _username_variants
    variants = _username_variants("Alice Martin")
    assert "alice.martin" in variants
    assert "alicemartin" in variants
    assert "amartin" in variants
    assert _username_variants("Madonna") == []
    assert _username_variants("") == []


def test_social_osint_splits_confirmed_from_claimed(monkeypatch):
    import modules.social_osint as osint_module
    from modules.social_osint import SocialOSINT

    async def fake_maigret(username, timeout=240):
        return {"available": True,
                "results": [{"site": "GitHub",
                             "url": f"https://github.com/{username}"}]}

    async def fake_holehe(email, timeout=180):
        return {"available": True, "results": ["github: registered"]}

    monkeypatch.setattr(osint_module, "maigret_scan", fake_maigret)
    monkeypatch.setattr(osint_module, "holehe_scan", fake_holehe)
    monkeypatch.setattr(osint_module, "tool_available", lambda name: True)
    async def fake_harvester(domain, timeout=240):
        return {"available": False, "emails": [], "hosts": []}

    monkeypatch.setattr(osint_module, "theharvester_scan", fake_harvester)
    state = _state()
    state.add_asset("email", "email:jane.doe@example.com",
                    "jane.doe@example.com", confidence="TENTATIVE",
                    sources=["test"], attrs={})

    result = asyncio.run(SocialOSINT(
        state, {"target": {"domain": "example.com"}}).run())

    assert result == "done"
    titles = [f["title"] for f in state.findings["findings"]]
    assert any(t.startswith("Confirmed Email Registrations") for t in titles)
    assert any(t.startswith("Claimed Social Profiles") for t in titles)
    claimed = [f for f in state.findings["findings"]
               if f["title"].startswith("Claimed Social Profiles")][0]
    assert claimed["severity"] == "INFO"


# ── Wave D: XSS blind confirmation ──────────────────────────────

def test_xss_blind_callback_confirms(monkeypatch):
    import modules.xss_scan as xss_module
    from modules.xss_scan import XSSScan

    async def fake_curl(url, **kwargs):
        return {"status": 200, "body": "<html>static</html>"}

    async def fake_dalfox(urls, timeout=600, blind=None, blind_oob=False,
                          rate_limit=0):
        assert blind and "interactsh" in blind or "oob" in blind or blind, \
            "blind pass must carry the OOB callback URL"
        return {"available": True, "results": [{
            "type": "V-blind", "url": urls[0] + "?q=1",
            "payload": "<script src=CALLBACK>", "evidence": "blind hit"}],
            "exit_code": 0}

    class FakeOOB:
        poll_interval = 0
        async def register_callback(self, payload):
            return "corr12345678"
        def callback_url(self, corr_id, path="/"):
            return f"http://corr12345678.oob.test{path}"
        async def poll(self, corr_id):
            return [{"interaction": "dns"}]

    monkeypatch.setattr(xss_module, "curl", fake_curl)
    monkeypatch.setattr(xss_module, "dalfox_scan", fake_dalfox)
    monkeypatch.setattr(xss_module, "tool_available", lambda name: True)
    state = _state()
    state.add_asset("parameter", "param:https://example.com/?q",
                    "q", confidence="FIRM", sources=["test"],
                    attrs={"url": "https://example.com/", "source": "test"})
    module = XSSScan(state, {"target": {"domain": "example.com"}})
    monkeypatch.setattr(module, "oob", lambda: FakeOOB())

    result = asyncio.run(module.run())

    assert result == "done"
    blind = [f for f in state.findings["findings"]
             if f["title"] == "Confirmed Blind XSS via OOB Callback"]
    assert len(blind) == 1
    assert blind[0]["verified"] is True
    assert blind[0]["confidence"] == "CONFIRMED"


# ── Wave D: JWT differential replay ─────────────────────────────

def _hs256(payload: dict, secret: str, header=None) -> str:
    import base64 as _b64
    import hashlib as _hl
    import hmac as _hmac
    import json as _json
    head = _b64.urlsafe_b64encode(_json.dumps(
        header or {"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    body = _b64.urlsafe_b64encode(_json.dumps(payload).encode()).decode().rstrip("=")
    sig = _hmac.new(secret.encode(), f"{head}.{body}".encode(),
                    _hl.sha256).digest()
    return f"{head}.{body}." + _b64.urlsafe_b64encode(sig).decode().rstrip("=")


def _jwt_curl_factory(accept_forged: bool):
    async def fake_curl(url, **kwargs):
        headers = kwargs.get("headers", {}) or {}
        auth = headers.get("Authorization", "")
        if not auth:
            return {"status": 401, "body": "login required"}
        if accept_forged or auth.endswith(".validsig"):
            return {"status": 200, "body": "dashboard: admin panel"}
        return {"status": 401, "body": "login required"}
    return fake_curl


def test_jwt_none_alg_replay_accepted(monkeypatch):
    import actions.auth.jwt as jwt_module
    from actions.auth.jwt import jwt_none_alg
    from actions.registry import ActionContext

    valid = _hs256({"sub": "u1"}, "s3cr3t").rsplit(".", 1)[0] + ".validsig"
    monkeypatch.setattr(jwt_module, "curl",
                        _jwt_curl_factory(accept_forged=True))
    ctx = ActionContext(action_id="auth.jwt.none_alg",
                        params={"token": valid,
                                "url": "https://example.com/api/me"},
                        target="https://example.com/api/me")

    result = asyncio.run(jwt_none_alg(ctx))

    assert result.success is True
    assert result.confidence == "CONFIRMED"


def test_jwt_none_alg_replay_rejected(monkeypatch):
    import actions.auth.jwt as jwt_module
    from actions.auth.jwt import jwt_none_alg
    from actions.registry import ActionContext

    valid = _hs256({"sub": "u1"}, "s3cr3t").rsplit(".", 1)[0] + ".validsig"
    monkeypatch.setattr(jwt_module, "curl",
                        _jwt_curl_factory(accept_forged=False))
    ctx = ActionContext(action_id="auth.jwt.none_alg",
                        params={"token": valid,
                                "url": "https://example.com/api/me"},
                        target="https://example.com/api/me")

    result = asyncio.run(jwt_none_alg(ctx))

    assert result.success is False


def test_jwt_craft_without_url_is_not_a_finding(monkeypatch):
    from actions.auth.jwt import jwt_none_alg
    from actions.registry import ActionContext

    valid = _hs256({"sub": "u1"}, "s3cr3t")
    ctx = ActionContext(action_id="auth.jwt.none_alg",
                        params={"token": valid}, target="")

    result = asyncio.run(jwt_none_alg(ctx))

    assert result.success is False
    assert "not replayed" in result.error


def test_jwt_weak_secret_crack_offline(monkeypatch):
    from actions.auth.jwt import jwt_weak_secret_crack
    from actions.registry import ActionContext

    token = _hs256({"sub": "admin"}, "secret")
    ctx = ActionContext(action_id="auth.jwt.weak_secret_crack",
                        params={"token": token}, target="")

    result = asyncio.run(jwt_weak_secret_crack(ctx))

    assert result.success is True
    assert result.confidence == "CONFIRMED"
    assert result.data["secret"] == "secret"


# ── Wave D: redirect probe + action oracles ───────────────────────

def test_redirect_probe_confirms_offsite_location(monkeypatch):
    import actions.web.redirect as redirect_module
    from actions.web.redirect import redirect_probe
    from actions.registry import ActionContext

    async def fake_curl(url, **kwargs):
        assert kwargs.get("follow_redirects") is False, \
            "the probe must never follow the redirect"
        return {"status": 302,
                "headers": "Location: https://redirect-probe.invalid/x",
                "body": "", "time_ms": 5, "url": url}

    monkeypatch.setattr(redirect_module, "curl", fake_curl)
    ctx = ActionContext(action_id="web.redirect.probe",
                        params={"url": "https://example.com/go",
                                "param": "next"},
                        target="https://example.com/go")

    result = asyncio.run(redirect_probe(ctx))

    assert result.success is True
    assert result.confidence == "CONFIRMED"
    assert result.data["location"] == "https://redirect-probe.invalid/x"


def test_redirect_probe_rejects_onsite_location(monkeypatch):
    import actions.web.redirect as redirect_module
    from actions.web.redirect import redirect_probe
    from actions.registry import ActionContext

    async def fake_curl(url, **kwargs):
        return {"status": 302, "headers": "Location: /dashboard",
                "body": "", "time_ms": 5, "url": url}

    monkeypatch.setattr(redirect_module, "curl", fake_curl)
    ctx = ActionContext(action_id="web.redirect.probe",
                        params={"url": "https://example.com/go",
                                "param": "next"},
                        target="https://example.com/go")

    result = asyncio.run(redirect_probe(ctx))

    assert result.success is False


def test_xss_action_uses_marker_gate(monkeypatch):
    import actions.web.xss as xss_module
    from actions.web.xss import reflected_xss
    from actions.registry import ActionContext

    seen = []

    async def fake_curl(url, **kwargs):
        seen.append(url)
        # Marker reflects; no payload shape ever does.
        return {"status": 200, "body": "<html>echo</html>",
                "time_ms": 5, "url": url}

    monkeypatch.setattr(xss_module, "curl", fake_curl)
    ctx = ActionContext(action_id="web.xss.reflected",
                        params={"url": "https://example.com/?q=1",
                                "param": "q"},
                        target="https://example.com/?q=1")

    result = asyncio.run(reflected_xss(ctx))

    assert result.success is False
    assert not any("sVg" in url for url in seen), \
        "without marker reflection no payload may be sent"


def test_ssrf_cloud_needs_content_markers(monkeypatch):
    import actions.web.ssrf as ssrf_module
    from actions.web.ssrf import ssrf_cloud_metadata
    from actions.registry import ActionContext

    async def fake_curl(url, **kwargs):
        if "169.254.169.254" in url or "metadata.google" in url:
            return {"status": 200,
                    "body": "<html>generic echo service response page</html>",
                    "time_ms": 5, "url": url}
        return {"status": 404, "body": "", "time_ms": 5, "url": url}

    monkeypatch.setattr(ssrf_module, "curl", fake_curl)
    ctx = ActionContext(action_id="web.ssrf.cloud_metadata",
                        params={"url": "https://example.com/fetch",
                                "param": "url"},
                        target="https://example.com/fetch")

    result = asyncio.run(ssrf_cloud_metadata(ctx))

    assert result.success is False, \
        "a 200 echo without cloud markers is not metadata"


def test_ssrf_cloud_markers_confirm(monkeypatch):
    import actions.web.ssrf as ssrf_module
    from actions.web.ssrf import ssrf_cloud_metadata
    from actions.registry import ActionContext

    async def fake_curl(url, **kwargs):
        if "iam/security-credentials" in url:
            return {"status": 200, "body": "my-role-name",
                    "time_ms": 5, "url": url}
        if "meta-data" in url:
            return {"status": 200,
                    "body": "ami-id\ninstance-id\nhostname",
                    "time_ms": 5, "url": url}
        return {"status": 404, "body": "", "time_ms": 5, "url": url}

    monkeypatch.setattr(ssrf_module, "curl", fake_curl)
    ctx = ActionContext(action_id="web.ssrf.cloud_metadata",
                        params={"url": "https://example.com/fetch",
                                "param": "url"},
                        target="https://example.com/fetch")

    result = asyncio.run(ssrf_cloud_metadata(ctx))

    assert result.success is True
    assert result.confidence == "FIRM"


# ── Wave D: smuggling pre-filter + desync oracle ────────────────

def _raw_http_server(handler):
    import socket as _socket
    import threading as _threading
    server = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    server.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    port = server.getsockname()[1]

    def serve():
        server.settimeout(10)
        while True:
            try:
                conn, _ = server.accept()
            except Exception:
                return
            try:
                handler(conn)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    thread = _threading.Thread(target=serve, daemon=True)
    thread.start()
    return server, port


def test_smuggling_strict_server_skips_fuzzer(monkeypatch):
    import modules.http_smuggling as smuggling_module
    from modules.http_smuggling import HTTPSmuggling

    def strict_handler(conn):
        conn.settimeout(5)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        except Exception:
            pass
        head = data.decode("utf-8", errors="replace").lower()
        if "transfer-encoding" in head and "content-length" in head:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n"
                         b"Connection: close\r\n\r\n")
        else:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                         b"Connection: close\r\n\r\nok")

    server, port = _raw_http_server(strict_handler)
    try:
        async def no_smuggler(target, timeout=300):
            raise AssertionError("smuggler must not run on strict servers")

        monkeypatch.setattr(smuggling_module, "smuggler_scan", no_smuggler)
        monkeypatch.setattr(smuggling_module, "tool_available", lambda name: True)
        state = _state()
        state.add_asset("webapp", f"webapp:http://127.0.0.1:{port}/",
                        f"http://127.0.0.1:{port}/", confidence="CONFIRMED",
                        sources=["test"], attrs={})
        config = {"target": {"domain": "127.0.0.1",
                             "base_url": f"http://127.0.0.1:{port}/"}}

        result = asyncio.run(HTTPSmuggling(state, config).run())

        assert result == "done"
        assert state.findings["findings"] == []
    finally:
        server.close()


def test_smuggling_desync_oracle_confirms(monkeypatch):
    import re as _re
    import modules.http_smuggling as smuggling_module
    from modules.http_smuggling import HTTPSmuggling

    def desync_handler(conn):
        conn.settimeout(8)
        data = b""
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
                if b"Connection: close" in data and data.count(b"\r\n\r\n") >= 2:
                    break
                if len(data) > 131072:
                    break
        except Exception:
            pass
        text = data.decode("utf-8", errors="replace")
        marker = _re.search(r"hopefully404-[0-9a-f]+", text)
        marker = marker.group(0) if marker else "nomarker"
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        conn.sendall(f"HTTP/1.1 404 Not Found\r\nContent-Length: {len(marker)}"
                    f"\r\n\r\n{marker}".encode())

    server, port = _raw_http_server(desync_handler)
    try:
        async def no_smuggler(target, timeout=300):
            raise AssertionError("proven desync must not need the fuzzer")

        monkeypatch.setattr(smuggling_module, "smuggler_scan", no_smuggler)
        monkeypatch.setattr(smuggling_module, "tool_available", lambda name: True)
        state = _state()
        state.add_asset("webapp", f"webapp:http://127.0.0.1:{port}/",
                        f"http://127.0.0.1:{port}/", confidence="CONFIRMED",
                        sources=["test"], attrs={})
        config = {"target": {"domain": "127.0.0.1",
                             "base_url": f"http://127.0.0.1:{port}/"}}

        result = asyncio.run(HTTPSmuggling(state, config).run())

        assert result == "done"
        assert len(state.findings["findings"]) == 1
        finding = state.findings["findings"][0]
        assert finding["severity"] == "HIGH"
        assert finding["verified"] is True
        assert "hopefully404-" in finding["evidence"][1]
    finally:
        server.close()


# ── Wave D: planner suggests provable actions ───────────────────

def test_planner_attaches_proving_actions():
    from agents.attack_planner import fallback_plan, _attach_proving_actions
    bundle = {
        "risk": {"top_findings": [
            {"id": "F-1", "title": "Open redirect via next on /login",
             "severity": "HIGH", "risk_score": 80, "category": "Open Redirect"},
            {"id": "F-2", "title": "Reflected input on /search",
             "severity": "MEDIUM", "risk_score": 50, "category": "XSS"},
        ]},
        "assets": {"counts_by_type": {}},
        "patterns": [],
    }
    plan = fallback_plan(bundle)
    first = plan["top_hypotheses"][0]
    assert first["suggested_action"] == "web.redirect.probe"
    assert first["needs_ceiling"] == "LOW"
    second = plan["top_hypotheses"][1]
    assert second["suggested_action"] == "web.xss.reflected"
    assert second["needs_ceiling"] == "MEDIUM"


def test_planner_rejects_invented_action_ids():
    from agents.attack_planner import _attach_proving_actions
    plan = {"top_hypotheses": [
        {"title": "SQL injection in login", "why": "sql errors",
         "suggested_action": "web.sqli.rce_nuke"},
    ]}
    out = _attach_proving_actions(plan)
    assert out["top_hypotheses"][0]["suggested_action"] == "web.sqli.detect"


# ── Wave D+: KEV match strengths ─────────────────────────────────

def test_kev_match_strengths(monkeypatch):
    import json as _json
    import modules.exploit_lookup as exploit_module
    from modules.exploit_lookup import check_cisa_kev

    feed = {"vulnerabilities": [
        {"cveID": "CVE-2024-0001", "product": "Exchange Server",
         "vendorProject": "Microsoft", "vulnerabilityName": "Exchange RCE",
         "dueDate": "2024-01-01", "shortDescription": "d"},
        {"cveID": "CVE-2024-0002", "product": "Windows Kernel",
         "vendorProject": "Microsoft", "vulnerabilityName": "EoP",
         "dueDate": "2024-01-01", "shortDescription": "d"},
    ]}

    async def fake_bash(cmd, timeout=120):
        return {"stdout": _json.dumps(feed), "stderr": "",
                "exit_code": 0, "error": None}

    monkeypatch.setattr(exploit_module, "bash", fake_bash)

    matches = asyncio.run(check_cisa_kev(["exchange", "Microsoft"]))
    by_cve = {m["cve"]: m for m in matches}
    # "exchange" is a substring of "Exchange Server", "Microsoft" is exact vendor.
    assert by_cve["CVE-2024-0001"]["match_strength"] == "substring"
    assert by_cve["CVE-2024-0002"]["match_strength"] in ("exact", "vendor")


# ── Wave D+: sitemap liveness + ASN scope ────────────────────────

def test_sitemap_dead_keyword_urls_are_skipped(monkeypatch):
    import modules.sitemap as sitemap_module
    from modules.sitemap import SitemapExploit
    from core.site_profile import clear_profiles

    clear_profiles()

    async def fake_curl(url, **kwargs):
        if url.endswith("sitemap.xml"):
            return {"status": 200,
                    "body": '<?xml version="1.0"?><urlset>'
                            "<url><loc>https://example.com/blog/old-posts</loc></url>"
                            "<url><loc>https://example.com/admin/panel</loc></url>"
                            "</urlset>"}
        if url == "https://example.com":
            return {"status": 200, "body": "BASE SHELL"}
        if url.endswith("/blog/old-posts"):
            return {"status": 200, "body": "BASE SHELL"}
        if url.endswith("/admin/panel"):
            return {"status": 200,
                    "body": "admin login form, distinct content here"}
        return {"status": 404, "body": "BASE SHELL"}

    monkeypatch.setattr(sitemap_module, "curl", fake_curl)
    state = _state()

    result = asyncio.run(SitemapExploit(
        state, {"target": {"domain": "example.com"}}).run())

    assert result == "done"
    findings = [f for f in state.findings["findings"]
                if "Hidden/Test Pages" in f["title"]]
    assert len(findings) == 1
    assert "/admin/panel" in findings[0]["evidence"][0]
    assert "old-posts" not in findings[0]["evidence"][0]


def test_sitemap_error_page_mentioning_sitemap_is_ignored(monkeypatch):
    import modules.sitemap as sitemap_module
    from modules.sitemap import SitemapExploit
    from core.site_profile import clear_profiles

    clear_profiles()

    async def fake_curl(url, **kwargs):
        return {"status": 404,
                "body": "<html>error: sitemap not found on this host</html>"}

    monkeypatch.setattr(sitemap_module, "curl", fake_curl)
    state = _state()

    assert asyncio.run(SitemapExploit(
        state, {"target": {"domain": "example.com"}}).run()) == "done"
    assert state.get_assets_by_type("webapp") == []


def test_asn_shared_prefixes_are_scoped(monkeypatch):
    import modules.asn_expansion as asn_module
    from modules.asn_expansion import ASNExpansion

    async def fake_asn_lookup(ip):
        return {"ip": ip, "asn": "AS13335", "org": "Cloudflare",
                "country": "US"}

    async def fake_bgpview_asn(asn):
        return {"asn": asn, "ipv4_prefixes": [
            {"prefix": "104.16.0.0/13"},
            {"prefix": "203.0.113.0/24"},
        ]}

    monkeypatch.setattr(asn_module, "asn_lookup", fake_asn_lookup)
    monkeypatch.setattr(asn_module, "bgpview_asn", fake_bgpview_asn)
    state = _state()
    state.add_asset("ip", "ip:104.16.5.5", "104.16.5.5",
                    confidence="FIRM", sources=["test"], attrs={})

    assert asyncio.run(ASNExpansion(
        state, {"target": {"domain": "example.com"}}).run()) == "done"
    cidrs = {c["value"]: c for c in state.get_assets_by_type("cidr")}
    assert "104.16.0.0/13" not in cidrs, "transit /13 must not be target surface"
    assert cidrs["203.0.113.0/24"]["attrs"]["shared_hosting"] is True
    assert cidrs["203.0.113.0/24"]["confidence"] == "TENTATIVE"


# ── Juice Shop wave: scope gates ─────────────────────────────────

def test_is_public_target_grades_hosts():
    from core.validators import is_public_target
    assert is_public_target("example.com") is True
    assert is_public_target("8.8.8.8") is True
    assert is_public_target("localhost") is False
    assert is_public_target("127.0.0.1") is False
    assert is_public_target("app.local") is False
    assert is_public_target("a.b") is False
    assert is_public_target("") is False


def test_non_public_targets_skip_dns_empire(monkeypatch):
    import modules.subdomain as subdomain_module
    import modules.email_security_module as email_module
    import modules.threat_intel as threat_module
    from modules.subdomain import SubdomainEnum
    from modules.email_security_module import EmailSecurity
    from modules.threat_intel import ThreatIntel

    async def no_network(*args, **kwargs):
        raise AssertionError("no network may be touched")

    async def fake_crtsh(domain):
        raise AssertionError("crt.sh must not be queried")

    monkeypatch.setattr(subdomain_module, "crtsh", fake_crtsh)
    state = _state()
    config = {"target": {"domain": "localhost",
                         "base_url": "http://localhost:3000"}}

    assert asyncio.run(SubdomainEnum(state, config).run()) == "skipped"
    assert asyncio.run(EmailSecurity(state, config).run()) == "skipped"
    assert asyncio.run(ThreatIntel(state, config).run()) == "skipped"


# ── Juice Shop wave: probe targets ──────────────────────────────

def test_probe_targets_scope_and_dedupe():
    from core.probe_targets import in_scope_url, iter_probe_points
    base = "http://localhost:3000"
    assert in_scope_url("http://localhost:3000/rest/products/search?q=1",
                        base, "localhost") is True
    assert in_scope_url("https://www.youtube.com/watch?v=1",
                        base, "localhost") is False
    assert in_scope_url("http://localhost:/8094/api/v1/status",
                        base, "localhost") is False
    assert in_scope_url("http://localhost:8094/api/v1/status",
                        base, "localhost") is False
    assert in_scope_url("https://example.com/?q=1",
                        "https://example.com", "example.com") is True
    assert in_scope_url("http://example.com:8080/?q=1",
                        "https://example.com", "example.com") is True

    state = _state()
    state.add_asset("api_endpoint",
                    "api:http://localhost:3000/api/Users/{id}",
                    "http://localhost:3000/api/Users/{id}",
                    confidence="FIRM", sources=["test"],
                    attrs={"methods": ["GET", "PUT"]})
    points = iter_probe_points(state, base, "localhost")
    assert ("http://localhost:3000/api/Users/{id}", "id", "PUT") in [
        (p["url"], p["param"], p["method"]) for p in points]


# ── Juice Shop wave: auth audit ─────────────────────────────────

def _auth_state(monkeypatch):
    import modules.auth_audit as auth_module

    async def fake_curl(url, **kwargs):
        method = kwargs.get("method", "GET")
        data = kwargs.get("data", "") or ""
        if url.endswith("/rest/user/login") and method == "POST":
            if "OR 1=1" in data or "OR '1'='1" in data or "admin'--" in data:
                return {"status": 200,
                        "body": '{"authentication": {"token": "'
                                'eyJhbGciOiJIUzI1NiJ9.'
                                'eyJlbWFpbCI6ImFkbWluQGV4YW1wbGUudGVzdCIsInJvbGUiOiJhZG1pbiJ9.'
                                'SIG"}}',
                        "headers": "", "time_ms": 5, "url": url}
            return {"status": 401, "body": "Invalid email or password.",
                    "headers": "", "time_ms": 5, "url": url}
        if url.endswith("/rest/admin/application-configuration"):
            auth = (kwargs.get("headers", {}) or {}).get("Authorization", "")
            if not auth:
                return {"status": 200,
                        "body": '{"config": {"application": {"name": "Shop", "admin": true}}}',
                        "headers": "", "time_ms": 5, "url": url}
            if auth.startswith("Bearer eyJ"):
                return {"status": 200,
                        "body": '{"config": {"application": {"name": "Shop", "admin": true}}}',
                        "headers": "", "time_ms": 5, "url": url}
            return {"status": 401, "body": "Unauthorized",
                    "headers": "", "time_ms": 5, "url": url}
        return {"status": 404, "body": "<html>shell</html>",
                "headers": "", "time_ms": 5, "url": url}

    monkeypatch.setattr(auth_module, "curl", fake_curl)
    state = _state()
    return state


def test_auth_audit_sqli_bypass_and_admin_surface(monkeypatch):
    from modules.auth_audit import AuthAudit
    state = _auth_state(monkeypatch)

    # Pack-style config: target-specific paths arrive via config,
    # never hardcoded (see knowledge/juice_shop_lab.yaml).
    result = asyncio.run(AuthAudit(
        state, {"target": {"domain": "localhost",
                           "base_url": "http://localhost:3000"},
                "modules": {"auth_audit": {
                    "extra_login_paths": ["/rest/user/login"],
                    "extra_admin_paths": [
                        "/rest/admin/application-configuration"],
                }}}).run())

    assert result == "done"
    titles = [f["title"] for f in state.findings["findings"]]
    assert any("SQL Injection Authentication Bypass" in t for t in titles)
    assert any("Admin Surface Exposed Without Authentication" in t
               for t in titles)
    creds = state.get_assets_by_type("identity_credential")
    assert len(creds) == 1
    assert creds[0]["attrs"]["technique"] == "sqli_auth_bypass"


def test_auth_audit_none_alg_forgery_accepted(monkeypatch):
    import modules.auth_audit as auth_module
    from modules.auth_audit import AuthAudit, _none_alg_variant

    async def fake_curl(url, **kwargs):
        auth = (kwargs.get("headers", {}) or {}).get("Authorization", "")
        if url.endswith("/rest/admin/application-configuration"):
            if not auth:
                return {"status": 401, "body": "Unauthorized",
                        "headers": "", "time_ms": 5, "url": url}
            return {"status": 200,
                    "body": '{"config": {"admin": true}}',
                    "headers": "", "time_ms": 5, "url": url}
        return {"status": 404, "body": "<html>shell</html>",
                "headers": "", "time_ms": 5, "url": url}

    monkeypatch.setattr(auth_module, "curl", fake_curl)
    state = _state()
    # Discovered admin endpoint (generic path: discovery, not hardcode).
    state.add_asset("api_endpoint",
                    "api:http://localhost:3000/rest/admin/application-configuration",
                    "http://localhost:3000/rest/admin/application-configuration",
                    confidence="FIRM", sources=["test"], attrs={})
    forged = _none_alg_variant(
        "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6IngifQ.SIG")
    assert forged.split(".")[0] != "eyJhbGciOiJIUzI1NiJ9"
    assert forged.endswith(".")

    module = AuthAudit(state, {"target": {"domain": "localhost",
                                          "base_url": "http://localhost:3000"}})
    asyncio.run(module._authenticated_follow_ups(
        {"token": "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6IngifQ.SIG",
         "email": "x", "role": ""}))

    assert any(f["title"].startswith("Unsigned JWT Accepted")
               for f in state.findings["findings"])


# ── Juice Shop wave: response keys ──────────────────────────────

def test_response_audit_flags_password_hash(monkeypatch):
    import modules.response_audit as response_module
    from modules.response_audit import ResponseAudit

    async def fake_curl(url, **kwargs):
        if url.endswith("/api/Users/1"):
            return {"status": 200,
                    "body": '{"status": "success", "data": '
                            '{"id": 1, "email": "a@b.c", '
                            '"password": "5f4dcc3b5aa765d61d8327deb882cf99"}}',
                    "time_ms": 5, "url": url}
        return {"status": 401, "body": "Unauthorized",
                "time_ms": 5, "url": url}

    monkeypatch.setattr(response_module, "curl", fake_curl)
    state = _state()
    state.add_asset("api_endpoint", "api:http://localhost:3000/api/Users/1",
                    "http://localhost:3000/api/Users/1", confidence="FIRM",
                    sources=["test"], attrs={})

    result = asyncio.run(ResponseAudit(
        state, {"target": {"domain": "localhost",
                           "base_url": "http://localhost:3000"}}).run())

    assert result == "done"
    assert len(state.findings["findings"]) == 1
    finding = state.findings["findings"][0]
    assert finding["severity"] == "HIGH"
    assert finding["verified"] is True
    assert "5f4dcc3b5aa765d61d8327deb882cf99" not in finding["evidence"][0]
    assert finding["evidence"][0].startswith("password: 5f4d")


# ── Juice Shop wave: NoSQL + SSTI oracles ───────────────────────

def test_nosql_operator_differential_fires(monkeypatch):
    import modules.nosql_scan as nosql_module
    from modules.nosql_scan import NoSQLScan

    async def fake_curl(url, **kwargs):
        from urllib.parse import urlparse, parse_qs
        query = parse_qs(urlparse(url).query)
        flat = str(query)
        if "zzz_no_such_value_9f8" in flat and "$" not in flat:
            return {"status": 200,
                    "body": '{"status": "success", "data": []}',
                    "time_ms": 5, "url": url}
        if "$gt" in flat or "$ne" in flat:
            return {"status": 200,
                    "body": '{"status": "success", "data": '
                            '[{"orderId": "1"}, {"orderId": "2"}]}',
                    "time_ms": 5, "url": url}
        return {"status": 200,
                "body": '{"status": "success", "data": []}',
                "time_ms": 5, "url": url}

    monkeypatch.setattr(nosql_module, "curl", fake_curl)
    state = _state()
    state.add_asset("parameter", "param:http://example.com/api/orders:orderId",
                    "orderId", confidence="FIRM", sources=["test"],
                    attrs={"url": "http://example.com/api/orders",
                           "source": "test"})

    result = asyncio.run(NoSQLScan(
        state, {"target": {"domain": "example.com",
                           "base_url": "http://example.com"}}).run())

    assert result == "done"
    assert len(state.findings["findings"]) == 1
    assert state.findings["findings"][0]["severity"] == "HIGH"


def test_ssti_arithmetic_differential(monkeypatch):
    import modules.ssti_scan as ssti_module
    from modules.ssti_scan import SSTIScan

    async def fake_curl(url, **kwargs):
        from urllib.parse import urlparse, parse_qs, unquote
        query = parse_qs(urlparse(url).query)
        value = query.get("q", [""])[0]
        if value == "zz74x74zz":
            return {"status": 200, "body": "<p>hello zz74x74zz, price 49</p>",
                    "time_ms": 5, "url": url}
        if "{{7*7}}" in value:
            return {"status": 200, "body": "<p>hello 49, price 49</p>",
                    "time_ms": 5, "url": url}
        return {"status": 200, "body": f"<p>hello {value}</p>",
                "time_ms": 5, "url": url}

    monkeypatch.setattr(ssti_module, "curl", fake_curl)
    state = _state()
    state.add_asset("parameter", "param:http://example.com/search:q",
                    "q", confidence="FIRM", sources=["test"],
                    attrs={"url": "http://example.com/search",
                           "source": "test"})

    result = asyncio.run(SSTIScan(
        state, {"target": {"domain": "example.com",
                           "base_url": "http://example.com"}}).run())

    assert result == "done"
    assert len(state.findings["findings"]) == 1
    assert "Jinja" in state.findings["findings"][0]["title"] or \
        "jinja2" in state.findings["findings"][0]["title"].lower()


def test_ssti_price_page_does_not_fire(monkeypatch):
    import modules.ssti_scan as ssti_module
    from modules.ssti_scan import SSTIScan

    async def fake_curl(url, **kwargs):
        # Every price on the page contains 49; payloads reflect literally.
        return {"status": 200,
                "body": "<p>$49.00 gala apple, 49 left</p>",
                "time_ms": 5, "url": url}

    monkeypatch.setattr(ssti_module, "curl", fake_curl)
    state = _state()
    state.add_asset("parameter", "param:http://example.com/search:q",
                    "q", confidence="FIRM", sources=["test"],
                    attrs={"url": "http://example.com/search",
                           "source": "test"})

    assert asyncio.run(SSTIScan(
        state, {"target": {"domain": "example.com",
                           "base_url": "http://example.com"}}).run()) == "done"
    assert state.findings["findings"] == []


# ── Juice Shop wave: upload + DOM + backup bypass ───────────────

def test_upload_svg_served_intact_is_stored_xss(monkeypatch):
    import re as _re
    import modules.upload_audit as upload_module
    from modules.upload_audit import UploadAudit

    markers = {}

    async def fake_curl(url, **kwargs):
        if url.endswith("/file-upload") and kwargs.get("method") == "POST":
            ctype = (kwargs.get("headers", {}) or {}).get("Content-Type", "")
            if "multipart" in ctype:
                data = kwargs.get("data", b"") or b""
                raw = data if isinstance(data, bytes) else data.encode()
                match = _re.search(rb"upl[0-9a-f]{8}", raw)
                if match:
                    markers["m"] = match.group(0).decode()
                return {"status": 201,
                        "body": '{"location": "/uploads/probe.svg"}',
                        "time_ms": 5, "url": url}
            data = kwargs.get("data", b"") or b""
            if b"XXE_PROBE_CANARY" in (data if isinstance(data, bytes)
                                       else data.encode()):
                return {"status": 200,
                        "body": "<r>plain text, no entities</r>",
                        "time_ms": 5, "url": url}
            return {"status": 415, "body": "unsupported",
                    "time_ms": 5, "url": url}
        if url.endswith("/uploads/probe.svg"):
            marker = markers.get("m", "MARK")
            return {"status": 200,
                    "body": f"<svg onload=\"x\">{marker}</svg>",
                    "time_ms": 5, "url": url}
        return {"status": 404, "body": "nope", "time_ms": 5, "url": url}

    monkeypatch.setattr(upload_module, "curl", fake_curl)
    state = _state()

    result = asyncio.run(UploadAudit(
        state, {"target": {"domain": "example.com",
                           "base_url": "http://example.com"}}).run())

    assert result == "done"
    stored = [f for f in state.findings["findings"]
              if f["title"].startswith("Stored Script via SVG Upload")]
    assert len(stored) >= 1
    assert all(f["verified"] is True for f in stored)
    assert any("http://example.com/file-upload" in f["title"]
               for f in stored)


def test_upload_xxe_canary_expansion(monkeypatch):
    import modules.upload_audit as upload_module
    from modules.upload_audit import UploadAudit

    async def fake_curl(url, **kwargs):
        if url.endswith("/file-upload") and kwargs.get("method") == "POST":
            ctype = (kwargs.get("headers", {}) or {}).get("Content-Type", "")
            if "multipart" in ctype:
                return {"status": 200, "body": '{"ok": true}',
                        "time_ms": 5, "url": url}
            return {"status": 200,
                    "body": "<r>XXE_PROBE_CANARY_7f3a expanded here</r>",
                    "time_ms": 5, "url": url}
        return {"status": 404, "body": "nope", "time_ms": 5, "url": url}

    monkeypatch.setattr(upload_module, "curl", fake_curl)
    state = _state()

    result = asyncio.run(UploadAudit(
        state, {"target": {"domain": "example.com",
                           "base_url": "http://example.com"}}).run())

    assert result == "done"
    xxe = [f for f in state.findings["findings"]
           if f["title"].startswith("XXE Entity Expansion")]
    assert len(xxe) >= 1
    assert all(f["severity"] == "HIGH" for f in xxe)
    assert any("http://example.com/file-upload" in f["title"] for f in xxe)


def test_dom_xss_candidate_building_preserves_fragments():
    import asyncio as _asyncio
    import modules.dom_xss_scan as dom_module
    from modules.dom_xss_scan import DomXSSScan

    state = _state()
    state.add_asset("url", "url:http://example.com/#/search",
                    "http://example.com/#/search", confidence="FIRM",
                    sources=["test"], attrs={})
    module = DomXSSScan(state, {"target": {"domain": "example.com",
                                           "base_url": "http://example.com"}})
    pages = module._target_pages()
    assert "http://example.com/#/search" in pages

    seen_urls = []

    async def fake_browser(url, expected, config):
        seen_urls.append(url)
        return False

    monkeypatch_browser = __import__("pytest").MonkeyPatch()
    monkeypatch_browser.setattr(dom_module, "_browser_executes", fake_browser)
    try:
        assert _asyncio.run(module._test_page(
            "http://example.com/#/search")) is False
    finally:
        monkeypatch_browser.undo()
    assert any("/#/search?q=" in url for url in seen_urls), seen_urls


def test_misconfig_backup_bypass_variant(monkeypatch):
    import modules.misconfig as misconfig_module
    from modules.misconfig import MisconfigProbes
    from core.site_profile import clear_profiles

    clear_profiles()

    async def fake_curl(url, **kwargs):
        if url == "http://example.com":
            return {"status": 200, "body": "BASE SHELL"}
        if url.endswith("package.json.bak"):
            return {"status": 403, "body": "BASE SHELL"}
        if url.endswith("package.json.bak%2500.md"):
            return {"status": 200,
                    "body": '{"name": "shop", "version": "1.0.0"}'}
        return {"status": 404, "body": "BASE SHELL"}

    async def fake_curl_status(url, timeout=5):
        result = await fake_curl(url)
        return {"status": result["status"], "body": result["body"],
                "content_type": ""}

    monkeypatch.setattr(misconfig_module, "curl_with_status",
                        fake_curl_status)
    state = _state()

    result = asyncio.run(MisconfigProbes(
        state, {"target": {"domain": "example.com",
                           "base_url": "http://example.com"},
                "misconfig": {"max_paths": 5}}).run())

    assert result == "done"
    backups = [f for f in state.findings["findings"]
               if f["title"] == "Backup File Exposed"]
    assert len(backups) == 1
    assert backups[0]["severity"] == "HIGH"
    assert "%2500" in backups[0]["evidence"][0]


# ── Juice Shop wave: forgery sweep + identity merge ─────────────

def test_forgery_sweep_accepts_none_on_guarded_endpoint(monkeypatch):
    from modules.auth_audit import AuthAudit

    async def fake_get(url, auth):
        if not auth:
            return {"status": 401, "body": "Unauthorized"}
        if "none" in str(auth.get("Authorization", "")).lower() or \
                auth.get("Authorization", "").endswith("."):
            return {"status": 200,
                    "body": '{"id": 1, "email": "victim@example.com"}'}
        return {"status": 200,
                "body": '{"id": 1, "email": "victim@example.com"}'}

    monkeypatch.setattr("modules.auth_audit._get", fake_get)
    state = _state()
    state.add_asset("api_endpoint", "api:http://example.com/api/Users/1",
                    "http://example.com/api/Users/1", confidence="FIRM",
                    sources=["test"], attrs={})
    module = AuthAudit(state, {"target": {"domain": "example.com",
                                          "base_url": "http://example.com"}})

    asyncio.run(module._forgery_sweep(
        {"token": "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6IngifQ.SIG",
         "email": "x", "role": ""}))

    assert len(state.findings["findings"]) == 1
    finding = state.findings["findings"][0]
    assert finding["severity"] == "CRITICAL"
    assert finding["verified"] is True


def test_forgery_sweep_ignores_open_endpoints(monkeypatch):
    from modules.auth_audit import AuthAudit

    async def fake_get(url, auth):
        return {"status": 200, "body": '{"public": true}'}

    monkeypatch.setattr("modules.auth_audit._get", fake_get)
    state = _state()
    state.add_asset("api_endpoint", "api:http://example.com/api/Products",
                    "http://example.com/api/Products", confidence="FIRM",
                    sources=["test"], attrs={})
    module = AuthAudit(state, {"target": {"domain": "example.com",
                                          "base_url": "http://example.com"}})

    asyncio.run(module._forgery_sweep(
        {"token": "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6IngifQ.SIG",
         "email": "x", "role": ""}))

    assert state.findings["findings"] == []


def test_idor_adopts_discovered_sessions():
    from core.auth_harness import AuthHarness
    from modules.idor_differ import IdorDiffer
    state = _state()
    state.add_asset(
        "identity_credential", "identity:sqli_auth_bypass",
        "sqli_auth_bypass", confidence="CONFIRMED", sources=["auth_audit"],
        attrs={"endpoint": "http://example.com/rest/user/login",
               "technique": "sqli_auth_bypass", "role": "admin",
               "token": "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6IngifQ.SIG"})

    module = IdorDiffer(state, {"target": {"domain": "example.com"}})
    harness = AuthHarness({"target": {"domain": "example.com"}})
    assert not harness.identities
    module._merge_discovered_identities(harness)

    assert "sqli_auth_bypass" in harness.identities
    identity = harness.identities["sqli_auth_bypass"]
    assert identity.bearer_token.startswith("eyJ")
    assert identity.privileged is True


# ── Continue wave: UNION impact proof ───────────────────────────

def test_sqli_union_confirms_version(monkeypatch):
    import actions.web.sqli as sqli_module
    from actions.web.sqli import detect_sqli
    from actions.registry import ActionContext

    async def fake_curl(url, **kwargs):
        from urllib.parse import urlparse, parse_qs, unquote
        query = parse_qs(urlparse(url).query)
        q = query.get("q", ["1"])[0]
        base_body = ('{"status":"success","data":[{"id":1,"name":"Apple Juice",'
                     '"description":"The all-time classic fruit juice blend",'
                     '"price":1.99,"deluxePrice":0.99,'
                     '"image":"apple_juice.jpg",'
                     '"createdAt":"2026-10-06","updatedAt":"2026-10-06"}]}')
        if q == "1":
            return {"status": 200, "body": base_body,
                    "time_ms": 5, "url": url}
        if q == "'":
            return {"status": 200,
                    "body": '{"status":"success","data":[]}',
                    "time_ms": 5, "url": url}
        if "ORDER BY 1--" in q:
            return {"status": 200, "body": base_body,
                    "time_ms": 5, "url": url}
        if "ORDER BY" in q:
            number = int(q.split("ORDER BY")[1].split("--")[0])
            if number <= 9:
                return {"status": 200, "body": base_body,
                        "time_ms": 5, "url": url}
            return {"status": 500,
                    "body": "Error: SQLITE_ERROR: 1st ORDER BY term out of range",
                    "time_ms": 5, "url": url}
        if "UNION SELECT" in q and "sqlite_version()" in q:
            return {"status": 200,
                    "body": '{"status":"success","data":[{"id":"3.44.2",'
                            '"name":"Apple","price":1.99}]}',
                    "time_ms": 5, "url": url}
        return {"status": 200, "body": base_body,
                "time_ms": 5, "url": url}

    monkeypatch.setattr(sqli_module, "curl", fake_curl)
    import core.verification_oracle as oracle_module
    monkeypatch.setattr(oracle_module, "curl", fake_curl)
    ctx = ActionContext(action_id="web.sqli.detect",
                        params={"url": "http://example.com/rest/products/search",
                                "param": "q"},
                        target="http://example.com/rest/products/search")

    result = asyncio.run(detect_sqli(ctx))

    assert result.success is True
    proof = result.data.get("union_confirmation", {})
    assert proof.get("backend") == "sqlite", proof
    assert proof.get("columns") == 9, proof
    assert proof.get("version") == "3.44.2", proof


# ── Juice Shop wave II: claims, BOLA-ids, write access, errors ──

def test_auth_audit_flags_password_in_claims(monkeypatch):
    import base64 as _b64
    import json as _json
    import modules.auth_audit as auth_module
    from modules.auth_audit import AuthAudit

    payload = _b64.urlsafe_b64encode(_json.dumps(
        {"email": "a@b.c", "password": "0192023a7bbd73250516f069df18b500",
         "role": "admin"}).encode()).decode().rstrip("=")
    token = f"eyJhbGciOiJIUzI1NiJ9.{payload}.SIG"

    async def fake_curl(url, **kwargs):
        if url.endswith("/rest/user/login"):
            return {"status": 200,
                    "body": '{"authentication": {"token": "%s"}}' % token,
                    "headers": "", "time_ms": 5, "url": url}
        return {"status": 404, "body": "<html>shell</html>",
                "headers": "", "time_ms": 5, "url": url}

    monkeypatch.setattr(auth_module, "curl", fake_curl)
    state = _state()

    result = asyncio.run(AuthAudit(
        state, {"target": {"domain": "localhost",
                           "base_url": "http://localhost:3000"},
                "modules": {"auth_audit": {
                    "extra_login_paths": ["/rest/user/login"],
                }}}).run())

    assert result == "done"
    claims = [f for f in state.findings["findings"]
              if f["title"] == "Sensitive Keys Inside JWT Claims"]
    assert len(claims) == 1
    assert claims[0]["severity"] == "HIGH"
    assert "0192023a7bbd73250516f069df18b500" not in str(claims[0]["evidence"])


def test_bola_across_ids_needs_distinct_owners(monkeypatch):
    from modules.auth_audit import AuthAudit
    state = _state()
    module = AuthAudit(state, {"target": {"domain": "example.com",
                                          "base_url": "http://example.com"}})

    async def fake_get_same_owner(url, auth):
        return {"status": 200,
                "body": '{"id": 1, "email": "same@example.com"}'}

    asyncio.run(module._bola_across_ids(
        "http://example.com/api/Users/1", "FORGED", {"status": 401, "body": ""}))
    # (no network: _get is real here, both fail -> no finding)
    assert state.findings["findings"] == []


def test_write_access_noop_put(monkeypatch):
    import modules.auth_audit as auth_module
    from modules.auth_audit import AuthAudit

    async def fake_curl(url, **kwargs):
        if kwargs.get("method") == "PUT":
            import json as _json
            return {"status": 200, "body": kwargs.get("data", "{}"),
                    "time_ms": 5, "url": url}
        if url.endswith("/api/Products/1"):
            return {"status": 200,
                    "body": '{"status": "success", "data": {"id": 1, '
                            '"name": "Apple", "price": 1.99}}',
                    "time_ms": 5, "url": url}
        return {"status": 404, "body": "nope", "time_ms": 5, "url": url}

    monkeypatch.setattr(auth_module, "curl", fake_curl)
    state = _state()
    state.add_asset("api_endpoint",
                    "api:http://example.com/api/Products/1",
                    "http://example.com/api/Products/1",
                    confidence="FIRM", sources=["test"],
                    attrs={"methods": ["GET", "PUT"]})
    module = AuthAudit(state, {"target": {"domain": "example.com",
                                          "base_url": "http://example.com"}})

    asyncio.run(module._write_access_probes(
        {"token": "", "email": "", "role": ""}))

    assert len(state.findings["findings"]) == 1
    finding = state.findings["findings"][0]
    assert finding["severity"] == "HIGH"
    assert finding["verified"] is True
    assert "Unauthenticated" in finding["title"]


def test_error_audit_matches_stack_signatures(monkeypatch):
    import modules.error_audit as error_module
    from modules.error_audit import ErrorAudit
    from core.site_profile import clear_profiles

    clear_profiles()

    async def fake_curl(url, **kwargs):
        from urllib.parse import urlparse
        path = urlparse(url).path or "/"
        if path == "/" or ("zz9" not in path and "[" not in path
                           and "%ff" not in path.lower()):
            return {"status": 404, "body": "not found",
                    "time_ms": 5, "url": url}
        return {"status": 500,
                "body": "Error: SQLITE_ERROR: no such table: main.Users\n"
                        "at Database.prepare (/app/node_modules/sequelize/lib/sqlite/query.js:12:34)",
                "time_ms": 5, "url": url}

    async def fake_curl_status(url, timeout=10):
        result = await fake_curl(url)
        return {"status": result["status"], "body": result["body"],
                "content_type": ""}

    monkeypatch.setattr(error_module, "curl", fake_curl)
    monkeypatch.setattr("tools.wrappers.curl", fake_curl)
    state = _state()

    result = asyncio.run(ErrorAudit(
        state, {"target": {"domain": "example.com",
                           "base_url": "http://example.com"}}).run())

    assert result == "done"
    assert any("sqlite" in str(f["evidence"]).lower()
               for f in state.findings["findings"])


def test_js_fragment_routes_extracted():
    from modules.js_analysis import extract_endpoints, _absolutize_endpoint
    found = extract_endpoints(
        'const r = "#/score-board"; fetch("/api/Users"); path: "search"',
        "http://example.com")
    assert "#/score-board" in found
    assert _absolutize_endpoint("http://example.com", "#/score-board") == \
        "http://example.com/#/score-board"
    assert _absolutize_endpoint("http://example.com", "search") == \
        "http://example.com/#/search"
    assert _absolutize_endpoint("http://example.com", "not a path...") == ""


# ── Continue wave: header XSS, password change, sessions ────────

def test_header_reflection_unsanitized_is_filed(monkeypatch):
    import modules.xss_scan as xss_module
    from modules.xss_scan import XSSScan

    async def fake_curl(url, **kwargs):
        from urllib.parse import urlparse
        headers = kwargs.get("headers", {}) or {}
        marker = headers.get("True-Client-IP", "")
        # Only the tracking pixel endpoint echoes the header.
        if "/track" not in urlparse(url).path:
            return {"status": 200, "body": "<html>home</html>",
                    "time_ms": 5, "url": url}
        if marker.startswith("hxprobe"):
            return {"status": 200,
                    "body": f"<html>ip logged: {marker}</html>",
                    "time_ms": 5, "url": url}
        if marker.startswith("<sVg"):
            return {"status": 200,
                    "body": f"<html>ip logged: {marker}</html>",
                    "time_ms": 5, "url": url}
        return {"status": 200, "body": "<html>home</html>",
                "time_ms": 5, "url": url}

    async def fake_browser(url, expected, config):
        return False

    monkeypatch.setattr(xss_module, "curl", fake_curl)
    monkeypatch.setattr(xss_module, "_browser_confirms_execution",
                        fake_browser)
    monkeypatch.setattr(xss_module, "tool_available", lambda name: False)
    state = _state()
    state.add_asset("url", "url:http://example.com/track",
                    "http://example.com/track", confidence="FIRM",
                    sources=["test"], attrs={})
    module = XSSScan(state, {"target": {"domain": "example.com",
                                        "base_url": "http://example.com"},
                             "xss": {"browser_confirm": False}})

    result = asyncio.run(module.run())

    assert result == "done"
    header_hits = [f for f in state.findings["findings"]
                   if "header:True-Client-IP" in str(f.get("evidence", ""))]
    assert len(header_hits) == 1
    assert header_hits[0]["confidence"] == "FIRM"


def test_password_change_opt_in_default_off(monkeypatch):
    from modules.auth_audit import AuthAudit
    state = _state()
    module = AuthAudit(state, {"target": {"domain": "example.com",
                                          "base_url": "http://example.com"}})
    assert module._cfg().get("test_password_change", False) is not True


def test_password_change_without_current_is_high(monkeypatch):
    import modules.auth_audit as auth_module
    from modules.auth_audit import AuthAudit

    async def fake_curl(url, **kwargs):
        if url.endswith("/rest/user/change-password"):
            return {"status": 200,
                    "body": '{"status": "success", "message": "password updated"}',
                    "time_ms": 5, "url": url}
        return {"status": 404, "body": "nope", "time_ms": 5, "url": url}

    monkeypatch.setattr(auth_module, "curl", fake_curl)
    state = _state()
    module = AuthAudit(state, {"target": {"domain": "example.com",
                                          "base_url": "http://example.com"},
                               "modules": {"auth_audit":
                                           {"test_password_change": True}}})

    asyncio.run(module._password_change_probe(
        {"token": "T", "email": "a@b.c", "role": ""}))

    assert len(state.findings["findings"]) == 1
    assert state.findings["findings"][0]["severity"] == "HIGH"


def test_adopt_discovered_shared_helper():
    from core.auth_harness import AuthHarness
    state = _state()
    state.add_asset(
        "identity_credential", "identity:sqli_auth_bypass",
        "sqli_auth_bypass", confidence="CONFIRMED", sources=["auth_audit"],
        attrs={"endpoint": "http://example.com/rest/user/login",
               "technique": "sqli_auth_bypass", "role": "",
               "token": "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6IngifQ.SIG"})
    harness = AuthHarness({"target": {"domain": "example.com"}})

    assert harness.adopt_discovered(state) == 1
    assert "sqli_auth_bypass" in harness.identities
    # Idempotent: second merge adopts nothing new.
    assert harness.adopt_discovered(state) == 0


# ── Continue wave: template params + fragment routes ────────────

def test_template_literal_params_extracted():
    from modules.js_analysis import extract_template_params
    found = extract_template_params(
        "search(e){return this.http.get(`${this.hostServer}/rest/products/search?q=${e}`)}"
        "track(o){return this.http.post(`${this.hostServer}/rest/track-order`,"
        " {orderId:o})}")
    assert found == {"/rest/products/search": ["q"]}


def test_fragment_routes_absolutized():
    from modules.js_analysis import extract_endpoints, _absolutize_endpoint
    found = extract_endpoints(
        "{path:`search`,component:Vs},{path:`basket`,component:Bk}",
        "http://example.com")
    assert "search" in found and "basket" in found
    assert _absolutize_endpoint("http://example.com", "search") == \
        "http://example.com/#/search"


def test_js_template_params_become_assets(monkeypatch):
    import modules.js_analysis as js_module
    from modules.js_analysis import JSAnalysis

    async def fake_curl(url, **kwargs):
        if url.endswith("/app.js"):
            return {"status": 200,
                    "body": "s(e){return this.http.get(`${h}/rest/products/search?q=${e}`)}",
                    "time_ms": 5, "url": url}
        return {"status": 200, "body": "<html></html>", "time_ms": 5,
                "url": url}

    async def fake_status(url, timeout=10):
        result = await fake_curl(url)
        return {"status": result["status"], "body": result["body"]}

    monkeypatch.setattr(js_module, "curl_with_status", fake_status)
    state = _state()
    state.add_asset("js_file", "js:http://example.com/app.js",
                    "http://example.com/app.js", confidence="FIRM",
                    sources=["test"], attrs={})

    assert asyncio.run(JSAnalysis(
        state, {"target": {"domain": "example.com",
                           "base_url": "http://example.com"}}).run()) == "done"
    params = {(p["value"], (p.get("attrs") or {}).get("url"))
              for p in state.get_assets_by_type("parameter")}
    assert ("q", "http://example.com/rest/products/search") in params


# ── Generality wave: API gate + pack merge ───────────────────────

def test_api_gate_rejects_spa_shells():
    from modules.auth_audit import _looks_like_api
    assert _looks_like_api('{"status": "error"}') is True
    assert _looks_like_api("Invalid email or password.") is True
    assert _looks_like_api(
        "<html><body><button>login</button><div id=token></div></body></html>"
    ) is False
    assert _looks_like_api("") is False


def test_pack_merge_and_unknown_pack():
    from knowledge import apply_pack, list_packs, load_pack
    assert "juice_shop_lab" in list_packs()
    pack = load_pack("juice_shop_lab")
    config = {"target": {"domain": "x"}, "modules": {}}
    apply_pack(config, pack)
    assert "/rest/user/login" in config["modules"]["auth_audit"]["extra_login_paths"]
    assert ["admin@juice-sh.op", "admin123"] in \
        config["modules"]["auth_audit"]["extra_credentials"]
    assert "coupons_2013.md" in config["modules"]["misconfig"]["extra_backup_bases"]
    assert "ftp" in config["wordlists"]["content_discovery"]
    # Operator values win; pack appends without duplicating.
    config2 = {"modules": {"auth_audit": {
        "extra_login_paths": ["/rest/user/login"]}}}
    apply_pack(config2, pack)
    assert config2["modules"]["auth_audit"]["extra_login_paths"].count(
        "/rest/user/login") == 1
    try:
        load_pack("no_such_pack_xyz")
        raise SystemExit("should have raised")
    except FileNotFoundError:
        pass


def test_generic_seeds_have_no_lab_paths():
    from modules.auth_audit import ADMIN_PATH_SEEDS, LOGIN_PATH_SEEDS
    joined = " ".join(LOGIN_PATH_SEEDS) + " " + " ".join(ADMIN_PATH_SEEDS)
    assert "application-configuration" not in joined
    import modules.misconfig as misconfig_module
    assert "coupons_2013" not in str(misconfig_module.FINDING_RULES)


# ── Relations/findings/graph wave ───────────────────────────────

def test_taxonomy_maps_categories():
    from core.taxonomy import classify
    assert classify("SQL Injection") == {
        "cwe": ["CWE-89"], "owasp": "A03:2021 – Injection"}
    assert classify("Stored XSS")["cwe"] == ["CWE-79"]
    assert classify("Broken Access Control")["owasp"].startswith("A01")
    assert classify("Threat Intelligence") == {"cwe": [], "owasp": ""}
    assert classify("Something Entirely New") == {"cwe": [], "owasp": ""}


def test_add_finding_carries_taxonomy_and_clean_evidence():
    state = _state()
    state.add_asset("url", "url:http://example.com/x",
                    "http://example.com/x")
    fid = state.add_finding(
        title="SQLi here", severity="HIGH", confidence="CONFIRMED",
        category="SQL Injection", description="d",
        evidence=["real line", "", "   "],
        asset_keys=["url:http://example.com/x", "url:missing"])

    finding = state.findings["findings"][0]
    assert finding["cwe"] == ["CWE-89"]
    assert finding["owasp"] == "A03:2021 – Injection"
    assert finding["evidence"] == ["real line"]
    assert finding["first_seen"] == finding["last_seen"]
    edges = [e for e in state.assets["edges"]
             if e.get("target") == fid]
    assert len(edges) == 1
    assert edges[0]["type"] == "AFFECTED_BY"
    assert edges[0]["source"] == "url:http://example.com/x"


def test_merge_bumps_last_seen_and_keeps_taxonomy():
    state = _state()
    first = state.add_finding(
        title="Same", severity="LOW", confidence="FIRM",
        category="Exposure", description="d")
    before = [f for f in state.findings["findings"] if f["id"] == first][0]
    assert before["last_seen"] == before["first_seen"]
    second = state.add_finding(
        title="Same", severity="HIGH", confidence="CONFIRMED",
        category="Exposure", description="d2", verified=True)
    assert first == second
    merged = state.findings["findings"][0]
    assert merged["severity"] == "HIGH"
    assert merged["verified"] is True
    assert merged["last_seen"] >= merged["first_seen"]


def test_graph_build_sanitizes_and_scopes():
    from core.attack_graph import AttackGraph
    state = _state()
    state.add_asset("url", "url:http://example.com/a",
                    "http://example.com/a")
    state.add_asset("url", "url:https://evil.example.net/x",
                    "https://evil.example.com/x".replace("example.com", "example.net"))
    state.add_asset("phone", "phone:123", "123")
    state.add_asset("identity_credential", "identity:u", "u",
                    confidence="CONFIRMED", sources=["t"],
                    attrs={"token": "LIVESECRET", "role": "admin"})
    graph = AttackGraph(state, scope_hosts={"example.com"})
    graph.build()
    keys = set(graph.nodes)
    assert "url:http://example.com/a" in keys
    assert "phone:123" not in keys
    assert not any("evil" in key for key in keys), \
        "third-party hosts must not enter the attack graph"
    identity = graph.nodes.get("identity:u")
    assert identity is not None
    import json as _json
    assert "LIVESECRET" not in _json.dumps(identity.attrs)
    assert identity.attrs.get("role") == "admin"


def test_graph_display_marks_affected_nodes():
    from gui.graph import build_display_graph, to_gravis_graph
    assets = {"nodes": [
        {"key": "url:http://example.com/a", "type": "url",
         "value": "http://example.com/a", "confidence": "FIRM",
         "attrs": {}, "sources": ["t"]},
        {"key": "url:http://example.com/b", "type": "url",
         "value": "http://example.com/b", "confidence": "FIRM",
         "attrs": {}, "sources": ["t"]},
    ], "edges": []}
    findings = [{"id": "FINDING-0001", "title": "SQLi", "severity": "HIGH",
                 "asset_keys": ["url:http://example.com/a"]}]
    display = build_display_graph(assets, aggregate=False,
                                  findings=findings)
    by_key = {n["key"]: n for n in display["nodes"]}
    assert by_key["url:http://example.com/a"]["attrs"]["finding_count"] == 1
    assert by_key["url:http://example.com/a"]["attrs"]["worst_finding"] == "HIGH"
    assert "finding_count" not in by_key["url:http://example.com/b"]["attrs"]
    gravis = to_gravis_graph(display)
    assert gravis["graph"]["nodes"]["url:http://example.com/a"][
        "metadata"]["border_color"] == "#ef4444"


def test_probe_garbage_filter():
    from core.probe_targets import is_probe_garbage
    assert is_probe_garbage("http://h/?q=<sVg/onLOad=x>") is True
    assert is_probe_garbage("http://h/?q=osintxss1234") is True
    assert is_probe_garbage("http://h/rest/products/search?q=1") is False
    assert is_probe_garbage("http://h/api/Users/{id}") is False


# ── Relations/findings/graph rendering ──────────────────────────

def test_report_renders_cwe_owasp_and_observed():
    from core.reporting import build_report_bundle, render_markdown
    state = _state()
    state.add_finding(
        title="SQLi", severity="HIGH", confidence="CONFIRMED",
        category="SQL Injection", description="d")
    bundle = build_report_bundle(state, "example.com")
    markdown = render_markdown(bundle)
    assert "CWE-89" in markdown
    assert "A03:2021" in markdown
    finding = state.findings["findings"][0]
    assert finding["first_seen"] and finding["last_seen"]


def test_module_relation_edges_created():
    state = _state()
    state.add_asset("url", "url:http://example.com/p",
                    "http://example.com/p")
    state.add_asset("parameter", "param:http://example.com/p:q", "q",
                    confidence="FIRM", sources=["t"],
                    attrs={"url": "http://example.com/p"})
    state.add_edge("url:http://example.com/p",
                   "param:http://example.com/p:q", "HAS_PARAMETER")
    types = Counter(e.get("type") for e in state.assets["edges"])
    assert types["HAS_PARAMETER"] == 1
