"""Tests for P3 keyed enrichment modules."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.keyed_subdomains as keyed_subdomains_module
import modules.reputation_enrich as reputation_module
import modules.vt_enrich as vt_module
from modules.keyed_subdomains import KeyedSubdomains
from modules.reputation_enrich import ReputationEnrich
from modules.vt_enrich import VirusTotalEnrich
from state.manager import StateManager


def test_vt_enrich_skips_without_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    result = asyncio.run(VirusTotalEnrich(state, {"target": {"domain": "example.com"}}).run())

    assert result == "skipped"
    assert state.module["skipped"][0]["module_id"] == "vt_enrich"


def test_vt_enrich_adds_subdomains_and_reputation_finding(monkeypatch):
    async def fake_domain(domain, api_key):
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 0,
                        "harmless": 5,
                    }
                }
            }
        }

    async def fake_subdomains(domain, api_key):
        return ["api.example.com"]

    async def fake_ip(ip, api_key):
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}

    monkeypatch.setattr(vt_module, "virustotal_domain", fake_domain)
    monkeypatch.setattr(vt_module, "virustotal_domain_subdomains", fake_subdomains)
    monkeypatch.setattr(vt_module, "virustotal_ip", fake_ip)

    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    state.add_asset("domain", "domain:example.com", "example.com")
    config = {
        "target": {"domain": "example.com"},
        "api_keys": {"virustotal": "test-key"},
    }

    result = asyncio.run(VirusTotalEnrich(state, config).run())

    assert result == "done"
    assert state.get_assets_by_type("subdomain")[0]["value"] == "api.example.com"
    assert state.findings["findings"][0]["title"] == "VirusTotal Reputation Signal on Domain"


def test_vt_enrich_does_not_ask_about_a_loopback_address(monkeypatch):
    """A HIGH finding this module produced: `VirusTotal IP Reputation
    Signals: 127.0.0.1: malicious=1`, against a target whose whole surface is
    one container. A reputation vote about an address nothing can reach from
    outside says nothing about the target."""
    queried = []

    async def fake_domain(domain, api_key):
        return {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 0, "suspicious": 0, "harmless": 5}}}}

    async def fake_subdomains(domain, api_key):
        return []

    async def fake_ip(ip, api_key):
        queried.append(ip)
        return {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 7, "suspicious": 0}}}}

    monkeypatch.setattr(vt_module, "virustotal_domain", fake_domain)
    monkeypatch.setattr(vt_module, "virustotal_domain_subdomains", fake_subdomains)
    monkeypatch.setattr(vt_module, "virustotal_ip", fake_ip)

    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    state.add_asset("ip", "ip:127.0.0.1", "127.0.0.1")
    state.add_asset("ip", "ip:10.0.0.4", "10.0.0.4")
    state.add_asset("ip", "ip:8.8.8.8", "8.8.8.8")
    config = {"target": {"domain": "example.com"},
              "api_keys": {"virustotal": "test-key"}}

    result = asyncio.run(VirusTotalEnrich(state, config).run())

    assert result == "done"
    assert queried == ["8.8.8.8"], "non-routable addresses must not be queried"
    signals = [f for f in state.findings["findings"]
               if f["title"].startswith("VirusTotal IP Reputation Signals")]
    assert len(signals) == 1
    assert "8.8.8.8" in signals[0]["evidence"][0]


def test_reputation_enrich_with_abuseipdb(monkeypatch):
    from datetime import datetime, timedelta, timezone
    recent = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()

    async def fake_abuseipdb(ip, api_key):
        return {"data": {"abuseConfidenceScore": 75, "totalReports": 8,
                         "lastReportedAt": recent}}

    monkeypatch.setattr(reputation_module, "abuseipdb_check", fake_abuseipdb)

    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    state.add_asset("ip", "ip:8.8.8.8", "8.8.8.8")
    config = {
        "target": {"domain": "example.com"},
        "api_keys": {"abuseipdb": "test-key"},
    }

    result = asyncio.run(ReputationEnrich(state, config).run())

    assert result == "done"
    assert state.findings["findings"][0]["title"] == "AbuseIPDB Reputation Signals: 1 IP(s)"


def test_reputation_enrich_ignores_stale_single_reports(monkeypatch):
    async def fake_abuseipdb(ip, api_key):
        return {"data": {"abuseConfidenceScore": 42, "totalReports": 3}}

    monkeypatch.setattr(reputation_module, "abuseipdb_check", fake_abuseipdb)

    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    state.add_asset("ip", "ip:8.8.8.8", "8.8.8.8")
    config = {
        "target": {"domain": "example.com"},
        "api_keys": {"abuseipdb": "test-key"},
    }

    assert asyncio.run(ReputationEnrich(state, config).run()) == "done"
    assert state.findings["findings"] == [], \
        "one stale user report is not a HIGH finding"


def test_keyed_subdomains_adds_sources(monkeypatch):
    async def fake_chaos(domain, api_key):
        return ["api.example.com", "cdn.example.com"]

    monkeypatch.setattr(keyed_subdomains_module, "chaos_subdomains", fake_chaos)

    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    state.add_asset("domain", "domain:example.com", "example.com")
    config = {
        "target": {"domain": "example.com"},
        "api_keys": {"chaos": "test-key"},
    }

    result = asyncio.run(KeyedSubdomains(state, config).run())

    assert result == "done"
    assert len(state.get_assets_by_type("subdomain")) == 2
