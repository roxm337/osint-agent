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


def test_reputation_enrich_with_abuseipdb(monkeypatch):
    async def fake_abuseipdb(ip, api_key):
        return {"data": {"abuseConfidenceScore": 42, "totalReports": 3}}

    monkeypatch.setattr(reputation_module, "abuseipdb_check", fake_abuseipdb)

    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    state.add_asset("ip", "ip:203.0.113.10", "203.0.113.10")
    config = {
        "target": {"domain": "example.com"},
        "api_keys": {"abuseipdb": "test-key"},
    }

    result = asyncio.run(ReputationEnrich(state, config).run())

    assert result == "done"
    assert state.findings["findings"][0]["title"] == "AbuseIPDB Reputation Signals: 1 IP(s)"


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
