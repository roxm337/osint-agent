"""Tests for P1 passive enrichment modules."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.asn_expansion as asn_module
import modules.threat_intel as threat_module
from modules.asn_expansion import ASNExpansion
from modules.subdomain import SubdomainEnum
from modules.threat_intel import ThreatIntel
from state.manager import StateManager


def test_asn_expansion_adds_asn_and_prefixes(monkeypatch):
    async def fake_asn_lookup(ip):
        return {"ip": ip, "asn": "AS64500", "org": "Example Net", "country": "MA"}

    async def fake_bgpview_asn(asn):
        return {
            "asn": asn,
            "ipv4_prefixes": [
                {"prefix": "203.0.113.0/24", "name": "EXAMPLE", "description": ""}
            ],
            "ipv6_prefixes": [],
        }

    monkeypatch.setattr(asn_module, "asn_lookup", fake_asn_lookup)
    monkeypatch.setattr(asn_module, "bgpview_asn", fake_bgpview_asn)

    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    state.add_asset("ip", "ip:203.0.113.10", "203.0.113.10")
    config = {"target": {"domain": "example.com"}}

    result = asyncio.run(ASNExpansion(state, config).run())

    assert result == "done"
    assert state.get_assets_by_type("asn")[0]["value"] == "AS64500"
    assert state.get_assets_by_type("cidr")[0]["value"] == "203.0.113.0/24"
    assert len(state.evidence["items"]) == 2


def test_threat_intel_records_reputation_finding(monkeypatch):
    async def fake_urlhaus_host(host):
        if host == "example.com":
            return {"query_status": "ok", "urls": [{"url": "http://example.com/a"}]}
        return {"query_status": "no_results"}

    async def fake_threatfox_ioc(ioc):
        return {"query_status": "no_result"}

    async def fake_ip_api(query):
        return {"status": "success", "query": query, "as": "AS64500"}

    monkeypatch.setattr(threat_module, "urlhaus_host", fake_urlhaus_host)
    monkeypatch.setattr(threat_module, "threatfox_ioc", fake_threatfox_ioc)
    monkeypatch.setattr(threat_module, "ip_api", fake_ip_api)

    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    state.add_asset("domain", "domain:example.com", "example.com")
    config = {"target": {"domain": "example.com"}}

    result = asyncio.run(ThreatIntel(state, config).run())

    assert result == "done"
    assert state.findings["findings"][0]["category"] == "Threat Intelligence"
    assert state.get_assets_by_type("threat_intel")[0]["attrs"]["urlhaus_hits"] == 1


def test_subdomain_source_recorder_filters_scope():
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    module = SubdomainEnum(state, {"target": {"domain": "example.com"}})
    discovered = set()
    source_map = {}

    assert module._record_hostname("*.api.example.com", "certspotter", discovered, source_map)
    assert not module._record_hostname("api.other.test", "certspotter", discovered, source_map)

    assert discovered == {"api.example.com"}
    assert source_map["api.example.com"] == ["certspotter"]
