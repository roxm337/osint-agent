"""Tests for state manager — asset graph, findings, persistence."""

import sys
import json
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from state.manager import StateManager


class TestStateManager:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state = StateManager(self.tmpdir)

    def test_add_asset(self):
        asset = self.state.add_asset(
            "domain", "domain:example.com", "example.com",
            confidence="CONFIRMED", sources=["test"],
        )
        assert asset["type"] == "domain"
        assert asset["key"] == "domain:example.com"
        assert asset["confidence"] == "CONFIRMED"

    def test_add_asset_upgrades_confidence(self):
        first = self.state.add_asset(
            "ip", "ip:1.2.3.4", "1.2.3.4",
            confidence="TENTATIVE", sources=["test"],
        )
        assert first["confidence"] == "TENTATIVE"

        upgraded = self.state.add_asset(
            "ip", "ip:1.2.3.4", "1.2.3.4",
            confidence="CONFIRMED", sources=["better test"],
        )
        assert upgraded["confidence"] == "CONFIRMED"
        assert "test" in upgraded["sources"]
        assert "better test" in upgraded["sources"]

    def test_add_edge_dedup(self):
        self.state.add_edge("domain:x", "ip:1.2.3.4", "RESOLVES_TO")
        self.state.add_edge("domain:x", "ip:1.2.3.4", "RESOLVES_TO")
        assert len(self.state.assets["edges"]) == 1

    def test_add_finding(self):
        fid = self.state.add_finding(
            title="Test Finding",
            severity="HIGH",
            confidence="CONFIRMED",
            category="Test",
            description="A test finding",
            evidence=["evidence1"],
            remediation="fix it",
            asset_keys=["domain:example.com"],
        )
        assert fid == "FINDING-0001"
        assert len(self.state.findings["findings"]) == 1
        assert self.state.module["stats"]["total_findings"] == 1

    def test_get_assets_by_type(self):
        self.state.add_asset("ip", "ip:1.2.3.4", "1.2.3.4")
        self.state.add_asset("domain", "domain:x", "x")
        ips = self.state.get_assets_by_type("ip")
        assert len(ips) == 1
        assert ips[0]["key"] == "ip:1.2.3.4"

    def test_get_findings_by_severity(self):
        self.state.add_finding(title="High", severity="HIGH", confidence="CONFIRMED",
                                category="Test", description="desc")
        self.state.add_finding(title="Low", severity="LOW", confidence="CONFIRMED",
                                category="Test", description="desc")
        highs = self.state.get_findings_by_severity("HIGH")
        assert len(highs) == 1
        assert highs[0]["title"] == "High"

    def test_skip_block_module(self):
        self.state.skip_module("mod_a", "no data")
        self.state.block_module("mod_b", "error")
        assert len(self.state.module["skipped"]) == 1
        assert self.state.module["skipped"][0]["module_id"] == "mod_a"
        assert self.state.module["skipped"][0]["reason"] == "no data"
        assert len(self.state.module["blocked"]) == 1

    def test_waf_limit_hit(self):
        assert self.state.waf_limit_hit() is False
        self.state.record_waf_block("/test", 503)
        self.state.record_waf_block("/test2", 503)
        self.state.record_waf_block("/test3", 503)
        self.state.record_waf_block("/test4", 503)
        self.state.record_waf_block("/test5", 503)
        assert self.state.waf_limit_hit(threshold=5) is True

    def test_persistence(self):
        self.state.add_asset("domain", "domain:x", "x")
        self.state.add_finding(title="F", severity="INFO", confidence="CONFIRMED",
                                category="C", description="D")
        self.state.save()

        state2 = StateManager(self.tmpdir)
        assert len(state2.assets["nodes"]) == 1
        assert len(state2.findings["findings"]) == 1
