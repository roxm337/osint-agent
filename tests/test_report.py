"""Tests for report output placement."""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.report import Reporting
from state.manager import StateManager


def test_report_writes_to_state_output_dir():
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    state.add_asset("domain", "domain:example.com", "example.com")
    state.add_finding(
        title="Example Finding",
        severity="INFO",
        confidence="CONFIRMED",
        category="Test",
        description="Generated during test.",
    )

    config = {
        "target": {"domain": "example.com"},
        "paths": {"output_dir": str(tmpdir / "wrong-output")},
    }

    result = asyncio.run(Reporting(state, config).run())

    assert result == "done"
    assert (tmpdir / "run" / "example.com" / "example.com_report.md").exists()
    assert (tmpdir / "run" / "example.com" / "example.com_findings.json").exists()
    assert not (tmpdir / "wrong-output" / "example.com_report.md").exists()


def test_report_writes_advanced_artifacts():
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    state.add_asset("domain", "domain:example.com", "example.com")
    state.add_asset("webapp", "webapp:https://example.com", "https://example.com")
    state.add_edge("domain:example.com", "webapp:https://example.com", "hosts")
    evidence_id = state.add_evidence(
        "content_discovery",
        "json",
        "https://example.com/admin",
        {"status": 403, "path": "/admin"},
    )
    run_id = state.begin_module_run("content_discovery", "high", 4)
    state.add_check("content_discovery:https://example.com")
    state.finish_module_run(run_id, "completed")
    state.add_finding(
        title="Administrative Path Exposed",
        severity="HIGH",
        confidence="FIRM",
        category="Exposure",
        description="A restricted administrative path was discovered.",
        evidence=["/admin returned 403"],
        evidence_refs=[evidence_id],
        asset_keys=["webapp:https://example.com"],
        remediation="Restrict admin paths and verify access controls.",
    )

    config = {"target": {"domain": "example.com"}}
    result = asyncio.run(Reporting(state, config).run())
    output_dir = tmpdir / "run" / "example.com"

    assert result == "done"
    report = (output_dir / "example.com_report.md").read_text()
    summary = json.loads((output_dir / "example.com_summary.json").read_text())

    assert (output_dir / "example.com_executive_summary.md").exists()
    assert "## Executive Summary" in report
    assert "## Risk Overview" in report
    assert "## Top Findings" in report
    assert "## Module Run Ledger" in report
    assert "Administrative Path Exposed" in report
    assert summary["risk"]["critical_high"] == 1
    assert summary["risk"]["top_findings"][0]["title"] == "Administrative Path Exposed"
    assert summary["modules"]["runs"][0]["module_id"] == "content_discovery"
