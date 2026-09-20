"""Tests for evidence and module run persistence."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from state.manager import StateManager


def test_evidence_is_indexed_and_persisted():
    tmpdir = tempfile.mkdtemp()
    state = StateManager(tmpdir)

    evidence_id = state.add_evidence(
        "test_module",
        "http",
        "https://example.com",
        {"status": 200},
    )
    finding_id = state.add_finding(
        title="Evidence-backed Finding",
        severity="LOW",
        confidence="CONFIRMED",
        category="Test",
        description="Test finding.",
        evidence_refs=[evidence_id],
    )
    state.save()

    loaded = StateManager(tmpdir)
    assert loaded.evidence["items"][0]["id"] == evidence_id
    assert loaded.findings["findings"][0]["id"] == finding_id
    assert loaded.findings["findings"][0]["evidence_refs"] == [evidence_id]
    assert (Path(tmpdir) / loaded.evidence["items"][0]["path"]).exists()


def test_module_run_ledger_records_deltas():
    state = StateManager(tempfile.mkdtemp())

    run_id = state.begin_module_run("seed_discovery", "low", 1)
    state.add_check("http:https://example.com")
    state.add_asset("domain", "domain:example.com", "example.com")
    state.add_finding(
        title="Finding",
        severity="INFO",
        confidence="CONFIRMED",
        category="Test",
        description="Test.",
    )
    state.finish_module_run(run_id, "done")

    run = state.module["runs"][0]
    assert run["status"] == "done"
    assert run["requests"] == 1
    assert run["assets_added"] == 1
    assert run["findings_added"] == 1
