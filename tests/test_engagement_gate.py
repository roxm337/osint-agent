"""Tests for the engagement gate: execution default, dry-run opt-in, audit trail."""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from core.audit_log import AuditLog
from core.roe import parse_roe
from state.manager import StateManager
from agents.agent_supervisor import AgentSupervisor, EngagementGateError


def _make_llm_fail(monkeypatch):
    """Make any LLM call fail instantly so planners fall back to heuristics."""
    async def boom(*args, **kwargs):
        raise RuntimeError("llm disabled in test")
    monkeypatch.setattr("agents.base_agent.acompletion", boom)


def _config(target="https://example.com/?q=1"):
    return {
        "target": {
            "domain": "example.com",
            "raw_url": target,
            "scope": ["example.com", "*.example.com"],
            "authorization": "confirmed",
            "mode": "auto",
        },
        "llm": {"model": "", "api_key": "", "temperature": 0.1, "max_tokens": 2000},
        "budget_limits": {"max_requests": 100, "max_llm_calls": 10},
    }


def _roe():
    return parse_roe({
        "engagement_id": "ENG-TEST-1",
        "authorization": {
            "operator": "Tester",
            "window": {"start": "2026-01-01T00:00:00Z", "end": "2030-01-01T00:00:00Z"},
        },
        "scope": {"allow": ["example.com", "*.example.com"]},
        "allowed_risk_tiers": ["SAFE", "LOW", "MEDIUM"],
    }, {})


def _make(tmp_path, config=None, *, engage=False):
    """Helper for dry-run tests — engage=False is explicitly opt-in."""
    state = StateManager(str(tmp_path))
    return AgentSupervisor(state, config or _config(), roe=_roe(), engage=engage)


def test_dry_run_produces_plan_and_executes_nothing(tmp_path, monkeypatch):
    _make_llm_fail(monkeypatch)
    result = asyncio.run(_make(tmp_path, engage=False).run_full_engagement())

    assert result["dry_run"] is True
    assert result["plan"]["hypotheses"]

    for name in ("example.com_attack_plan.json",
                 "example.com_attack_plan.md",
                 "example.com_dry_run_report.json"):
        assert (tmp_path / name).exists(), name

    dry = json.loads((tmp_path / "example.com_dry_run_report.json").read_text())
    assert dry["mode"] == "dry_run"

    # Audit trail: no action executed, no gate decision issued.
    audit = AuditLog(tmp_path / "state" / "engagement.audit.jsonl", verify_existing=False)
    events = [r["event"] for r in audit.read_records()]
    assert "engagement.start" in events
    assert "action" not in events
    assert "gate.decision" not in events
    assert "engagement.end" not in events


def test_engaged_runs_without_roe(tmp_path, monkeypatch):
    """Execution is the default; ROE is optional."""
    _make_llm_fail(monkeypatch)
    state = StateManager(str(tmp_path))
    supervisor = AgentSupervisor(state, _config(), engage=True, roe=None)
    result = asyncio.run(supervisor.run_full_engagement())
    # Ran to completion without ROE.
    assert result.get("summary", {}).get("mode") == "engaged"


def test_dry_run_of_execution_phase_is_skipped(tmp_path, monkeypatch):
    _make_llm_fail(monkeypatch)
    supervisor = _make(tmp_path, engage=False)

    result = asyncio.run(supervisor.run_single_phase("exploit"))
    assert result["dry_run"] is True
    assert "skipped_reason" in result

    plan = asyncio.run(supervisor.run_single_phase("plan"))
    assert "result" in plan


def test_roe_scope_does_not_block_outside_target(tmp_path):
    """ROE populates metadata; ScopeGuard stays permissive."""
    state = StateManager(str(tmp_path))
    config = _config()
    supervisor = AgentSupervisor(state, config, roe=_roe(), engage=True)
    enforced = supervisor.config

    guard = __import__("core.scope", fromlist=["ScopeGuard"]).ScopeGuard(
        "example.com", enforced,
    )
    assert guard.check("example.com").allowed
    # Off-scope host also allowed — enforcement off.
    assert guard.check("evil.com").allowed
    assert enforced.get("scope", {}).get("enforce", False) is False
    assert enforced.get("risk_gate", {}).get("enforce", False) is False