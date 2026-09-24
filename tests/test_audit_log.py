"""Tests for the append-only tamper-evident audit log."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from core.audit_log import AuditLog, AuditLogError


def test_append_and_verify(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("test.event", {"a": 1})
    log.record("test.event2", {"b": 2})
    log.close()

    assert log.verify()["ok"] is True
    records = log.read_records()
    assert len(records) == 2
    assert records[0]["prev"] == "0" * 64
    assert records[1]["prev"] == records[0]["hash"]


def test_tamper_detected(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("test.event", {"a": 1})
    log.record("test.event2", {"b": 2})
    log.close()

    log_path = tmp_path / "audit.jsonl"
    lines = log_path.read_text().splitlines()
    first = json.loads(lines[0])
    first["data"]["a"] = 999
    log_path.write_text(json.dumps(first, sort_keys=True) + "\n" + "\n".join(lines[1:]) + "\n")

    res = log.verify()
    assert res["ok"] is False
    assert res["broken_at_seq"] == 1


def test_chain_reopen_continues_cleanly(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("test.event", {"a": 1})
    log.close()

    log2 = AuditLog(path)
    log2.record("test.event2", {"b": 2})
    log2.close()

    assert log2.verify()["ok"] is True
    records = log2.read_records()
    assert len(records) == 2
    assert records[0]["seq"] == 1
    assert records[1]["seq"] == 2
    assert records[1]["prev"] == records[0]["hash"]


def test_corrupted_existing_log_rejected(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text('{"seq": 1, "garbage": true}\n')
    with pytest.raises(AuditLogError):
        AuditLog(path)


def test_sensitive_params_redacted(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.action("web.test", "https://example.com",
               {"url": "https://example.com", "api_key": "sk-secret", "q": "1"},
               risk="LOW", result={"success": True})
    log.close()

    rec = log.read_records()[-1]
    assert rec["data"]["params"]["api_key"] == "<redacted>"
    assert rec["data"]["params"]["url"] != "<redacted>"


def test_typed_events_serialize(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.engagement_start("example.com", "agent", roe_id="ENG-1", dry_run=True)
    log.roe_loaded({"engagement_id": "ENG-1"})
    log.plan({"focus": "x", "hypotheses": [{"id": "HYP-1", "action_id": "web.xss.reflected"}]})
    log.gate("scope", "web.xss.reflected", "example.com", allowed=False, reason="outside scope")
    log.close()

    assert log.verify()["ok"] is True
    events = [r["event"] for r in log.read_records()]
    assert events == ["engagement.start", "roe.loaded", "plan", "gate.decision"]