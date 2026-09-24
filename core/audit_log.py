"""Append-only, tamper-evident engagement audit log.

Every decision and action in an engagement is written to a JSONL file as a
record chained to the previous record via SHA-256. Any modification to a prior
record breaks the hash chain and is detectable by `AuditLog.verify()`.

Schema per line (one JSON object per line):

    {"seq": 1, "ts": "...", "event": "...", "data": {...},
     "prev": "<sha256 of previous record>", "hash": "<sha256 of this record>"}

The `hash` covers the canonical serialization of everything before it in the
record (seq, ts, event, data, prev), so reordering, deletion, or editing any
field is caught by verification.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any, Optional


class AuditLogError(Exception):
    pass


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


class AuditLog:
    """Thread-safe append-only audit log with a SHA-256 hash chain."""

    def __init__(self, path: str | Path, *, verify_existing: bool = True):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0
        self._last_hash = _ZERO_HASH
        self._file = None

        if self.path.exists():
            if verify_existing:
                state = self.verify()
                if not state["ok"]:
                    raise AuditLogError(
                        f"existing audit log is corrupted at seq {state.get('broken_at_seq')}"
                    )
            self._load_tail()

    # ── lifecycle ─────────────────────────────────────────────────

    def _load_tail(self):
        """Recover seq and last_hash from the trailing record of an existing log."""
        last = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)
        if last:
            self._seq = int(last.get("seq", 0))
            self._last_hash = last.get("hash", _ZERO_HASH)

    def open(self) -> "AuditLog":
        if self._file is None or self._file.closed:
            self._file = self.path.open("a", encoding="utf-8")
        return self

    def close(self):
        with self._lock:
            if self._file and not self._file.closed:
                self._file.flush()
                self._file.close()
                self._file = None

    def __enter__(self) -> "AuditLog":
        return self.open()

    def __exit__(self, *exc):
        self.close()

    # ── writing ───────────────────────────────────────────────────

    def record(self, event: str, data: Optional[dict] = None) -> int:
        """Append a record and return its sequence number."""
        with self._lock:
            self.open()
            self._seq += 1
            payload = {
                "seq": self._seq,
                "ts": _now(),
                "event": event,
                "data": data or {},
                "prev": self._last_hash,
            }
            h = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
            payload["hash"] = h
            line = json.dumps(payload, sort_keys=True)
            try:
                self._file.write(line + "\n")
                self._file.flush()
            finally:
                pass
            self._last_hash = h
            return self._seq

    # ── verification ──────────────────────────────────────────────

    def verify(self) -> dict:
        """Replay the chain and report integrity."""
        if not self.path.exists():
            return {"ok": True, "records": 0}
        prev = _ZERO_HASH
        count = 0
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                count += 1
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    return {"ok": False, "records": count, "broken_at_seq": count,
                            "reason": "invalid JSON"}
                stored_hash = record.get("hash")
                stored_prev = record.get("prev")
                recomputed = hashlib.sha256(
                    _canonical({
                        "seq": record.get("seq"),
                        "ts": record.get("ts"),
                        "event": record.get("event"),
                        "data": record.get("data", {}),
                        "prev": record.get("prev"),
                    }).encode("utf-8")
                ).hexdigest()
                if stored_hash != recomputed:
                    return {"ok": False, "records": count, "broken_at_seq": count,
                            "reason": "hash mismatch"}
                if stored_prev != prev:
                    return {"ok": False, "records": count, "broken_at_seq": count,
                            "reason": "broken chain link"}
                prev = stored_hash
        return {"ok": True, "records": count, "last_hash": prev}

    def read_records(self) -> list[dict]:
        if not self.path.exists():
            return []
        records = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    # ── typed events ──────────────────────────────────────────────

    def engagement_start(self, target: str, mode: str, roe_id: str = "",
                         dry_run: bool = True) -> int:
        return self.record("engagement.start", {
            "target": target, "mode": mode, "roe_id": roe_id, "dry_run": dry_run,
        })

    def engagement_end(self, summary: dict) -> int:
        return self.record("engagement.end", summary)

    def roe_loaded(self, roe: dict) -> int:
        return self.record("roe.loaded", roe)

    def plan(self, plan: dict) -> int:
        safe = {
            "focus": plan.get("focus", ""),
            "hypothesis_count": len(plan.get("hypotheses", [])),
            "hypotheses": [
                {
                    "id": h.get("id"),
                    "title": h.get("title"),
                    "target": h.get("target"),
                    "action_id": h.get("action_id"),
                    "assigned_to": h.get("assigned_to"),
                }
                for h in plan.get("hypotheses", [])[:25]
            ],
            "module_sequence": plan.get("module_sequence", []),
            "watch_items": plan.get("watch_items", []),
        }
        return self.record("plan", safe)

    def gate(self, kind: str, action_id: str, target: str,
             allowed: bool, reason: str, risk: str = "") -> int:
        return self.record("gate.decision", {
            "kind": kind, "action_id": action_id, "target": target,
            "allowed": allowed, "reason": reason, "risk": risk,
        })

    def action(self, action_id: str, target: str, params: dict,
               risk: str, result: dict) -> int:
        return self.record("action", {
            "action_id": action_id,
            "target": target,
            "risk": risk,
            "params": _sanitize(params),
            "result": _truncate(result),
        })

    def budget(self, summary: dict) -> int:
        return self.record("budget", summary)


_ZERO_HASH = "0" * 64


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


_SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey", "key",
    "cookie", "authorization", "auth", "bearer", "sig", "signature", "hash",
    "session", "sessionid", "credit", "card",
}


def _sanitize(params: dict) -> dict:
    out = {}
    for key, value in (params or {}).items():
        if any(s in str(key).lower() for s in _SENSITIVE_KEYS) and value:
            out[str(key)] = "<redacted>"
        elif isinstance(value, dict):
            out[str(key)] = _sanitize(value)
        elif isinstance(value, list):
            out[str(key)] = [v if not isinstance(v, dict) else _sanitize(v)
                             for v in value]
        else:
            out[str(key)] = value
    return out


def _truncate(obj: Any, max_len: int = 2000) -> Any:
    if isinstance(obj, dict):
        return {k: _truncate(v, max_len) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_truncate(v, max_len) for v in obj][:20]
    text = str(obj)
    return text[:max_len] if len(text) > max_len else text