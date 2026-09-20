"""State Manager — typed asset graph with confidence ladders."""

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Union

CONFIDENCE_ORDER = {"TENTATIVE": 0, "FIRM": 1, "CONFIRMED": 2}
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class StateManager:
    """Persistent state for a single target investigation."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.state_dir = self.output_dir / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self.assets_file = self.state_dir / "assets.json"
        self.findings_file = self.state_dir / "findings.json"
        self.module_file = self.state_dir / "module.json"
        self.evidence_file = self.state_dir / "evidence.json"
        self.evidence_dir = self.state_dir / "evidence"
        self.evidence_dir.mkdir(exist_ok=True)

        self.assets = self._read_json(self.assets_file, {"nodes": [], "edges": []})
        self.findings = self._read_json(self.findings_file, {"findings": []})
        self.evidence = self._read_json(self.evidence_file, {"items": []})
        self.module = self._read_json(self.module_file, {
            "current": None,
            "completed": [],
            "skipped": [],
            "blocked": [],
            "runs": [],
            "completed_checks": [],
            "waf": {
                "detected": False,
                "vendor": None,
                "blocks": [],
                "allows": [],
                "rate_limit": None,
            },
            "stats": {
                "total_requests": 0,
                "total_assets": 0,
                "total_findings": 0,
                "started_at": self._now(),
                "last_action": self._now(),
            }
        })
        # Migrate old tuple format (module_id, reason) -> dict format
        for key in ("skipped", "blocked"):
            migrated = []
            for entry in self.module.get(key, []):
                if isinstance(entry, (list, tuple)) and len(entry) == 2:
                    migrated.append({"module_id": entry[0], "reason": entry[1]})
                elif isinstance(entry, dict):
                    migrated.append(entry)
            self.module[key] = migrated
        self.module.setdefault("runs", [])
        self.module.setdefault("completed_checks", [])
        self.evidence.setdefault("items", [])
        self._dirty = False

    # ── Asset Management ──────────────────────────────────────────

    def add_asset(self, asset_type: str, key: str, value: str,
                  confidence: str = "TENTATIVE",
                  sources: Optional[list] = None,
                  attrs: Optional[dict] = None) -> dict:
        """Add or upgrade an asset in the graph."""
        node = self._find_node(key)
        if node:
            old_confidence = CONFIDENCE_ORDER.get(node.get("confidence", "TENTATIVE"), 0)
            new_confidence = CONFIDENCE_ORDER.get(confidence, 0)
            if new_confidence > old_confidence:
                node["confidence"] = confidence
            if sources:
                existing = set(node.get("sources", []))
                node["sources"] = list(existing | set(sources))
            if attrs:
                node["attrs"] = {**node.get("attrs", {}), **attrs}
            node["last_seen"] = self._now()
            self._dirty = True
            return node

        node = {
            "type": asset_type,
            "key": key,
            "value": value,
            "confidence": confidence,
            "sources": sources or [],
            "attrs": attrs or {},
            "first_seen": self._now(),
            "last_seen": self._now(),
        }
        self.assets["nodes"].append(node)
        self.module["stats"]["total_assets"] = len(self.assets["nodes"])
        self._dirty = True
        return node

    def add_edge(self, source_key: str, target_key: str, edge_type: str,
                 attrs: Optional[dict] = None):
        """Add a typed edge between two assets."""
        edge = {
            "source": source_key,
            "target": target_key,
            "type": edge_type,
            "attrs": attrs or {},
            "seen_at": self._now(),
        }
        # Dedup
        for existing in self.assets["edges"]:
            if (existing["source"] == source_key
                    and existing["target"] == target_key
                    and existing["type"] == edge_type):
                return
        self.assets["edges"].append(edge)
        self._dirty = True

    def get_assets_by_type(self, asset_type: str) -> list:
        return [n for n in self.assets["nodes"] if n["type"] == asset_type]

    def get_assets_by_confidence(self, confidence: str) -> list:
        return [n for n in self.assets["nodes"] if n["confidence"] == confidence]

    # ── Finding Management ────────────────────────────────────────

    def add_finding(self, title: str, severity: str, confidence: str,
                    category: str, description: str,
                    evidence: Optional[list] = None,
                    remediation: str = "",
                    asset_keys: Optional[list] = None,
                    evidence_refs: Optional[list] = None,
                    risk_score: Optional[int] = None) -> str:
        fid = f"FINDING-{len(self.findings['findings']) + 1:04d}"
        if risk_score is None:
            from core.scoring import score_finding
            risk_score = score_finding(severity, confidence, asset_keys, category)
        finding = {
            "id": fid,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "risk_score": risk_score,
            "category": category,
            "description": description,
            "evidence": evidence or [],
            "evidence_refs": evidence_refs or [],
            "remediation": remediation,
            "asset_keys": asset_keys or [],
            "created_at": self._now(),
        }
        self.findings["findings"].append(finding)
        self.module["stats"]["total_findings"] = len(self.findings["findings"])
        self._dirty = True
        return fid

    def get_findings_by_severity(self, severity: str) -> list:
        return [f for f in self.findings["findings"] if f["severity"] == severity]

    # ── Module State ──────────────────────────────────────────────

    def set_module(self, module_id: str):
        self.module["current"] = module_id
        self._dirty = True

    def begin_module_run(self, module_id: str, detectability: str = "",
                         stage: int = 0) -> str:
        run_id = f"RUN-{len(self.module.get('runs', [])) + 1:04d}"
        run = {
            "id": run_id,
            "module_id": module_id,
            "stage": stage,
            "detectability": detectability,
            "status": "running",
            "started_at": self._now(),
            "finished_at": None,
            "requests_before": self.module["stats"]["total_requests"],
            "requests_after": None,
            "requests": 0,
            "assets_before": len(self.assets["nodes"]),
            "assets_after": None,
            "assets_added": 0,
            "findings_before": len(self.findings["findings"]),
            "findings_after": None,
            "findings_added": 0,
            "error": "",
        }
        self.module.setdefault("runs", []).append(run)
        self.module["current"] = module_id
        self._dirty = True
        return run_id

    def finish_module_run(self, run_id: str, status: str, error: str = ""):
        for run in reversed(self.module.get("runs", [])):
            if run.get("id") == run_id:
                run["status"] = status
                run["finished_at"] = self._now()
                run["requests_after"] = self.module["stats"]["total_requests"]
                run["requests"] = (
                    run["requests_after"] - run.get("requests_before", 0)
                )
                run["assets_after"] = len(self.assets["nodes"])
                run["assets_added"] = (
                    run["assets_after"] - run.get("assets_before", 0)
                )
                run["findings_after"] = len(self.findings["findings"])
                run["findings_added"] = (
                    run["findings_after"] - run.get("findings_before", 0)
                )
                run["error"] = error
                break
        self.module["current"] = None
        self._dirty = True

    def complete_module(self, module_id: str):
        if module_id not in self.module["completed"]:
            self.module["completed"].append(module_id)
        self.module["current"] = None
        self._dirty = True

    def skip_module(self, module_id: str, reason: str = ""):
        if not any(s.get("module_id") == module_id for s in self.module["skipped"]):
            self.module["skipped"].append({"module_id": module_id, "reason": reason})
        self.module["current"] = None
        self._dirty = True

    def block_module(self, module_id: str, reason: str = ""):
        if not any(b.get("module_id") == module_id for b in self.module["blocked"]):
            self.module["blocked"].append({"module_id": module_id, "reason": reason})
        self.module["current"] = None
        self._dirty = True

    def add_check(self, check_name: str):
        if check_name not in self.module["completed_checks"]:
            self.module["completed_checks"].append(check_name)
        self.module["stats"]["last_action"] = self._now()
        self.module["stats"]["total_requests"] += 1
        self._dirty = True

    def is_check_done(self, check_name: str) -> bool:
        return check_name in self.module["completed_checks"]

    def is_module_complete(self, module_id: str) -> bool:
        return module_id in self.module["completed"]

    # ── WAF Tracking ──────────────────────────────────────────────

    def record_waf_block(self, path: str, code: int):
        block = {"path": path, "code": code}
        if block not in self.module["waf"]["blocks"]:
            self.module["waf"]["blocks"].append(block)
        self.module["waf"]["detected"] = True
        self._dirty = True

    def record_waf_allow(self, path: str, code: int):
        allow = {"path": path, "code": code}
        if allow not in self.module["waf"]["allows"]:
            self.module["waf"]["allows"].append(allow)
        self._dirty = True

    def waf_limit_hit(self, threshold: int = 5) -> bool:
        blocks = self.module["waf"]["blocks"]
        return len(blocks) >= threshold

    # ── Evidence Management ───────────────────────────────────────

    def add_evidence(self, module_id: str, evidence_type: str, subject: str,
                     data: Union[dict, list, str]) -> str:
        eid = f"EVIDENCE-{len(self.evidence['items']) + 1:04d}"
        path = self.evidence_dir / f"{eid}.json"
        item = {
            "id": eid,
            "module_id": module_id,
            "type": evidence_type,
            "subject": subject,
            "path": str(path.relative_to(self.output_dir)),
            "created_at": self._now(),
        }
        self._write_json(path, {
            "id": eid,
            "module_id": module_id,
            "type": evidence_type,
            "subject": subject,
            "created_at": item["created_at"],
            "data": data,
        })
        self.evidence["items"].append(item)
        self._dirty = True
        return eid

    # ── Persistence ───────────────────────────────────────────────

    def save(self):
        if not self._dirty:
            return
        self._write_json(self.assets_file, self.assets)
        self._write_json(self.findings_file, self.findings)
        self._write_json(self.module_file, self.module)
        self._write_json(self.evidence_file, self.evidence)
        self._dirty = False

    def summary(self) -> dict:
        return {
            "target": str(self.output_dir),
            "assets": len(self.assets["nodes"]),
            "edges": len(self.assets["edges"]),
            "findings": len(self.findings["findings"]),
            "evidence": len(self.evidence["items"]),
            "findings_by_severity": {
                s: len(self.get_findings_by_severity(s))
                for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            },
            "modules_completed": self.module["completed"],
            "modules_skipped": [s["module_id"] for s in self.module["skipped"]],
            "modules_blocked": [b["module_id"] for b in self.module["blocked"]],
            "waf_detected": self.module["waf"]["detected"],
            "total_requests": self.module["stats"]["total_requests"],
            "module_runs": self.module.get("runs", []),
            "started_at": self.module["stats"]["started_at"],
            "last_action": self.module["stats"]["last_action"],
        }

    # ── Internals ─────────────────────────────────────────────────

    def _find_node(self, key: str) -> Optional[dict]:
        for node in self.assets["nodes"]:
            if node["key"] == key:
                return node
        return None

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _read_json(self, path: Path, default: dict) -> dict:
        if path.exists():
            try:
                return json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return default

    def _write_json(self, path: Path, data: dict):
        path.write_text(json.dumps(data, indent=2, default=str))
