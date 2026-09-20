"""Blackboard — shared state and append-only event store for multi-agent system."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from state.manager import StateManager


class AgentRole(Enum):
    SUPERVISOR = "supervisor"
    RECON = "recon"
    VULN_ANALYST = "vuln_analyst"
    EXPLOITATION = "exploitation"
    VERIFICATION = "verification"
    REPORTING = "reporting"


@dataclass
class Hypothesis:
    id: str
    title: str
    description: str
    likelihood: float  # 0.0 - 1.0
    impact: float      # 0.0 - 1.0
    target: str
    technique: str
    action_id: str = ""
    params: dict = field(default_factory=dict)
    status: str = "proposed"  # proposed | testing | confirmed | rejected
    evidence_refs: list = field(default_factory=list)
    created_by: str = ""
    result: Optional[dict] = None


@dataclass
class AgentMessage:
    source: AgentRole
    target: AgentRole
    msg_type: str  # task_assigned | result | hypothesis | request_info | plan_update
    payload: dict = field(default_factory=dict)
    timestamp: float = 0.0


class Blackboard:
    """Append-only event store + shared state for multi-agent coordination."""

    def __init__(self, state: StateManager, config: dict):
        self.state = state
        self.config = config
        self.hypotheses: list[Hypothesis] = []
        self.messages: list[AgentMessage] = []
        self.current_plan: dict = {}
        self._agent_status: dict[str, str] = {}

    # ── Hypothesis lifecycle ──────────────────────────────────────

    def add_hypothesis(self, hypothesis: Hypothesis) -> str:
        self.hypotheses.append(hypothesis)
        return hypothesis.id

    def update_hypothesis(self, hyp_id: str, **updates):
        for h in self.hypotheses:
            if h.id == hyp_id:
                for k, v in updates.items():
                    setattr(h, k, v)
                return

    def get_hypotheses(self, status: Optional[str] = None) -> list[Hypothesis]:
        if status:
            return [h for h in self.hypotheses if h.status == status]
        return self.hypotheses.copy()

    def top_hypotheses(self, limit: int = 5) -> list[Hypothesis]:
        scored = sorted(self.hypotheses, key=lambda h: h.likelihood * h.impact, reverse=True)
        return scored[:limit]

    # ── Agent communication ───────────────────────────────────────

    def send(self, source: AgentRole, target: AgentRole,
             msg_type: str, payload: Optional[dict] = None):
        msg = AgentMessage(
            source=source,
            target=target,
            msg_type=msg_type,
            payload=payload or {},
            timestamp=time.time(),
        )
        self.messages.append(msg)
        return msg

    def read(self, target: AgentRole, msg_type: Optional[str] = None) -> list[AgentMessage]:
        filtered = [m for m in self.messages if m.target == target]
        if msg_type:
            filtered = [m for m in filtered if m.msg_type == msg_type]
        return filtered

    def ack(self, msg: AgentMessage):
        """Mark a message as processed."""
        pass  # kept simple; could be extended with ack tracking

    # ── Plan management ───────────────────────────────────────────

    def set_plan(self, plan: dict):
        self.current_plan = plan

    def get_plan(self) -> dict:
        return self.current_plan

    # ── Agent status ──────────────────────────────────────────────

    def set_agent_status(self, agent_id: str, status: str):
        self._agent_status[agent_id] = status

    def get_agent_status(self, agent_id: str) -> str:
        return self._agent_status.get(agent_id, "idle")

    # ── Serialization ─────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "hypotheses": [asdict(h) for h in self.hypotheses],
            "messages": [
                {"source": m.source.value, "target": m.target.value,
                 "type": m.msg_type, "payload": m.payload,
                 "timestamp": m.timestamp}
                for m in self.messages[-100:]  # keep last 100
            ],
            "current_plan": self.current_plan,
            "agent_status": self._agent_status,
            "stats": {
                "total_hypotheses": len(self.hypotheses),
                "total_messages": len(self.messages),
                "confirmed": len([h for h in self.hypotheses if h.status == "confirmed"]),
                "rejected": len([h for h in self.hypotheses if h.status == "rejected"]),
            },
        }

    def save(self, path: str | Path):
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))
