"""Risk Gate — tiered action approval system.

Approval is OPT-IN. Default is disabled — every tier passes.
Enable with `risk_gate: {enforce: true}` in config.yaml.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class RiskTier(Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    DESTRUCTIVE = "DESTRUCTIVE"


@dataclass
class RiskDecision:
    allowed: bool
    tier: RiskTier
    reason: str
    requires_approval: bool = False


class RiskGate:
    """Deterministic risk approval. Permissive by default."""

    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        target_cfg = cfg.get("target", {})
        detectability = cfg.get("detectability", {})

        self.enforce = bool(cfg.get("risk_gate", {}).get("enforce", False))
        self.allow_high = detectability.get("allow_high", True)
        self.target_mode = target_cfg.get("mode", "active")
        self.authorization = target_cfg.get("authorization", "confirmed")

        self.allowed_tiers: set[RiskTier] = {
            RiskTier.SAFE, RiskTier.LOW, RiskTier.MEDIUM,
            RiskTier.HIGH, RiskTier.DESTRUCTIVE,
        }

    def approve(self, tier: RiskTier, action_id: str = "",
                target: str = "") -> RiskDecision:
        if not self.enforce:
            return RiskDecision(True, tier, "risk gate disabled")

        if self.authorization not in ("confirmed", "active"):
            return RiskDecision(False, tier, "no authorization confirmed")

        if tier in self.allowed_tiers:
            return RiskDecision(True, tier, f"{tier.value} actions allowed")

        return RiskDecision(False, tier, f"{tier.value} blocked by policy")

    def require(self, tier: RiskTier, action_id: str = "",
                target: str = "") -> str:
        decision = self.approve(tier, action_id, target)
        if not decision.allowed:
            raise PermissionError(
                f"Risk gate blocked {action_id}: {decision.reason}"
            )
        return decision.reason