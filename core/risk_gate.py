"""Risk Gate — tiered action approval system.

Approval is OPT-IN.

Default (risk_gate.enforce unset / false): fully permissive. Every tier
passes, no authorization check, no mode check.

With risk_gate.enforce = true, the deterministic tier logic applies:
  SAFE        — always allowed
  LOW         — allowed only in active mode
  MEDIUM      — allowed only when detectability.allow_high = true
  HIGH        — allowed only when detectability.allow_high = true, flagged
  DESTRUCTIVE — always blocked, flagged for approval
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
    """Tiered approval. Permissive by default; strict when enforce=true."""

    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        target_cfg = cfg.get("target", {})
        detectability = cfg.get("detectability", {})

        self.enforce = bool(cfg.get("risk_gate", {}).get("enforce", False))
        self.allow_high = bool(detectability.get("allow_high", False))
        self.target_mode = target_cfg.get("mode", "passive")
        self.authorization = target_cfg.get("authorization", "pending")

        # In enforcement mode, active tiers come from allow_high.
        if self.enforce:
            self.allowed_tiers: set[RiskTier] = {RiskTier.SAFE, RiskTier.LOW}
            if self.allow_high:
                self.allowed_tiers.add(RiskTier.MEDIUM)
                self.allowed_tiers.add(RiskTier.HIGH)
        else:
            # Permissive: every tier in the allowlist so nothing is refused.
            self.allowed_tiers = {
                RiskTier.SAFE, RiskTier.LOW, RiskTier.MEDIUM,
                RiskTier.HIGH, RiskTier.DESTRUCTIVE,
            }

    def approve(self, tier: RiskTier, action_id: str = "",
                target: str = "") -> RiskDecision:
        if not self.enforce:
            return RiskDecision(True, tier, "risk gate disabled")

        if self.authorization not in ("confirmed", "active"):
            return RiskDecision(False, tier, "no authorization confirmed")

        if tier == RiskTier.SAFE:
            return RiskDecision(True, tier, "SAFE actions always allowed")

        if tier == RiskTier.LOW:
            if self.target_mode == "passive":
                return RiskDecision(False, tier,
                                    "LOW actions not allowed in passive mode")
            return RiskDecision(True, tier, "LOW actions allowed")

        if tier == RiskTier.MEDIUM:
            if RiskTier.MEDIUM not in self.allowed_tiers:
                return RiskDecision(False, tier,
                                    "MEDIUM actions require active mode")
            return RiskDecision(True, tier, "MEDIUM actions allowed")

        if tier == RiskTier.HIGH:
            if RiskTier.HIGH not in self.allowed_tiers:
                return RiskDecision(False, tier,
                                    "HIGH actions require ROE opt-in")
            return RiskDecision(True, tier, "HIGH actions allowed",
                                requires_approval=True)

        if tier == RiskTier.DESTRUCTIVE:
            return RiskDecision(False, tier,
                                "DESTRUCTIVE actions blocked by default",
                                requires_approval=True)

        return RiskDecision(False, tier, f"unknown tier: {tier}")

    def require(self, tier: RiskTier, action_id: str = "",
                target: str = "") -> str:
        decision = self.approve(tier, action_id, target)
        if not decision.allowed:
            raise PermissionError(
                f"Risk gate blocked {action_id}: {decision.reason}"
            )
        return decision.reason