"""Risk Gate — tiered action approval system.

Tiers:
  SAFE        — auto-run, no side effects, read-only queries
  LOW         — auto-run, bounded probes, no data modification
  MEDIUM      — runs if ROE allows medium-risk actions
  HIGH        — requires ROE opt-in, may trigger security controls
  DESTRUCTIVE — blocked by default, requires explicit per-action human approval
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
    """Deterministic risk approval for every action."""

    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        target_cfg = cfg.get("target", {})
        detectability = cfg.get("detectability", {})

        self.allow_high = detectability.get("allow_high", False)
        self.target_mode = target_cfg.get("mode", "passive")
        self.authorization = target_cfg.get("authorization", "pending")

        # Explicit tier grant (e.g. from an ROE file) is authoritative when
        # present. Otherwise fall back to the legacy allow_high binary.
        explicit = target_cfg.get("allowed_risk_tiers")
        if explicit:
            self.allowed_tiers: set[RiskTier] = {
                RiskTier(str(t).upper()) for t in explicit
                if RiskTier(str(t).upper()) != RiskTier.DESTRUCTIVE
            }
        else:
            self.allowed_tiers: set[RiskTier] = {RiskTier.SAFE, RiskTier.LOW}
            if self.allow_high:
                self.allowed_tiers.add(RiskTier.MEDIUM)
                self.allowed_tiers.add(RiskTier.HIGH)

        # SAFE actions are never blocked by tier policy.
        self.allowed_tiers.add(RiskTier.SAFE)

    def approve(self, tier: RiskTier, action_id: str = "",
                target: str = "") -> RiskDecision:
        if self.authorization not in ("confirmed", "active"):
            return RiskDecision(False, tier, "no authorization confirmed")

        if tier == RiskTier.SAFE:
            return RiskDecision(True, tier, "SAFE actions always allowed")

        if tier == RiskTier.LOW:
            if tier not in self.allowed_tiers:
                return RiskDecision(False, tier, "LOW actions not authorized")
            if self.target_mode == "passive":
                return RiskDecision(False, tier,
                                    "LOW actions not allowed in passive mode")
            return RiskDecision(True, tier, "LOW actions allowed")

        if tier in (RiskTier.MEDIUM, RiskTier.HIGH):
            if tier not in self.allowed_tiers:
                label = "MEDIUM" if tier == RiskTier.MEDIUM else "HIGH"
                return RiskDecision(False, tier,
                                    f"{label} actions require authorization (ROE opt-in)")
            return RiskDecision(True, tier, f"{tier.value} actions allowed",
                                requires_approval=(tier == RiskTier.HIGH))

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
