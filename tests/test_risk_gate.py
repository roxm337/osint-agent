"""Tests for risk gate — permissive default and opt-in enforcement."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.risk_gate import RiskGate, RiskTier
import pytest


class TestPermissiveDefault:
    """Default (risk_gate.enforce unset / false): every tier passes."""

    def test_safe_allowed_by_default(self):
        gate = RiskGate({})
        assert gate.approve(RiskTier.SAFE).allowed is True

    def test_all_tiers_allowed_by_default(self):
        gate = RiskGate({})
        for tier in RiskTier:
            assert gate.approve(tier).allowed is True

    def test_require_does_not_raise_by_default(self):
        gate = RiskGate({})
        # Must not raise — destructive action approved by default.
        gate.require(RiskTier.DESTRUCTIVE)

    def test_pending_authorization_does_not_block_by_default(self):
        gate = RiskGate(
            {"target": {"authorization": "pending", "mode": "passive"}}
        )
        for tier in RiskTier:
            assert gate.approve(tier).allowed is True

    def test_reason_marks_gate_disabled(self):
        gate = RiskGate({})
        decision = gate.approve(RiskTier.HIGH)
        assert "disabled" in decision.reason.lower()


class TestEnforcementMode:
    """With risk_gate.enforce = true, the deterministic tier logic applies."""

    def test_safe_always_allowed(self):
        gate = RiskGate({
            "risk_gate": {"enforce": True},
            "target": {"authorization": "confirmed", "mode": "passive"},
        })
        assert gate.approve(RiskTier.SAFE).allowed is True

    def test_low_blocked_in_passive(self):
        gate = RiskGate({
            "risk_gate": {"enforce": True},
            "target": {"authorization": "confirmed", "mode": "passive"},
        })
        assert gate.approve(RiskTier.LOW).allowed is False

    def test_low_allowed_in_active(self):
        gate = RiskGate({
            "risk_gate": {"enforce": True},
            "target": {"authorization": "confirmed", "mode": "active"},
        })
        assert gate.approve(RiskTier.LOW).allowed is True

    def test_medium_requires_allow_high(self):
        gate = RiskGate({
            "risk_gate": {"enforce": True},
            "target": {"authorization": "confirmed", "mode": "active"},
            "detectability": {"allow_high": False},
        })
        assert gate.approve(RiskTier.MEDIUM).allowed is False

    def test_medium_allowed_with_allow_high(self):
        gate = RiskGate({
            "risk_gate": {"enforce": True},
            "target": {"authorization": "confirmed", "mode": "active"},
            "detectability": {"allow_high": True},
        })
        assert gate.approve(RiskTier.MEDIUM).allowed is True

    def test_high_requires_approval(self):
        gate = RiskGate({
            "risk_gate": {"enforce": True},
            "target": {"authorization": "confirmed", "mode": "active"},
            "detectability": {"allow_high": True},
        })
        decision = gate.approve(RiskTier.HIGH)
        assert decision.allowed is True
        assert decision.requires_approval is True

    def test_high_blocked_without_allow_high(self):
        gate = RiskGate({
            "risk_gate": {"enforce": True},
            "target": {"authorization": "confirmed", "mode": "active"},
            "detectability": {"allow_high": False},
        })
        assert gate.approve(RiskTier.HIGH).allowed is False

    def test_destructive_blocked(self):
        gate = RiskGate({
            "risk_gate": {"enforce": True},
            "target": {"authorization": "confirmed", "mode": "active"},
        })
        decision = gate.approve(RiskTier.DESTRUCTIVE)
        assert decision.allowed is False
        assert decision.requires_approval is True

    def test_no_auth_blocks_everything(self):
        gate = RiskGate({
            "risk_gate": {"enforce": True},
            "target": {"authorization": "pending", "mode": "passive"},
        })
        for tier in RiskTier:
            decision = gate.approve(tier)
            assert decision.allowed is False

    def test_require_raises_on_blocked(self):
        gate = RiskGate({
            "risk_gate": {"enforce": True},
            "target": {"authorization": "confirmed", "mode": "passive"},
        })
        with pytest.raises(PermissionError):
            gate.require(RiskTier.LOW)
