"""Tests for risk gate."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.risk_gate import RiskGate, RiskTier
import pytest


def test_safe_always_allowed():
    gate = RiskGate({"target": {"authorization": "confirmed", "mode": "passive"}})
    decision = gate.approve(RiskTier.SAFE)
    assert decision.allowed is True


def test_low_blocked_in_passive():
    gate = RiskGate({"target": {"authorization": "confirmed", "mode": "passive"}})
    decision = gate.approve(RiskTier.LOW)
    assert decision.allowed is False


def test_low_allowed_in_active():
    gate = RiskGate({"target": {"authorization": "confirmed", "mode": "active"}})
    decision = gate.approve(RiskTier.LOW)
    assert decision.allowed is True


def test_medium_requires_allow_high():
    gate = RiskGate({
        "target": {"authorization": "confirmed", "mode": "active"},
        "detectability": {"allow_high": False},
    })
    decision = gate.approve(RiskTier.MEDIUM)
    assert decision.allowed is False


def test_medium_allowed_with_allow_high():
    gate = RiskGate({
        "target": {"authorization": "confirmed", "mode": "active"},
        "detectability": {"allow_high": True},
    })
    decision = gate.approve(RiskTier.MEDIUM)
    assert decision.allowed is True


def test_high_requires_approval():
    gate = RiskGate({
        "target": {"authorization": "confirmed", "mode": "active"},
        "detectability": {"allow_high": True},
    })
    decision = gate.approve(RiskTier.HIGH)
    assert decision.allowed is True
    assert decision.requires_approval is True


def test_destructive_blocked():
    gate = RiskGate({"target": {"authorization": "confirmed", "mode": "active"}})
    decision = gate.approve(RiskTier.DESTRUCTIVE)
    assert decision.allowed is False
    assert decision.requires_approval is True


def test_no_auth_blocks_everything():
    gate = RiskGate({"target": {"authorization": "pending", "mode": "passive"}})
    for tier in RiskTier:
        decision = gate.approve(tier)
        assert decision.allowed is False


def test_require_raises_on_blocked():
    gate = RiskGate({"target": {"authorization": "confirmed", "mode": "passive"}})
    with pytest.raises(PermissionError):
        gate.require(RiskTier.LOW)
