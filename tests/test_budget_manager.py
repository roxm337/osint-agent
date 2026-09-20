"""Tests for budget manager."""

import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.budget_manager import BudgetManager, BudgetExceededError
import pytest


def test_budget_starts_ok():
    budget = BudgetManager({})
    assert budget.check() is True


def test_request_counting():
    budget = BudgetManager({})
    budget.record_request(5)
    assert budget.state.requests_used == 5


def test_llm_call_counting():
    budget = BudgetManager({})
    budget.record_llm_call()
    budget.record_llm_call()
    assert budget.state.llm_calls_used == 2


def test_action_counting():
    budget = BudgetManager({})
    budget.record_action()
    assert budget.state.actions_used == 1


def test_custom_limits():
    budget = BudgetManager({"budget_limits": {"max_requests": 10}})
    for _ in range(10):
        budget.record_request()
    with pytest.raises(BudgetExceededError):
        budget.record_request()
        budget.check()


def test_summary_shape():
    budget = BudgetManager({})
    budget.record_request(3)
    s = budget.summary()
    assert "requests" in s
    assert "wall_clock" in s
    assert "errored" in s
    assert not s["errored"]


def test_custom_limits_from_config():
    budget = BudgetManager({
        "budget_limits": {
            "max_requests": 100,
            "max_wall_clock_seconds": 600,
            "max_llm_calls": 10,
        }
    })
    assert budget.max_requests == 100
    assert budget.max_wall_clock == 600
    assert budget.max_llm_calls == 10
