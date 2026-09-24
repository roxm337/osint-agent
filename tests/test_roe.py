"""Tests for Rules of Engagement (ROE) parsing, validation, and config enforcement."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from core.roe import ROEError, load_roe, parse_roe
from core.scope import ScopeGuard

import yaml


def _minimal():
    return {
        "engagement_id": "ENG-TEST-1",
        "authorization": {"operator": "Tester", "contact": "a@b.c"},
        "scope": {"allow": ["example.com", "*.example.com"]},
        "allowed_risk_tiers": ["SAFE", "LOW", "MEDIUM"],
    }


def test_parse_roe_happy_path():
    roe = parse_roe(_minimal(), _minimal())
    assert roe.engagement_id == "ENG-TEST-1"
    assert roe.scope == ["example.com", "*.example.com"]
    assert roe.tiers == ["SAFE", "LOW", "MEDIUM"]
    assert roe.validate() is roe


def test_load_roe_from_file(tmp_path):
    path = tmp_path / "roe.yaml"
    path.write_text(yaml.safe_dump(_minimal()))
    roe = load_roe(path)
    assert roe.engagement_id == "ENG-TEST-1"


def test_load_roe_missing_file():
    with pytest.raises(ROEError):
        load_roe("/nonexistent/roe.yaml")


def test_roe_requires_engagement_id():
    data = _minimal()
    data.pop("engagement_id")
    with pytest.raises(ROEError):
        parse_roe(data, data)


def test_roe_requires_scope():
    data = _minimal()
    data["scope"] = {"allow": []}
    with pytest.raises(ROEError):
        parse_roe(data, data)


def test_roe_rejects_invalid_tier():
    data = _minimal()
    data["allowed_risk_tiers"] = ["SAFE", "BOGUS"]
    with pytest.raises(ROEError):
        parse_roe(data, data)


def test_roe_rejects_destructive_grant():
    data = _minimal()
    data["allowed_risk_tiers"] = ["DESTRUCTIVE"]
    with pytest.raises(ROEError):
        parse_roe(data, data)


def test_roe_rejects_expired_window():
    data = _minimal()
    data["authorization"]["window"] = {
        "start": "2020-01-01T00:00:00Z",
        "end": "2021-01-01T00:00:00Z",
    }
    with pytest.raises(ROEError):
        parse_roe(data, data)


def test_roe_rejects_inverted_window():
    data = _minimal()
    data["authorization"]["window"] = {
        "start": "2030-01-01T00:00:00Z",
        "end": "2029-01-01T00:00:00Z",
    }
    with pytest.raises(ROEError):
        parse_roe(data, data)


def test_roe_enforce_caps_scope_and_sets_authorization():
    roe = parse_roe(_minimal(), _minimal())
    config = {
        "target": {
            "domain": "example.com",
            "scope": ["example.com", "*.example.com", "evil.com"],
            "authorization": "pending",
        },
    }
    enforced = roe.enforce(config)

    assert enforced["target"]["authorization"] == "confirmed"
    assert "evil.com" not in enforced["target"]["scope"]
    assert enforced["target"]["allowed_risk_tiers"] == ["SAFE", "LOW", "MEDIUM"]


def test_roe_effective_scope_allows_only_roe_targets():
    roe = parse_roe(_minimal(), _minimal())
    config = {"target": {"domain": "example.com", "scope": []}}
    enforced = roe.enforce(config)
    guard = ScopeGuard("example.com", enforced)

    assert guard.check("example.com").allowed
    assert guard.check("www.example.com").allowed
    assert not guard.check("evil.com").allowed


def test_roe_exclusions_win():
    data = _minimal()
    data["scope"]["exclude"] = ["prod.example.com"]
    roe = parse_roe(data, data)
    enforced = roe.enforce({"target": {"domain": "example.com", "scope": []}})
    guard = ScopeGuard("example.com", enforced)

    assert guard.check("www.example.com").allowed
    assert not guard.check("prod.example.com").allowed


def test_roe_enforce_merges_limit_overrides():
    roe = parse_roe(_minimal(), _minimal())
    data = dict(_minimal())
    data["limits"] = {"max_requests": 50}
    roe = parse_roe(data, data)
    enforced = roe.enforce({"budget_limits": {"max_requests": 5000}})
    assert enforced["budget_limits"]["max_requests"] == 50