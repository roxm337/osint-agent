"""Tests for core policy and scoring helpers."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.scope import ScopeGuard
from core.keyvault import KeyVault
from core.prioritization import prioritize_findings
from core.scoring import score_finding, score_label
from core.verification_oracle import InteractshClient, configure_oob


class TestScopeGuard:
    def test_default_scope_allows_target_and_subdomains(self):
        guard = ScopeGuard("example.com", {"target": {"scope": []}})

        assert guard.check("example.com").allowed is True
        assert guard.check("https://www.example.com/login").allowed is True
        assert guard.check("other.com").allowed is False

    def test_deny_scope_wins(self):
        guard = ScopeGuard(
            "example.com",
            {"target": {"scope": ["example.com", "*.example.com"],
                        "deny": ["admin.example.com"]}},
        )

        assert guard.check("admin.example.com").allowed is False
        assert guard.check("www.example.com").allowed is True

    def test_cidr_scope(self):
        guard = ScopeGuard(
            "example.com",
            {"target": {"scope": ["192.0.2.0/24"]}},
        )

        assert guard.check("192.0.2.10").allowed is True
        assert guard.check("198.51.100.10").allowed is False


def test_score_finding_is_stable_and_labeled():
    score = score_finding(
        "HIGH",
        "CONFIRMED",
        asset_keys=["webapp:https://example.com"],
        category="Network Exposure",
    )

    assert score >= 80
    assert score_label(score) == "High"


def test_keyvault_prefers_config_and_masks_values(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "env-value-123456")
    vault = KeyVault({"api_keys": {"virustotal": "config-value-abcdef"}})

    assert vault.get("virustotal") == "config-value-abcdef"
    assert vault.has("virustotal") is True
    assert vault.mask(vault.get("virustotal")) == "conf...cdef"


def test_prioritize_findings_adds_priority_metadata():
    findings = [
        {
            "id": "FINDING-0001",
            "title": "Known Exploited CVE",
            "severity": "LOW",
            "confidence": "FIRM",
            "category": "Exploit Intelligence",
            "asset_keys": ["webapp:https://example.com"],
            "intelligence": {"cvss": 9.8, "epss": 0.8, "kev": True},
        }
    ]

    prioritized = prioritize_findings(findings)

    assert prioritized[0]["risk_score"] >= 90
    assert prioritized[0]["priority"] == "P0"
    assert prioritized[0]["severity"] == "CRITICAL"


def test_interactsh_callback_url_uses_configured_domain():
    configure_oob({"oob": {"callback_domain": "oob.example.test"}})
    client = InteractshClient()

    assert client.callback_url("abc123", "/test") == "http://abc123.oob.example.test/test"

    configure_oob({})
