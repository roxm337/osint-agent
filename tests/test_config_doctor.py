"""Tests for core/config_doctor.py and the --check-config flag.

A stale config never crashes — every key has a code default — so without
this the operator runs Tier-2 tools on defaults they cannot see. The
doctor lists what the file does not say; --check-config prints coverage
without running anything.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config_doctor import KNOWN_KEYS, coverage, doctor


def test_empty_config_warns_on_every_known_key():
    warnings = doctor({})

    assert len(warnings) == len(KNOWN_KEYS)
    assert any(w.startswith("tools.backend") for w in warnings)
    assert any("kiterunner" in w for w in warnings)


def test_covered_keys_stay_silent():
    config = {
        "tools": {"backend": "docker", "image": "mine:latest"},
        "semgrep": {"enabled": False, "rules": "r"},
        "modules": {
            "content_discovery": {"kiterunner": {
                "enabled": True, "wordlist": "w", "max_routes": 5,
                "max_targets": 1}},
            "sqli_scan": {"oast": True},
            "ssrf_scan": {"enabled": True, "max_points": 6},
        },
        "xss": {"dalfox_blind_oob": False, "dalfox_rate_limit": 0},
        "oob": {"mode": "public", "enabled": True},
        "crawl": {"browser": {"enabled": True, "depth": 1,
                              "max_identities": 2}},
    }

    assert doctor(config) == []


def test_partial_config_warns_only_on_gaps():
    warnings = doctor({"tools": {"backend": "docker"}})

    assert not any(w.startswith("tools.backend") for w in warnings)
    assert any(w.startswith("tools.image") for w in warnings)


def test_non_dict_hops_count_as_absent():
    assert any(w.startswith("modules.content_discovery.kiterunner.enabled")
               for w in doctor({"modules": {"content_discovery": None}}))


def test_coverage_reports_effective_values():
    rows = {dotted: (present, value)
            for dotted, present, value, _why in coverage({"tools": {}})}

    assert rows["tools.backend"] == (False, "local")
    assert rows["semgrep.enabled"] == (False, True)


def test_check_config_runs_nothing(monkeypatch, capsys):
    """--check-config prints coverage and returns before any module runs."""
    import asyncio
    import orchestrator
    from orchestrator import Orchestrator
    from unittest.mock import AsyncMock, patch

    argv = ["orchestrator.py", "-t", "example.com", "-o", "/tmp/x",
            "--check-config"]
    monkeypatch.setattr(sys, "argv", argv)
    with patch.object(Orchestrator, "run_all", new=AsyncMock()) as run_all, \
         patch.object(Orchestrator, "run_module", new=AsyncMock()) as run_mod:
        asyncio.run(orchestrator.main())

    run_all.assert_not_called()
    run_mod.assert_not_called()
    out = capsys.readouterr().out
    assert "Config coverage" in out
    assert "tools.backend" in out
