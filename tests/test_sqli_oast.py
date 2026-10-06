"""Tests for the out-of-band wiring in modules/sqli_scan.py.

A blind injection produces the same bytes over HTTP whether or not the query
ran, so the only way to move a SQLi finding off FIRM is a callback from the
database. That makes the gate worth pinning down: turning OAST on when nothing
is listening costs requests against the target and still proves nothing, and
promoting a finding that never got a callback is a false report.
"""

import asyncio
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import BaseModule
from modules.sqli_scan import SQLiScan
from state.manager import StateManager


def _module(oob=None, module_cfg=None, parameters=()):
    config = {
        "target": {"domain": "example.test", "base_url": "https://example.test"},
        "paths": {"output_dir": tempfile.mkdtemp()},
        "modules": dict(module_cfg or {}),
    }
    if oob is not None:
        config["oob"] = oob
    state = StateManager(config["paths"]["output_dir"])
    for url, param in parameters:
        state.add_asset("parameter", f"url:{url}?{param}", param,
                        attrs={"url": url})
    return SQLiScan(state, config), state


def _stub_sqlmap(monkeypatch, results_by_url):
    """Replace the sqlmap call with canned output keyed by target URL."""
    seen = {}

    async def fake_sqlmap_scan(url, timeout=900, interactsh_url="",
                               risk=1, level=1, cookie="", headers=""):
        seen[url] = (interactsh_url, risk, level)
        payload = results_by_url.get(url, {})
        return {
            "available": True,
            "results": payload.get("results", []),
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "oast": payload.get("oast", False),
        }

    monkeypatch.setattr("modules.sqli_scan.sqlmap_scan", fake_sqlmap_scan)
    monkeypatch.setattr("modules.sqli_scan.tool_available", lambda name: True)
    return seen


# ── The gate ──────────────────────────────────────────────────────


def test_no_oob_config_means_no_callback_client():
    """Injecting a *.oob.invalid host would cost a request and prove nothing."""
    module, _ = _module()
    assert module.oob() is None
    assert module._interactsh_url() == ""


def test_a_callback_domain_alone_cannot_drive_sqlmap():
    """sqlmap needs an interactsh *server* to poll, not just somewhere to point
    a hostname. A bare callback domain must not be handed to --interactsh-url."""
    module, _ = _module(oob={"callback_domain": "oob.example.test"})
    assert module.oob() is not None
    assert module._interactsh_url() == ""


def test_a_configured_server_is_handed_to_sqlmap():
    module, _ = _module(oob={"server_url": "https://interactsh.example.test/"})
    assert module._interactsh_url() == "https://interactsh.example.test"


def test_oast_can_be_turned_off_for_this_module_alone():
    module, _ = _module(
        oob={"server_url": "https://interactsh.example.test"},
        module_cfg={"sqli_scan": {"oast": False}},
    )
    assert module._interactsh_url() == ""


# ── Attribution ───────────────────────────────────────────────────


def test_only_the_finding_from_the_confirmed_url_is_promoted(monkeypatch):
    """Two URLs are scanned. One gets a callback. The other stayed in-band, and
    its response was identical with and without the payload, so promoting it
    too would report proof that does not exist."""
    seen = _stub_sqlmap(monkeypatch, {
        "https://example.test/api/a?id=1": {
            "oast": True,
            "results": [{"url": "https://example.test/api/a?id=1",
                         "evidence": "GET parameter 'id' is vulnerable"}],
        },
        "https://example.test/api/b?id=1": {
            "oast": False,
            "results": [{"url": "https://example.test/api/b?id=1",
                         "evidence": "GET parameter 'id' is vulnerable"}],
        },
    })
    module, state = _module(
        oob={"server_url": "https://interactsh.example.test"},
        parameters=[("https://example.test/api/a", "id"),
                    ("https://example.test/api/b", "id")],
    )
    assert asyncio.run(module.run()) == "done"

    by_url = {f["asset_keys"][0]: f for f in state.findings["findings"]}
    assert by_url["url:https://example.test/api/a?id=1"]["confidence"] == "CONFIRMED"
    assert by_url["url:https://example.test/api/b?id=1"]["confidence"] == "FIRM"
    # The server is passed to every scan, and OAST is per-request, not per-run.
    assert {v[0] for v in seen.values()} == {"https://interactsh.example.test"}
    # Level 1 found candidate evidence in-band on /b, so only /b escalates.
    assert seen["https://example.test/api/a?id=1"][1:] == (1, 1)
    assert seen["https://example.test/api/b?id=1"][1:] == (3, 3)


def test_a_confirmed_finding_says_why(monkeypatch):
    _stub_sqlmap(monkeypatch, {
        "https://example.test/api/a?id=1": {
            "oast": True,
            "results": [{"url": "https://example.test/api/a?id=1",
                         "evidence": "GET parameter 'id' is vulnerable"}],
        },
    })
    module, state = _module(
        oob={"server_url": "https://interactsh.example.test"},
        parameters=[("https://example.test/api/a", "id")],
    )
    asyncio.run(module.run())
    finding = state.findings["findings"][0]

    assert "out of band" in finding["description"]
    assert "executed" in finding["description"]


def test_an_inband_finding_admits_it_is_not_proof(monkeypatch):
    _stub_sqlmap(monkeypatch, {
        "https://example.test/api/a?id=1": {
            "oast": False,
            "results": [{"url": "https://example.test/api/a?id=1",
                         "evidence": "GET parameter 'id' is vulnerable"}],
        },
    })
    module, state = _module(
        parameters=[("https://example.test/api/a", "id")],
    )
    asyncio.run(module.run())
    finding = state.findings["findings"][0]

    assert finding["confidence"] == "FIRM"
    assert "not proof of execution" in finding["description"]


def test_a_finding_with_no_url_is_never_promoted(monkeypatch):
    """sqlmap output that never printed a connection line has no URL, so the
    per-request OAST flag cannot be attributed to it. Default to FIRM."""
    _stub_sqlmap(monkeypatch, {
        "https://example.test/api/a?id=1": {
            "oast": True,
            "results": [{"url": "",
                         "evidence": "GET parameter 'id' is vulnerable"}],
        },
    })
    module, state = _module(
        oob={"server_url": "https://interactsh.example.test"},
        parameters=[("https://example.test/api/a", "id")],
    )
    asyncio.run(module.run())

    assert state.findings["findings"][0]["confidence"] == "FIRM"


def test_evidence_records_the_oast_decision(monkeypatch):
    _stub_sqlmap(monkeypatch, {
        "https://example.test/api/a?id=1": {
            "oast": True,
            "results": [{"url": "https://example.test/api/a?id=1",
                         "evidence": "GET parameter 'id' is vulnerable"}],
        },
    })
    module, state = _module(
        oob={"server_url": "https://interactsh.example.test"},
        parameters=[("https://example.test/api/a", "id")],
    )
    asyncio.run(module.run())

    import json
    item = state.evidence["items"][0]
    assert item["subject"] == "https://example.test/api/a?id=1"
    payload = json.loads(
        (state.output_dir / item["path"]).read_text()
    )["data"]
    assert payload["oast"] is True
    assert payload["interactsh_url"] == "https://interactsh.example.test"


def test_missing_sqlmap_still_skips(monkeypatch):
    """OAST config must not resurrect a module whose tool is missing: the
    native path is sqlmap's own OAST mode, not a second scanner."""
    monkeypatch.setattr("modules.sqli_scan.tool_available", lambda name: False)
    module, state = _module(oob={"server_url": "https://interactsh.example.test"})

    assert asyncio.run(module.run()) == "skipped"
    assert state.findings["findings"] == []


def test_a_malformed_module_config_does_not_break_the_gate():
    module, _ = _module(module_cfg={"sqli_scan": "not-a-dict"})
    assert module._cfg() == {}
    assert module._interactsh_url() == ""


def test_base_module_oob_returns_none_for_a_disabled_section():
    module, _ = _module()
    module.config["oob"] = {"callback_domain": "oob.example.test", "enabled": False}
    assert module.oob() is None


@pytest.mark.parametrize("cfg,expect_client", [
    ({"callback_domain": "oob.example.test", "enabled": False}, False),
    ({"server_url": "https://interactsh.example.test"}, True),
    ({"poll_url": "https://collaborator.example/api"}, True),
    ({"token": "secret"}, False),
])
def test_base_module_oob_gate(cfg, expect_client):
    module, _ = _module()
    module.config["oob"] = cfg
    assert (module.oob() is not None) is expect_client
    assert isinstance(module, BaseModule)
