"""Tests for main()'s CLI dispatch.

These exist because `--module <id>` was silently ignored: a wiring edit deleted
the `elif args.module:` branch, so the line after it was re-attached to the
`if args.pentest:` block and every `--module` run fell through to `run_all()`.
The whole 440-test suite stayed green, because the previous CLI test asserted
that the flag *strings* appeared in main()'s source. Grepping for a flag name
says nothing about which branch runs.

So these tests drive main() with real argv and assert on what was actually
called. Source inspection is not a substitute for behaviour.
"""

import sys
from unittest.mock import AsyncMock, patch

import pytest


def _argv(*extra):
    return ["orchestrator.py", "-t", "localhost:3000", "-o", "/tmp/x", *extra]


@pytest.fixture
def dispatched(monkeypatch):
    """Patch Orchestrator so main() runs without touching the network."""
    from orchestrator import Orchestrator

    calls = []

    async def _run_module(self, module_id):
        calls.append(("module", module_id))

    async def _run_all(self):
        calls.append(("all", None))

    async def _run_pentest(self):
        calls.append(("pentest", None))

    async def _run_llm(self):
        calls.append(("llm", None))

    monkeypatch.setattr(Orchestrator, "run_module", _run_module)
    monkeypatch.setattr(Orchestrator, "run_all", _run_all)
    monkeypatch.setattr(Orchestrator, "run_pentest", _run_pentest)
    monkeypatch.setattr(Orchestrator, "run_llm", _run_llm)
    return calls


def _run(monkeypatch, argv):
    import orchestrator
    monkeypatch.setattr(sys, "argv", argv)
    return orchestrator.main()


def test_module_flag_runs_only_that_module(dispatched, monkeypatch):
    """The regression: --module must not fall through to the full pipeline."""
    import asyncio
    asyncio.run(_run(monkeypatch, _argv("--module", "tech_detection")))
    assert dispatched == [("module", "tech_detection")], \
        "--module must run exactly that module, not run_all()"


def test_no_flags_runs_the_full_pipeline(dispatched, monkeypatch):
    import asyncio
    asyncio.run(_run(monkeypatch, _argv()))
    assert dispatched == [("all", None)]


def test_pentest_runs_pentest_only_in_auto_mode(dispatched, monkeypatch):
    import asyncio
    asyncio.run(_run(monkeypatch, _argv("--pentest")))
    assert dispatched == [("pentest", None)], \
        "--pentest in auto mode should not re-run the whole pipeline"


def test_pentest_with_module_runs_module_then_pentest(dispatched, monkeypatch):
    import asyncio
    asyncio.run(_run(monkeypatch, _argv("--pentest", "--module", "js_analysis")))
    assert dispatched == [("module", "js_analysis"), ("pentest", None)]


def test_active_pentest_runs_all_then_pentest(dispatched, monkeypatch):
    import asyncio
    asyncio.run(_run(monkeypatch, _argv("--active", "--pentest")))
    assert dispatched == [("all", None), ("pentest", None)]


def test_pentest_never_calls_run_module_with_none(dispatched, monkeypatch):
    """--pentest used to call run_module(None) unconditionally."""
    import asyncio
    asyncio.run(_run(monkeypatch, _argv("--pentest")))
    module_calls = [value for kind, value in dispatched if kind == "module"]
    assert all(v is not None for v in module_calls), \
        "run_module must never be called with None"
    assert not module_calls, "--pentest alone should not call run_module at all"


def test_llm_mode_runs_llm(dispatched, monkeypatch):
    import asyncio
    asyncio.run(_run(monkeypatch, _argv("--mode", "llm")))
    assert dispatched == [("llm", None)]
