"""Tests for core/chain_executor.py.

The gap this fills: `run_pentest()` built an attack graph, found chains, printed
them, and returned. Fifteen actions were registered and never invoked. So the
tool's findings were all claims, because nothing went and checked.

What these tests pin is the property that makes it safe to wire up: an action
above the operator's risk ceiling must not run, must be reported as blocked
rather than silently dropped, and must not produce a finding. A chain executor
that fires payloads is exactly the kind of thing that should be paranoid about
its own blast radius.

The proving side is tested with a registered fake action rather than a real
target — no fixture here, because the contract under test is "does a
successful result become a verified finding with real evidence", not whether
SQL injection works.
"""

import tempfile
from dataclasses import dataclass
from unittest.mock import patch

import pytest

from actions.registry import ActionMeta, ActionRegistry, RiskLevel
from core.attack_graph import AttackEdge, AttackNode
from core.chain_executor import ChainExecutor, risk_allows
from state.manager import StateManager


@dataclass
class FakeChain:
    """Minimal stand-in for an attack-graph chain."""
    nodes: dict
    edges: list
    score: float = 0.9

    @property
    def summary(self):
        return "fake chain"


def _node(node_id, node_type="url", **attrs):
    return AttackNode(id=node_id, label=node_id, node_type=node_type,
                      confidence="FIRM", attrs=attrs)


def _chain(action_id=None, edge_type="exploit", url="https://example.test/s?q=1",
           vuln_category=None):
    nodes = {"n1": _node("n1", "url", url=url)}
    if vuln_category:
        nodes["n2"] = _node("n2", "vuln", category=vuln_category)
        target = "n2"
    else:
        nodes["n2"] = _node("n2", "goal")
        target = "n2"
    edge = AttackEdge(source_id="n1", target_id=target, edge_type=edge_type,
                      likelihood=0.5, impact=0.8, action_id=action_id or "")
    return FakeChain(nodes, [edge])


def _register(action_id, risk, success=True, confidence="CONFIRMED",
              evidence=None, error="", raises=False, requires=("url",)):
    """Register a fake action and return the call log it appends to."""
    calls = []

    async def fn(ctx):
        calls.append(ctx)
        if raises:
            raise RuntimeError("action blew up")
        from actions.registry import ActionResult
        return ActionResult(
            success=success, confidence=confidence,
            evidence=evidence if evidence is not None else {"impact": "marker"},
            error=error, data={"sampled": "value"} if success else None,
        )

    ActionRegistry.register(
        ActionMeta(id=action_id, risk=risk, detectability="low",
                   description="fake", category="test",
                   requires=list(requires), produces="Finding"),
        fn,
    )
    return calls


@pytest.fixture(autouse=True)
def _clean_registry():
    saved = dict(ActionRegistry._actions)
    yield
    ActionRegistry._actions.clear()
    ActionRegistry._actions.update(saved)


def _state():
    return StateManager(tempfile.mkdtemp())


def _findings(state):
    return state.findings["findings"]


# --- the risk ceiling is the safety property ----------------------------

@pytest.mark.parametrize("action_risk,ceiling,allowed", [
    ("SAFE", "LOW", True),
    ("LOW", "LOW", True),
    ("MEDIUM", "LOW", False),
    ("MEDIUM", "MEDIUM", True),
    ("HIGH", "MEDIUM", False),
    ("HIGH", "HIGH", True),
    ("DESTRUCTIVE", "DESTRUCTIVE", True),
    ("DESTRUCTIVE", "HIGH", False),
    ("garbage", "DESTRUCTIVE", False),
])
def test_risk_allows(action_risk, ceiling, allowed):
    assert risk_allows(action_risk, RiskLevel(ceiling)) is allowed


def test_action_above_ceiling_never_runs():
    calls = _register("test.medium_probe", "MEDIUM")
    state = _state()
    ex = ChainExecutor(state, {}, max_risk=RiskLevel.LOW)
    report = asyncio_run(ex.execute([_chain(action_id="test.medium_probe")]))

    assert calls == [], "a MEDIUM action ran under a LOW ceiling"
    assert _findings(state) == [], "a blocked action produced a finding"
    assert report.blocked and report.blocked[0].status == "blocked_risk"
    assert "above the LOW ceiling" in report.blocked[0].detail


def test_raising_the_ceiling_lets_it_run():
    calls = _register("test.medium_probe", "MEDIUM")
    state = _state()
    ex = ChainExecutor(state, {}, max_risk=RiskLevel.MEDIUM)
    report = asyncio_run(ex.execute([_chain(action_id="test.medium_probe")]))
    assert calls, "raising the ceiling should let the action run"
    assert report.proven == 1


def test_destructive_never_runs_by_default():
    calls = _register("test.nuke", "DESTRUCTIVE")
    state = _state()
    ex = ChainExecutor(state, {}, max_risk=RiskLevel.LOW)
    asyncio_run(ex.execute([_chain(action_id="test.nuke")]))
    assert calls == []


def test_blocked_actions_are_reported_not_silently_dropped():
    _register("test.medium_probe", "MEDIUM")
    state = _state()
    ex = ChainExecutor(state, {}, max_risk=RiskLevel.SAFE)
    report = asyncio_run(ex.execute([_chain(action_id="test.medium_probe")]))
    assert len(report.blocked) == 1
    assert "MEDIUM" in report.blocked[0].detail


# --- a proven action becomes a verified finding -------------------------

def test_successful_action_becomes_verified_finding():
    _register("test.probe", "LOW", confidence="CONFIRMED",
              evidence={"impact": "admin token returned"})
    state = _state()
    ex = ChainExecutor(state, {})
    report = asyncio_run(ex.execute([_chain(action_id="test.probe")]))

    assert report.proven == 1
    findings = _findings(state)
    assert len(findings) == 1
    f = findings[0]
    assert f["verified"] is True
    assert f["confidence"] == "CONFIRMED"
    assert "was run, not inferred" in f["description"]
    assert any("admin token returned" in line for line in f["evidence"])


def test_unconfirmed_action_produces_no_finding():
    _register("test.probe", "LOW", success=False, error="no differential")
    state = _state()
    ex = ChainExecutor(state, {})
    report = asyncio_run(ex.execute([_chain(action_id="test.probe")]))
    assert report.proven == 0
    assert _findings(state) == []


def test_action_error_is_recorded_not_crashed():
    _register("test.probe", "LOW", raises=True)
    state = _state()
    ex = ChainExecutor(state, {})
    report = asyncio_run(ex.execute([_chain(action_id="test.probe")]))
    assert report.proven == 0
    # The registry traps the exception and hands it back as a failed result, so
    # the operator sees why the action did not run instead of a traceback.
    assert "action blew up" in report.skipped[0].detail
    assert _findings(state) == []


def test_severity_boosts_on_real_impact_words():
    _register("test.probe", "LOW", evidence={"impact": "root access obtained"})
    state = _state()
    ex = ChainExecutor(state, {})
    asyncio_run(ex.execute([_chain(action_id="test.probe")]))
    assert _findings(state)[0]["severity"] == "HIGH"


def test_severity_stays_modest_without_impact_words():
    _register("test.probe", "LOW", evidence={"note": "something happened"})
    state = _state()
    ex = ChainExecutor(state, {})
    asyncio_run(ex.execute([_chain(action_id="test.probe")]))
    assert _findings(state)[0]["severity"] == "MEDIUM"


# --- planning: which action proves which edge ---------------------------

def test_vuln_category_selects_the_matching_action():
    # web.sqli.detect is genuinely registered by the action library, so plan()
    # picks it up as-is. No need to fake one, and nothing executes here.
    assert ActionRegistry.get("web.sqli.detect")
    ex = ChainExecutor(_state(), {})
    planned = ex.plan(_chain(vuln_category="SQL Injection"))
    assert [p.action_id for p in planned] == ["web.sqli.detect"]
    assert "category" in planned[0].reason


def test_declared_action_wins_over_category():
    _register("test.declared", "LOW")
    ex = ChainExecutor(_state(), {})
    planned = ex.plan(_chain(action_id="test.declared",
                             vuln_category="SQL Injection"))
    assert [p.action_id for p in planned] == ["test.declared"]
    assert planned[0].reason == "declared on edge"


def test_edge_without_a_provable_action_is_skipped():
    ex = ChainExecutor(_state(), {})
    assert ex.plan(_chain(edge_type="affected_by")) == []


def test_edge_without_a_url_is_skipped():
    _register("test.probe", "LOW")
    chain = FakeChain(
        nodes={"n1": _node("n1", "url"), "n2": _node("n2", "goal")},
        edges=[AttackEdge(source_id="n1", target_id="n2", edge_type="exploit",
                          likelihood=0.5, impact=0.8, action_id="test.probe")],
    )
    ex = ChainExecutor(_state(), {})
    assert ex.plan(chain) == []


# --- budgets ------------------------------------------------------------

class _Budget:
    def __init__(self, ok=True):
        self.ok = ok
        self.actions = 0
    def check(self):
        return self.ok
    def record_action(self):
        self.actions += 1


def test_budget_exhaustion_stops_execution():
    calls = _register("test.probe", "LOW")
    state = _state()
    budget = _Budget(ok=False)
    ex = ChainExecutor(state, {}, budget=budget)
    report = asyncio_run(ex.execute([_chain(action_id="test.probe")]))
    assert calls == []
    assert report.skipped[0].detail == "budget exhausted"


def test_action_cap_is_enforced():
    _register("test.probe", "LOW")
    state = _state()
    budget = _Budget()
    ex = ChainExecutor(state, {}, budget=budget, max_actions=0)
    report = asyncio_run(ex.execute([_chain(action_id="test.probe")]))
    assert report.proven == 0
    assert "budget exhausted" in report.skipped[0].detail
    assert budget.actions == 0


def test_record_action_is_called():
    _register("test.probe", "LOW")
    budget = _Budget()
    ex = ChainExecutor(_state(), {}, budget=budget)
    asyncio_run(ex.execute([_chain(action_id="test.probe")]))
    assert budget.actions == 1


# --- param preflight: never look clean because we were not armed ---------

def test_sqli_action_gets_the_param_name_from_a_parameter_node():
    chain = FakeChain(
        nodes={
            "n1": AttackNode(id="n1", label="id", node_type="parameter",
                             confidence="FIRM", attrs={"url": "https://example.test/s"}),
            "n2": _node("n2", "vuln", category="SQL Injection"),
        },
        edges=[AttackEdge(source_id="n1", target_id="n2", edge_type="exploit",
                          likelihood=0.5, impact=0.9, action_id="web.sqli.detect")],
    )
    ex = ChainExecutor(_state(), {})
    planned = ex.plan(chain)
    assert len(planned) == 1, "a parameter node should arm the SQL action"
    assert planned[0].params["param"] == "id"
    assert planned[0].params["url"] == "https://example.test/s"


def test_action_needing_a_param_is_not_planned_without_one():
    chain = FakeChain(
        nodes={"n1": _node("n1", "url", url="https://example.test/s"),
               "n2": _node("n2", "vuln", category="SQL Injection")},
        edges=[AttackEdge(source_id="n1", target_id="n2", edge_type="exploit",
                          likelihood=0.5, impact=0.9, action_id="web.sqli.detect")],
    )
    ex = ChainExecutor(_state(), {})
    assert ex.plan(chain) == [], "should not plan an action it cannot arm"
    assert ex.unarmable, "the unarmable edge must be reported"
    assert "param" in ex.unarmable[0].detail


def test_unarmable_edge_never_becomes_a_clean_run():
    """A KeyError inside the action would look identical to 'not vulnerable'.
    Preflight is what stops the executor manufacturing a false negative."""
    chain = FakeChain(
        nodes={"n1": _node("n1", "url", url="https://example.test/s"),
               "n2": _node("n2", "vuln", category="SQL Injection")},
        edges=[AttackEdge(source_id="n1", target_id="n2", edge_type="exploit",
                          likelihood=0.5, impact=0.9, action_id="web.sqli.detect")],
    )
    state = _state()
    ex = ChainExecutor(state, {})
    report = asyncio_run(ex.execute([chain]))
    assert report.proven == 0
    assert _findings(state) == []
    assert report.unarmable, "must not look like a clean bill of health"


def test_param_is_read_from_the_url_query_when_there_is_no_parameter_node():
    meta, _ = ActionRegistry.get("web.sqli.detect")
    chain = FakeChain(
        nodes={"n1": _node("n1", "url", url="https://example.test/s?user=bob"),
               "n2": _node("n2", "vuln", category="SQL Injection")},
        edges=[AttackEdge(source_id="n1", target_id="n2", edge_type="exploit",
                          likelihood=0.5, impact=0.9, action_id="web.sqli.detect")],
    )
    ex = ChainExecutor(_state(), {})
    planned = ex.plan(chain)
    assert len(planned) == 1
    assert planned[0].params["param"] == "user"


def test_two_url_oracle_gets_a_derived_baseline():
    chain = FakeChain(
        nodes={"n1": _node("n1", "url", url="https://example.test/s?user=bob"),
               "n2": _node("n2", "goal")},
        edges=[AttackEdge(source_id="n1", target_id="n2", edge_type="extract",
                          likelihood=0.5, impact=0.5, action_id="verify.differential")],
    )
    ex = ChainExecutor(_state(), {})
    planned = ex.plan(chain)
    assert len(planned) == 1
    assert "user=1" in planned[0].params["baseline_url"]
    assert planned[0].params["test_url"] != planned[0].params["baseline_url"]


def test_falls_back_to_an_armable_action_rather_than_giving_up():
    """verify.differential needs two URLs. On a plain URL it cannot be armed, so
    the executor must fall through to verify.reproducible, which only needs one.
    Picking the first action that merely exists leaves the edge unproven."""
    chain = FakeChain(
        nodes={"n1": _node("n1", "url", url="https://example.test/robots.txt"),
               "n2": _node("n2", "goal")},
        edges=[AttackEdge(source_id="n1", target_id="n2", edge_type="extract",
                          likelihood=0.5, impact=0.5, action_id="")],
    )
    ex = ChainExecutor(_state(), {})
    planned = ex.plan(chain)
    assert len(planned) == 1, "should fall back to an action it can arm"
    assert planned[0].action_id == "verify.reproducible"
    assert ex.unarmable == []


def test_missing_url_is_named_in_the_unarmable_reason():
    chain = FakeChain(
        nodes={"n1": _node("n1", "asset", attrs={}), "n2": _node("n2", "goal")},
        edges=[AttackEdge(source_id="n1", target_id="n2", edge_type="extract",
                          likelihood=0.5, impact=0.5, action_id="")],
    )
    ex = ChainExecutor(_state(), {})
    assert ex.plan(chain) == []
    assert ex.unarmable
    assert "url" in ex.unarmable[0].detail, \
        "the operator must be told which input was missing"


def test_token_action_falls_back_when_graph_has_no_token():
    """auth.jwt.none_alg is the stronger proof but needs a token the graph does
    not have. Rather than dropping the edge, fall back to auth.jwt.detect,
    which only needs a URL, so the edge is still examined."""
    chain = FakeChain(
        nodes={"n1": _node("n1", "url", url="https://example.test/"),
               "n2": _node("n2", "goal")},
        edges=[AttackEdge(source_id="n1", target_id="n2", edge_type="authenticate",
                          likelihood=0.5, impact=0.8, action_id="")],
    )
    ex = ChainExecutor(_state(), {})
    planned = ex.plan(chain)
    assert [p.action_id for p in planned] == ["auth.jwt.detect"]
    assert ex.unarmable == []


def test_authenticate_edge_declaring_a_token_action_says_so_when_unarmable():
    chain = FakeChain(
        nodes={"n1": _node("n1", "url", url="https://example.test/"),
               "n2": _node("n2", "goal")},
        edges=[AttackEdge(source_id="n1", target_id="n2", edge_type="authenticate",
                          likelihood=0.5, impact=0.8, action_id="auth.jwt.none_alg")],
    )
    ex = ChainExecutor(_state(), {})
    planned = ex.plan(chain)
    assert planned[0].action_id == "auth.jwt.detect", \
        "the token action cannot run, so the weaker one should"
    assert "auth.jwt.none_alg" not in [p.action_id for p in planned]


def test_token_action_arms_when_the_graph_has_one():
    chain = FakeChain(
        nodes={"n1": AttackNode(id="n1", label="tok", node_type="secret",
                               confidence="FIRM",
                               attrs={"url": "https://example.test/",
                                      "token": "eyJhbGciOiJub25lIn0.e30."}),
               "n2": _node("n2", "goal")},
        edges=[AttackEdge(source_id="n1", target_id="n2", edge_type="authenticate",
                          likelihood=0.5, impact=0.8, action_id="auth.jwt.none_alg")],
    )
    ex = ChainExecutor(_state(), {})
    planned = ex.plan(chain)
    assert len(planned) == 1
    assert planned[0].params["token"].startswith("eyJ")


def test_every_required_param_is_present_for_each_armable_action():
    """Cross-check the whole mapping: anything we do plan must be fully armed."""
    cases = {
        "web.sqli.detect": ("https://example.test/s?user=bob", "SQL Injection"),
        "web.ssrf.oob_detect": ("https://example.test/s?url=x", "SSRF"),
        "verify.reproducible": ("https://example.test/s", "Info Disclosure"),
    }
    for action_id, (url, category) in cases.items():
        chain = FakeChain(
            nodes={"n1": _node("n1", "url", url=url),
                   "n2": _node("n2", "vuln", category=category)},
            edges=[AttackEdge(source_id="n1", target_id="n2",
                              edge_type="exploit", likelihood=0.5, impact=0.8,
                              action_id=action_id)],
        )
        planned = ChainExecutor(_state(), {}).plan(chain)
        assert planned, f"{action_id} should be armable from a plain URL"
        required = ActionRegistry.get(action_id)[0].requires
        for name in required:
            assert planned[0].params.get(name), \
                f"{action_id} planned without required param {name}"


# --- wiring: pentest mode must be off unless asked ----------------------

def test_orchestrator_defaults_to_not_executing(tmp_path):
    from orchestrator import Orchestrator
    o = Orchestrator(target="example.test", output_dir=str(tmp_path),
                     config_path="config.example.yaml", mode="auto")
    assert o.execute_chains is False, "chain execution must be opt-in"
    assert o.max_risk == "LOW", "default ceiling must be the conservative one"
    assert o.max_actions == 25


def test_pentest_without_execute_executes_nothing(tmp_path):
    """The regression this whole module exists for: --pentest alone used to
    print chains and stop. It must still not fire anything by default."""
    from orchestrator import Orchestrator
    o = Orchestrator(target="example.test", output_dir=str(tmp_path),
                     config_path="config.example.yaml", mode="auto")
    with patch("core.chain_executor.ChainExecutor.execute") as mock_exec:
        asyncio_run(o._execute_chains([]))
    mock_exec.assert_not_called()


def test_cli_exposes_execute_flag():
    import inspect
    from orchestrator import main
    src = inspect.getsource(main)
    for flag in ("--execute", "--max-risk", "--max-actions", "--max-chains"):
        assert flag in src, f"{flag} is not exposed on the CLI"


# --- the plan must outrank the graph ------------------------------------

def test_proposed_probes_lead_when_the_graph_already_has_chains():
    """The 25-probes-printed-and-never-run regression.

    `find_chains` is called with a 0.3 floor and scores a path by multiplying
    likelihood by impact, so a proposed probe edge (0.3 * 0.9) sits at 0.27
    underneath it. Arming those edges happened only when the chain search
    returned nothing, so the moment the graph held any chain at all — a
    bucket the seeder found, archived JavaScript — the plan was printed and
    then discarded, and a run rediscovered no SQL injection that earlier
    sections had already proved on the same target. The probes now lead the
    queue, deduplicated against what the graph already carries.
    """
    from types import SimpleNamespace

    from core.attack_graph import AttackPath
    from orchestrator import probe_chains_first

    n1 = AttackNode(id="n1", label="http://t/", node_type="url",
                    confidence="CONFIRMED")
    goal = AttackNode(id="goal", label="goal: probe", node_type="goal")
    graph = SimpleNamespace(nodes={"n1": n1, "goal": goal})

    graph_edge = AttackEdge(source_id="n1", target_id="goal",
                            edge_type="pivot", likelihood=0.5, impact=0.7)
    existing = [AttackPath(nodes=[n1, goal], edges=[graph_edge], score=0.35,
                           summary="graph chain")]
    probe = AttackEdge(source_id="n1", target_id="goal", edge_type="exploit",
                       action_id="web.sqli.detect", likelihood=0.3, impact=0.9)

    chains, probe_chains = probe_chains_first(graph, existing, [probe])
    assert len(probe_chains) == 1, "the plan must survive into the queue"
    assert chains[0] is probe_chains[0], "the plan runs before graph chains"
    assert chains[-1] is existing[0], "graph chains are kept, not replaced"
    assert chains[0].score == 0.27, "a probe scores under the 0.3 floor"
    assert chains[0].edges[0].action_id == "web.sqli.detect"

    # An edge the graph already carries as a chain is not run twice.
    same, probes = probe_chains_first(graph, existing, [graph_edge])
    assert probes == []
    assert [c.summary for c in same] == [c.summary for c in existing]

    # Nothing proposed: unchanged, and no crash on an empty plan.
    same, probes = probe_chains_first(graph, existing, [])
    assert probes == []
    assert same == existing


def test_execution_window_covers_every_planned_probe(tmp_path):
    """`--max-chains 10` must not drop the plan it was handed.

    The executor takes the first N chains it is given, so a plan of 25 probes
    handed to a window of 10 lost 15 of them to whatever the graph scored
    highest — on the benchmark target, archived JavaScript and an S3 bucket.
    The action budget is what bounds cost; this window only decides whose
    request is spent first.
    """
    from core.chain_executor import ExecutionReport
    from orchestrator import Orchestrator

    o = Orchestrator(target="example.test", output_dir=str(tmp_path),
                     config_path="config.example.yaml", mode="auto")
    o.execute_chains = True
    # `run_pentest` builds the budget; this test calls the executor directly.
    o.budget = None
    with patch("core.chain_executor.ChainExecutor.execute",
               return_value=ExecutionReport()) as mock_exec:
        asyncio_run(o._execute_chains([], probe_count=25))
    assert mock_exec.call_args.kwargs["max_chains"] == o.max_chains + 25

    # No plan: the operator's ceiling alone still applies.
    with patch("core.chain_executor.ChainExecutor.execute",
               return_value=ExecutionReport()) as mock_exec:
        asyncio_run(o._execute_chains([]))
    assert mock_exec.call_args.kwargs["max_chains"] == o.max_chains


def asyncio_run(coro):
    import asyncio
    return asyncio.run(coro)
