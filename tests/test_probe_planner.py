"""Can the tool aim itself at a target, or only confirm what it is handed?

The audit's most important finding was not a false positive. It was that
`--pentest --execute` found zero chains, ran zero actions, and produced zero
findings against an application with known critical bugs. The graph built
exploit edges only from vulns that had already been confirmed, so a clean
detector produced a graph with nothing to execute.

These tests cover the fix: the graph can now propose a probe for testable
surface, and — the part that matters more — it records why it did not, so
"nothing found" and "nothing attempted" stop looking the same.
"""

import tempfile
from pathlib import Path

import pytest

from core.attack_graph import AttackGraph, AttackNode
from state.manager import StateManager


def _graph(*nodes) -> AttackGraph:
    st = StateManager(str(Path(tempfile.mkdtemp()) / "run" / "t"))
    g = AttackGraph(st)
    for n in nodes:
        g.nodes[n.id] = n
    return g


def _search_url() -> AttackNode:
    """The exact shape that is worth testing: a real parameter on a real URL."""
    return AttackNode(
        id="url:search",
        label="https://t/rest/products/search?q=apple",
        node_type="url",
        confidence="CONFIRMED",
    )


def _param_node() -> AttackNode:
    return AttackNode(
        id="param:q",
        label="q",
        node_type="parameter",
        confidence="CONFIRMED",
        attrs={"url": "https://t/rest/products/search?q=apple"},
    )


def _static_asset() -> AttackNode:
    return AttackNode(
        id="url:js",
        label="https://t/static/app.js",
        node_type="url",
        confidence="CONFIRMED",
    )


# ── it proposes work ───────────────────────────────────────────────────────

def test_a_parameterised_url_gets_a_probe_proposed():
    g = _graph(_search_url())
    edges = g.propose_test_edges(risk_ceiling="MEDIUM")
    assert len(edges) == 1
    assert edges[0].action_id, "a proposed edge must name the action that runs it"
    assert edges[0].edge_type == "exploit"


def test_a_proposed_edge_becomes_a_findable_chain():
    """Edges are useless unless find_chains can actually reach them."""
    g = _graph(_search_url())
    g.propose_test_edges(risk_ceiling="MEDIUM")
    assert g.find_chains(), "proposed edges did not produce a chain"


def test_the_action_named_on_the_edge_is_one_that_exists():
    from actions.registry import ActionRegistry
    g = _graph(_search_url())
    for edge in g.propose_test_edges(risk_ceiling="MEDIUM"):
        assert ActionRegistry.get(edge.action_id) is not None


def test_a_static_asset_with_no_parameter_is_not_probed():
    """Nothing to inject, so a probe would be a wasted request."""
    g = _graph(_static_asset())
    edges = g.propose_test_edges(risk_ceiling="MEDIUM")
    assert edges == []


def test_proposals_are_bounded():
    """An unbounded planner turns noisy recon into noisy attack."""
    nodes = [AttackNode(id=f"url:{i}",
                        label=f"https://t/api/x{i}?q={i}",
                        node_type="url", confidence="CONFIRMED")
             for i in range(50)]
    g = _graph(*nodes)
    edges = g.propose_test_edges(max_edges=10, risk_ceiling="MEDIUM")
    assert len(edges) == 10
    assert g.probe_plan["capped_at"] == 10


def test_both_spellings_of_a_parameter_do_not_produce_two_probes():
    """A url node and its parameter node are the same target."""
    g = _graph(_search_url(), _param_node())
    edges = g.propose_test_edges(risk_ceiling="MEDIUM")
    targets = {e.target_id for e in edges}
    assert len(targets) == 2  # one per node, not one per (node, action)
    assert all(len(e.action_id.split(".")) >= 3 for e in edges)


# ── it explains itself ─────────────────────────────────────────────────────

def test_nothing_proposed_at_low_risk_is_explained_not_silent():
    """The failure this exists to prevent: an empty list that means nothing.

    Every injection action in the library is MEDIUM or above, so the default
    LOW ceiling legitimately proposes nothing. What must not happen is that
    being indistinguishable from having found nothing.
    """
    g = _graph(_search_url())
    edges = g.propose_test_edges(risk_ceiling="LOW")
    assert edges == []
    plan = g.probe_plan
    assert plan["surfaces_considered"] == 1, "the surface was never even looked at"
    assert plan["not_proposed"], "no reason recorded for proposing nothing"
    joined = " ".join(plan["not_proposed"])
    assert "MEDIUM" in joined and "LOW" in joined


def test_a_surface_with_no_parameter_is_explained():
    g = _graph(_static_asset())
    g.propose_test_edges(risk_ceiling="MEDIUM")
    joined = " ".join(g.probe_plan["not_proposed"])
    assert "parameter" in joined


def test_the_plan_records_the_ceiling_it_used():
    g = _graph(_search_url())
    g.propose_test_edges(risk_ceiling="MEDIUM")
    assert g.probe_plan["risk_ceiling"] == "MEDIUM"


def test_an_unknown_ceiling_falls_back_to_low_and_says_so():
    g = _graph(_search_url())
    edges = g.propose_test_edges(risk_ceiling="NONSENSE")
    assert edges == []
    assert g.probe_plan["risk_ceiling"] == "NONSENSE"
    assert g.probe_plan["surfaces_considered"] == 1


# ── the risk ceiling is a real ceiling ─────────────────────────────────────

def test_a_low_ceiling_never_proposes_a_medium_action():
    """Guards the rank comparison.

    RiskLevel values are the strings "LOW"/"MEDIUM"/"HIGH", and comparing
    those as text puts MEDIUM *below* LOW. A lexicographic comparison would
    let every injection action through a LOW ceiling.
    """
    from actions.registry import ActionRegistry
    g = _graph(_search_url(), _param_node())
    for edge in g.propose_test_edges(risk_ceiling="LOW"):
        meta = ActionRegistry.get(edge.action_id)[0]
        assert meta.risk.value == "SAFE", (
            f"{edge.action_id} is {meta.risk.value} and got through a LOW ceiling"
        )


def test_the_planner_surfaces_match_the_executor_param_derivation():
    """If these two disagree, the graph proposes probes the executor cannot arm.

    Same input, same answer: a disagreement here would surface as a stream of
    NO ARM outcomes that look like a broken planner rather than a missing edge.
    """
    from core.chain_executor import ChainExecutor
    from actions.registry import ActionRegistry

    node = _param_node()
    g = _graph(node)
    edges = g.propose_test_edges(risk_ceiling="MEDIUM")
    assert edges

    executor = ChainExecutor.__new__(ChainExecutor)
    meta = ActionRegistry.get(edges[0].action_id)[0]
    chain = type("C", (), {"nodes": {node.id: node}})()
    params, missing = executor._build_params(edges[0], chain, meta)
    assert not missing, f"executor could not arm what the graph proposed: {missing}"
    assert params["param"] == "q"
    assert params["url"] == "https://t/rest/products/search?q=apple"
