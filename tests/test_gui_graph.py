"""Tests for GUI graph construction."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gui.graph import (
    _patch_gravis_isolated_node_hover,
    build_display_graph,
    build_graph,
    graph_positions,
    render_gravis_html,
    to_gravis_graph,
)


def test_build_graph_infers_domain_to_subdomain_and_webapp():
    assets = {
        "nodes": [
            {"type": "domain", "key": "domain:example.com", "value": "example.com"},
            {"type": "subdomain", "key": "sub:www.example.com", "value": "www.example.com"},
            {"type": "webapp", "key": "webapp:https://www.example.com", "value": "https://www.example.com"},
        ],
        "edges": [],
    }

    graph = build_graph(assets)
    relations = {(e["source"], e["target"], e["type"]) for e in graph["edges"]}

    assert ("domain:example.com", "sub:www.example.com", "HAS_SUBDOMAIN") in relations
    assert ("sub:www.example.com", "webapp:https://www.example.com", "HOSTS_WEBAPP") in relations


def test_graph_positions_returns_coordinates_for_all_nodes():
    nodes = [
        {"type": "domain", "key": "domain:example.com"},
        {"type": "ip", "key": "ip:192.0.2.1"},
    ]

    positions = graph_positions(nodes)

    assert set(positions) == {"domain:example.com", "ip:192.0.2.1"}


def test_build_display_graph_aggregates_dense_types():
    assets = {
        "nodes": [
            {"type": "domain", "key": "domain:example.com", "value": "example.com"},
            *[
                {"type": "subdomain", "key": f"sub:s{i}.example.com", "value": f"s{i}.example.com"}
                for i in range(12)
            ],
        ],
        "edges": [
            {"source": "domain:example.com", "target": "sub:s1.example.com", "type": "HAS_SUBDOMAIN"}
        ],
    }

    graph = build_display_graph(assets, aggregate=True, aggregate_threshold=10)
    keys = {node["key"] for node in graph["nodes"]}

    assert "group:subdomain" in keys
    assert len(graph["nodes"]) == 2
    assert graph["meta"]["raw_nodes"] == 13


def test_to_gravis_graph_uses_gjgf_shape():
    display_graph = {
        "nodes": [
            {"type": "domain", "key": "domain:example.com", "value": "example.com", "attrs": {}},
            {"type": "ip", "key": "ip:192.0.2.1", "value": "192.0.2.1", "attrs": {}},
        ],
        "edges": [
            {"source": "domain:example.com", "target": "ip:192.0.2.1", "type": "RESOLVES_TO"}
        ],
    }

    graph = to_gravis_graph(display_graph, show_labels=True, show_edges=True)

    assert "graph" in graph
    assert "domain:example.com" in graph["graph"]["nodes"]
    assert graph["graph"]["edges"][0]["source"] == "domain:example.com"


def test_gravis_html_guards_isolated_hover_sets():
    html = (
        "const adjacentNodes = state.shownData.adjacency.map.get(node),\n"
        "                    incidentEdges = state.shownData.incidence.map.get(node);"
    )

    patched = _patch_gravis_isolated_node_hover(html)

    assert "adjacency.map.get(node) || new Set()" in patched
    assert "incidence.map.get(node) || new Set()" in patched
