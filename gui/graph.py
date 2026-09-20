"""Asset graph helpers for the GUI."""

from __future__ import annotations

from collections import defaultdict
from html import escape
from math import cos, pi, sin


AGGREGATE_TYPES = {"subdomain", "webapp", "bucket", "dns_record", "social_media"}


def build_graph(assets: dict) -> dict:
    nodes = assets.get("nodes", [])
    edges = list(assets.get("edges", []))
    by_key = {node.get("key"): node for node in nodes if node.get("key")}

    inferred = []
    for node in nodes:
        key = node.get("key", "")
        attrs = node.get("attrs", {})
        if node.get("type") == "subdomain":
            domain = ".".join(str(node.get("value", "")).split(".")[-2:])
            domain_key = f"domain:{domain}"
            if domain_key in by_key:
                inferred.append({
                    "source": domain_key,
                    "target": key,
                    "type": "HAS_SUBDOMAIN",
                    "attrs": {"inferred": True},
                })
            ip = attrs.get("ip")
            if ip and f"ip:{ip}" in by_key:
                inferred.append({
                    "source": key,
                    "target": f"ip:{ip}",
                    "type": "RESOLVES_TO",
                    "attrs": {"inferred": True},
                })
        elif node.get("type") == "webapp":
            host = str(node.get("value", "")).split("//")[-1].split("/", 1)[0]
            host_key = f"domain:{host}"
            sub_key = f"sub:{host}"
            if sub_key in by_key:
                inferred.append({
                    "source": sub_key,
                    "target": key,
                    "type": "HOSTS_WEBAPP",
                    "attrs": {"inferred": True},
                })
            elif host_key in by_key:
                inferred.append({
                    "source": host_key,
                    "target": key,
                    "type": "HOSTS_WEBAPP",
                    "attrs": {"inferred": True},
                })

    seen = {(e.get("source"), e.get("target"), e.get("type")) for e in edges}
    for edge in inferred:
        identity = (edge.get("source"), edge.get("target"), edge.get("type"))
        if identity not in seen:
            edges.append(edge)
            seen.add(identity)

    return {"nodes": nodes, "edges": edges}


def build_display_graph(assets: dict, aggregate: bool = True,
                        aggregate_threshold: int = 10) -> dict:
    graph = build_graph(assets)
    nodes = graph["nodes"]
    edges = graph["edges"]
    if not aggregate:
        return graph

    counts = defaultdict(int)
    for node in nodes:
        counts[node.get("type", "unknown")] += 1

    collapsed_types = {
        asset_type for asset_type, count in counts.items()
        if count >= aggregate_threshold or asset_type in AGGREGATE_TYPES
    }

    display_nodes = []
    key_map = {}
    for asset_type in sorted(collapsed_types):
        group_key = f"group:{asset_type}"
        display_nodes.append({
            "type": f"{asset_type}_group",
            "key": group_key,
            "value": f"{asset_type} ({counts[asset_type]})",
            "confidence": "GROUP",
            "attrs": {"count": counts[asset_type], "group_type": asset_type},
            "sources": ["graph aggregation"],
        })

    for node in nodes:
        asset_type = node.get("type", "unknown")
        if asset_type in collapsed_types:
            key_map[node.get("key")] = f"group:{asset_type}"
        else:
            key_map[node.get("key")] = node.get("key")
            display_nodes.append(node)

    display_edges = []
    seen = set()
    for edge in edges:
        source = key_map.get(edge.get("source"))
        target = key_map.get(edge.get("target"))
        if not source or not target or source == target:
            continue
        relation = edge.get("type", "RELATES_TO")
        identity = (source, target, relation)
        if identity in seen:
            continue
        seen.add(identity)
        display_edges.append({
            "source": source,
            "target": target,
            "type": relation,
            "attrs": edge.get("attrs", {}),
        })

    return {
        "nodes": display_nodes,
        "edges": display_edges,
        "meta": {
            "raw_nodes": len(nodes),
            "raw_edges": len(edges),
            "collapsed_types": sorted(collapsed_types),
        },
    }


def to_gravis_graph(display_graph: dict, show_labels: bool = False,
                    show_edges: bool = True) -> dict:
    """Convert display graph to gravis JSON Graph Format."""
    nodes = {}
    for node in display_graph.get("nodes", []):
        node_id = str(node.get("key", ""))
        if not node_id:
            continue
        asset_type = node.get("type", "asset")
        is_group = node.get("confidence") == "GROUP"
        color = _type_color(asset_type)
        count = int(node.get("attrs", {}).get("count", 1) or 1)
        size = 38 + min(42, count * 2) if is_group else 24 + min(18, len(node.get("sources", [])) * 2)
        label = _label(node, show_labels or is_group or asset_type == "domain")
        nodes[node_id] = {
            "label": label,
            "metadata": {
                "color": color,
                "size": size,
                "border_color": "#e2e8f0",
                "border_size": 2,
                "hover": _node_hover(node),
                "click": _node_click(node),
            },
        }

    edges = []
    if show_edges:
        for edge in display_graph.get("edges", []):
            source = str(edge.get("source", ""))
            target = str(edge.get("target", ""))
            if source not in nodes or target not in nodes:
                continue
            inferred = edge.get("attrs", {}).get("inferred", False)
            edges.append({
                "source": source,
                "target": target,
                "label": edge.get("type", ""),
                "metadata": {
                    "color": "#94a3b8" if inferred else "#e11d48",
                    "opacity": 0.44 if inferred else 0.76,
                    "size": 1.0 if inferred else 1.4,
                    "hover": escape(edge.get("type", "RELATES_TO")),
                },
            })

    return {
        "graph": {
            "directed": True,
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "background_color": "#f8fafc",
                "node_label_size": 11,
                "edge_label_size": 8,
                "edge_opacity": 0.55,
            },
        }
    }


def render_gravis_html(display_graph: dict, show_labels: bool = False,
                       show_edges: bool = True, height: int = 720) -> str:
    """Render a Gravis D3 HTML document for embedding in Qt WebEngine."""
    import warnings

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="pkg_resources is deprecated.*")
        import gravis as gv

    graph = to_gravis_graph(display_graph, show_labels=show_labels, show_edges=show_edges)
    fig = gv.d3(
        graph,
        graph_height=height,
        details_height=160,
        show_details=True,
        show_menu=True,
        show_node_label=True,
        show_edge_label=False,
        node_hover_tooltip=True,
        edge_hover_tooltip=True,
        node_drag_fix=True,
        node_hover_neighborhood=True,
        use_collision_force=True,
        collision_force_radius=30.0,
        collision_force_strength=0.8,
        links_force_distance=64.0,
        links_force_strength=0.72,
        many_body_force_strength=-180.0,
        use_x_positioning_force=True,
        x_positioning_force_strength=0.08,
        use_y_positioning_force=True,
        y_positioning_force_strength=0.08,
        zoom_factor=0.72,
    )
    html = fig.to_html_standalone()
    html = _patch_gravis_isolated_node_hover(html)
    html = _patch_gravis_light_theme(html)
    return html.replace(
        "</body>",
        "<style>body{margin:0;background:#eef2f7;color:#0f172a;font-family:Arial,sans-serif;}</style></body>",
    )


def _patch_gravis_isolated_node_hover(html: str) -> str:
    """Guard Gravis hover-neighborhood code for isolated graph nodes.

    Gravis 0.1.0 assumes every displayed node has adjacency/incidence Set
    entries. Aggregated OSINT graphs commonly contain isolated nodes, which
    makes Qt WebEngine log repeated `undefined.has` JavaScript errors on hover.
    """
    return html.replace(
        "const adjacentNodes = state.shownData.adjacency.map.get(node),\n"
        "                    incidentEdges = state.shownData.incidence.map.get(node);",
        "const adjacentNodes = state.shownData.adjacency.map.get(node) || new Set(),\n"
        "                    incidentEdges = state.shownData.incidence.map.get(node) || new Set();",
    )


def _patch_gravis_light_theme(html: str) -> str:
    light_theme = """
<style>
body {
    background: #eef2f7 !important;
    color: #0f172a !important;
}
svg {
    background: #f8fafc !important;
}
svg text {
    fill: #0f172a !important;
}
button, select, input, summary, details, label, div, span {
    color: #0f172a;
}
button, select, input {
    background: #ffffff !important;
    border: 1px solid #cbd5e1 !important;
    border-radius: 8px !important;
}
aside, pre {
    background: #ffffff !important;
    color: #0f172a !important;
}
details {
    background: #ffffff !important;
    border: 1px solid #dbe4ee !important;
    border-radius: 10px !important;
}
</style>
"""
    return html.replace("</head>", f"{light_theme}</head>")


def _type_color(asset_type: str) -> str:
    colors = {
        "domain": "#2563eb",
        "subdomain": "#0891b2",
        "subdomain_group": "#0891b2",
        "ip": "#7c3aed",
        "webapp": "#16a34a",
        "webapp_group": "#16a34a",
        "port": "#dc2626",
        "bucket": "#d97706",
        "bucket_group": "#d97706",
        "email": "#9333ea",
        "email_domain": "#9333ea",
        "email_pattern": "#a16207",
        "dns_record": "#334155",
        "dns_record_group": "#334155",
        "waf": "#475569",
        "social_media": "#1f2937",
        "social_media_group": "#1f2937",
        "exploit_intel": "#111827",
        "cloud_enum": "#64748b",
        "breach_data": "#64748b",
    }
    return colors.get(asset_type, "#334155")


def _label(node: dict, enabled: bool) -> str:
    if not enabled:
        return ""
    value = str(node.get("value") or node.get("key") or "")
    return value if len(value) <= 34 else value[:31] + "..."


def _node_hover(node: dict) -> str:
    attrs = node.get("attrs", {})
    rows = [
        f"<b>{escape(str(node.get('type', 'asset')))}</b>",
        escape(str(node.get("value", ""))),
        f"<code>{escape(str(node.get('key', '')))}</code>",
        f"confidence: {escape(str(node.get('confidence', '')))}",
    ]
    if attrs.get("count"):
        rows.append(f"count: {escape(str(attrs['count']))}")
    return "<br>".join(rows)


def _node_click(node: dict) -> str:
    attrs = node.get("attrs", {})
    sources = ", ".join(node.get("sources", []))
    rows = [
        f"<h3>{escape(str(node.get('value', node.get('key', ''))))}</h3>",
        f"<p><b>Type:</b> {escape(str(node.get('type', 'asset')))}</p>",
        f"<p><b>Confidence:</b> {escape(str(node.get('confidence', '')))}</p>",
    ]
    if sources:
        rows.append(f"<p><b>Sources:</b> {escape(sources)}</p>")
    if attrs:
        preview = escape(str(attrs)[:1500])
        rows.append(f"<pre>{preview}</pre>")
    return "".join(rows)


def graph_positions(nodes: list[dict], width: int = 820, height: int = 560) -> dict:
    grouped = defaultdict(list)
    for node in nodes:
        grouped[node.get("type", "unknown")].append(node)

    type_names = sorted(grouped)
    if not type_names:
        return {}

    center_x = width / 2
    center_y = height / 2
    type_radius = min(width, height) * 0.34
    positions = {}

    for type_index, type_name in enumerate(type_names):
        angle = (2 * pi * type_index) / max(len(type_names), 1)
        group_x = center_x + cos(angle) * type_radius
        group_y = center_y + sin(angle) * type_radius
        group = grouped[type_name]
        node_radius = 54 if len(group) > 1 else 0
        for node_index, node in enumerate(group):
            if node_radius:
                node_angle = (2 * pi * node_index) / len(group)
                x = group_x + cos(node_angle) * node_radius
                y = group_y + sin(node_angle) * node_radius
            else:
                x, y = group_x, group_y
            positions[node.get("key")] = (x, y)

    return positions


def radial_positions(nodes: list[dict], edges: list[dict], width: int = 1000,
                     height: int = 720) -> dict:
    if not nodes:
        return {}

    by_key = {node.get("key"): node for node in nodes}
    degree = defaultdict(int)
    for edge in edges:
        degree[edge.get("source")] += 1
        degree[edge.get("target")] += 1

    center_x = width / 2
    center_y = height / 2
    root = max(nodes, key=lambda node: degree[node.get("key")] + (3 if node.get("type") == "domain" else 0))
    positions = {root.get("key"): (center_x, center_y)}

    remaining = [node for node in nodes if node.get("key") != root.get("key")]
    grouped = defaultdict(list)
    for node in remaining:
        grouped[node.get("type", "unknown")].append(node)

    type_names = sorted(grouped)
    type_radius = min(width, height) * 0.34
    for type_index, type_name in enumerate(type_names):
        angle = (2 * pi * type_index) / max(len(type_names), 1)
        group = grouped[type_name]
        group_x = center_x + cos(angle) * type_radius
        group_y = center_y + sin(angle) * type_radius
        spread = 42 + min(90, len(group) * 3)
        for node_index, node in enumerate(group):
            node_angle = (2 * pi * node_index) / max(len(group), 1)
            distance = 0 if len(group) == 1 else spread
            positions[node.get("key")] = (
                group_x + cos(node_angle) * distance,
                group_y + sin(node_angle) * distance,
            )

    return {key: value for key, value in positions.items() if key in by_key}
