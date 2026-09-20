"""Attack graph — converts asset graph + findings into exploit chains."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from state.manager import StateManager

CONFIDENCE_ORDER = {"TENTATIVE": 0, "FIRM": 1, "CONFIRMED": 2}


@dataclass(frozen=True)
class AttackNode:
    id: str
    label: str
    node_type: str  # asset | vuln | credential | access_state | goal
    confidence: str = "TENTATIVE"
    attrs: dict = field(default_factory=dict)


@dataclass(frozen=True)
class AttackEdge:
    source_id: str
    target_id: str
    edge_type: str  # exploit | authenticate | pivot | escalate | exfil
    action_id: str = ""  # action that proves this edge
    likelihood: float = 0.5
    impact: float = 0.5
    attrs: dict = field(default_factory=dict)


@dataclass(frozen=True)
class AttackPath:
    nodes: list[AttackNode]
    edges: list[AttackEdge]
    score: float = 0.0
    summary: str = ""


class AttackGraph:
    """Attack graph that extends the asset/finding graph with exploit transitions."""

    def __init__(self, state: StateManager):
        self.state = state
        self.nodes: dict[str, AttackNode] = {}
        self.edges: list[AttackEdge] = []

    def build(self):
        """Build the attack graph from current state."""
        self.nodes.clear()
        self.edges.clear()

        # Seed nodes from asset graph
        for node in self.state.assets.get("nodes", []):
            key = node.get("key", "")
            if not key:
                continue
            self.nodes[key] = AttackNode(
                id=key,
                label=node.get("value", key),
                node_type=node.get("type", "asset"),
                confidence=node.get("confidence", "TENTATIVE"),
                attrs=node.get("attrs", {}),
            )

        # Add finding-derived vuln nodes
        for finding in self.state.findings.get("findings", []):
            vid = f"vuln:{finding.get('id', '')}"
            self.nodes[vid] = AttackNode(
                id=vid,
                label=finding.get("title", "Unknown finding"),
                node_type="vuln",
                confidence=finding.get("confidence", "TENTATIVE"),
                attrs={
                    "severity": finding.get("severity", ""),
                    "risk_score": finding.get("risk_score", 0),
                    "category": finding.get("category", ""),
                    "description": finding.get("description", ""),
                },
            )
            # Link vuln to affected assets
            for asset_key in finding.get("asset_keys", []):
                if asset_key in self.nodes:
                    self.edges.append(AttackEdge(
                        source_id=asset_key,
                        target_id=vid,
                        edge_type="affected_by",
                        likelihood=0.7,
                        impact=0.6,
                    ))

        # Infer transition edges from tech + vuln combinations
        self._infer_transitions()

    def _infer_transitions(self):
        """Detect common attack transitions from node types and attributes."""
        vuln_nodes = {k: v for k, v in self.nodes.items() if v.node_type == "vuln"}
        asset_nodes = {k: v for k, v in self.nodes.items() if v.node_type != "vuln"}

        new_nodes: list[AttackNode] = []
        new_edges: list[AttackEdge] = []

        for nid, node in list(self.nodes.items()):
            attrs = node.attrs
            node_type = node.node_type

            # Webapp -> API endpoints
            if node_type == "webapp":
                for other_id, other in asset_nodes.items():
                    if other.node_type == "url" and "api" in other.label.lower():
                        self._add_transition(nid, other_id, "api_discovery",
                                             likelihood=0.6, impact=0.4)

            # Login panels -> credential access
            if "login" in node.label.lower() or "admin" in node.label.lower():
                goal_id = f"goal:access_{node.label.replace('.', '_')}"
                if goal_id not in self.nodes and not any(n.id == goal_id for n in new_nodes):
                    new_nodes.append(AttackNode(
                        id=goal_id,
                        label=f"Access {node.label}",
                        node_type="goal",
                        confidence="TENTATIVE",
                    ))
                new_edges.append(AttackEdge(
                    source_id=nid, target_id=goal_id,
                    edge_type="authenticate",
                    likelihood=0.3, impact=0.8,
                ))

            # Parameterized URLs -> injection vulns
            if node_type == "parameter" or node_type == "url":
                for vid, vuln in vuln_nodes.items():
                    cat = vuln.attrs.get("category", "").lower()
                    if "sql" in cat:
                        new_edges.append(AttackEdge(
                            source_id=nid, target_id=vid,
                            edge_type="exploit",
                            likelihood=0.4, impact=0.9,
                        ))
                    if "xss" in cat:
                        new_edges.append(AttackEdge(
                            source_id=nid, target_id=vid,
                            edge_type="exploit",
                            likelihood=0.5, impact=0.6,
                        ))

            # Cloud buckets -> credential exposure
            if node_type == "cloud_bucket" or node_type == "bucket":
                goal_id = f"goal:bucket_access_{nid}"
                if goal_id not in self.nodes and not any(n.id == goal_id for n in new_nodes):
                    new_nodes.append(AttackNode(
                        id=goal_id,
                        label="Bucket data access",
                        node_type="goal",
                        confidence="TENTATIVE",
                    ))
                new_edges.append(AttackEdge(
                    source_id=nid, target_id=goal_id,
                    edge_type="pivot",
                    likelihood=0.5, impact=0.7,
                ))

            # JS files -> secrets -> further access
            if node_type == "js_file" or node_type == "javascript":
                secret_goal = f"goal:secrets_from_{nid}"
                if secret_goal not in self.nodes and not any(n.id == secret_goal for n in new_nodes):
                    new_nodes.append(AttackNode(
                        id=secret_goal,
                        label="Extracted secrets from JS",
                        node_type="goal",
                        confidence="TENTATIVE",
                    ))
                new_edges.append(AttackEdge(
                    source_id=nid, target_id=secret_goal,
                    edge_type="extract",
                    likelihood=0.6, impact=0.5,
                ))

        # Batch insert new nodes and edges
        for n in new_nodes:
            self.nodes[n.id] = n
        self.edges.extend(new_edges)

    def _add_transition(self, source: str, target: str, edge_type: str,
                        likelihood: float, impact: float):
        if source in self.nodes and target in self.nodes:
            self.edges.append(AttackEdge(
                source_id=source,
                target_id=target,
                edge_type=edge_type,
                likelihood=likelihood,
                impact=impact,
            ))

    def find_chains(self, max_depth: int = 4,
                    min_score: float = 0.1) -> list[AttackPath]:
        """BFS for exploit chains from assets to high-value goals."""
        goals = {k: v for k, v in self.nodes.items() if v.node_type == "goal"}
        assets = {k: v for k, v in self.nodes.items()
                  if v.node_type not in ("goal", "vuln")}

        if not goals or not assets:
            return []

        # Build adjacency
        adj: dict[str, list[tuple[str, AttackEdge]]] = {}
        for edge in self.edges:
            adj.setdefault(edge.source_id, []).append((edge.target_id, edge))

        chains = []
        for start_id in assets:
            visited = set()
            queue: list[tuple[str, list[AttackNode], list[AttackEdge], float]] = [
                (start_id, [assets[start_id]], [], 1.0)
            ]
            while queue:
                current, path_nodes, path_edges, path_score = queue.pop(0)
                if len(path_nodes) > max_depth:
                    continue
                if current in visited:
                    continue
                visited.add(current)

                if current in goals:
                    if len(path_edges) > 0 and path_score >= min_score:
                        summary = self._path_summary(path_nodes, path_edges)
                        chains.append(AttackPath(
                            nodes=path_nodes,
                            edges=path_edges,
                            score=round(path_score, 3),
                            summary=summary,
                        ))
                    continue

                for neighbor, edge in adj.get(current, []):
                    if neighbor not in visited:
                        edge_score = edge.likelihood * edge.impact
                        queue.append((
                            neighbor,
                            path_nodes + ([self.nodes[neighbor]] if neighbor in self.nodes else []),
                            path_edges + [edge],
                            path_score * edge_score,
                        ))

        chains.sort(key=lambda p: -p.score)
        return chains

    def _path_summary(self, nodes: list[AttackNode], edges: list[AttackEdge]) -> str:
        parts = []
        for i, edge in enumerate(edges):
            src_label = nodes[i].label if i < len(nodes) else edge.source_id
            parts.append(f"{src_label} --[{edge.edge_type}]--> ")
        if nodes:
            parts.append(nodes[-1].label)
        return "".join(parts)

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {"id": n.id, "label": n.label, "type": n.node_type,
                 "confidence": n.confidence}
                for n in self.nodes.values()
            ],
            "edges": [
                {"source": e.source_id, "target": e.target_id,
                 "type": e.edge_type, "likelihood": e.likelihood,
                 "impact": e.impact}
                for e in self.edges
            ],
        }

    def save(self, path: str | Path):
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))
