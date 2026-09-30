"""Attack graph — converts asset graph + findings into exploit chains."""

from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlparse
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


# Node types the planner will aim a probe at. Kept as one list, shared with
# the surface seeder, because the two used to disagree: recon and the seeder
# write `endpoint` nodes while this only accepted `url`/`parameter`/
# `api_endpoint`, so a freshly seeded target had 48 endpoints and the planner
# reported zero surfaces considered. Nothing was proposed, nothing was
# skipped, and the run printed no explanation at all.
TESTABLE_NODE_TYPES = ("url", "parameter", "api_endpoint", "endpoint")


class AttackGraph:
    """Attack graph that extends the asset/finding graph with exploit transitions."""

    probe_plan: dict = {}

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
                source_id=source, target_id=target,
                edge_type=edge_type,
                likelihood=likelihood, impact=impact,
            ))

    # ── surface-driven planning ────────────────────────────────────────────
    #
    # Everything above this line builds edges from vulns that have already been
    # confirmed, which is backwards for an autonomous hunt. On a target where
    # no detector fired, that produced 24 nodes, 3 edges and 0 chains, so the
    # executor was never aimed at anything and `--execute` could only ever
    # confirm a hypothesis a human had already formed.
    #
    # A `(url, param)` pair is a legitimate target before anything is known to
    # be wrong with it. The action is the oracle: `web.sqli.detect` against a
    # parameter either finds SQL injection or reports the parameter clean, and
    # both outcomes are worth having. So the graph proposes the test, the
    # executor runs it, and a clean result is recorded as a clean result
    # rather than as silence.

    PROBE_ACTIONS: list[str] = [
        "web.sqli.detect",
        "web.xss.reflected",
    ]

    def propose_test_edges(self, max_edges: int = 100,
                           risk_ceiling: str = "LOW") -> list[AttackEdge]:
        """Propose an exploit edge for every testable surface on the graph.

        Bounded on purpose. An unbounded planner multiplies a noisy recon into
        a noisy attack, and the cost of a wasted probe is not the same as the
        cost of a wasted report.

        The risk ceiling is honoured rather than worked around. Every injection
        action in the library is MEDIUM or above, so at the default LOW ceiling
        this proposes nothing — which is the correct answer, and the reason is
        recorded in `self.probe_plan` so the caller can say so out loud. The
        previous behaviour was to return an empty list indistinguishable from
        "there was nothing to test", which is how a scan of a real application
        reported zero chains and no explanation.

        Returns only the edges it created.
        """
        from actions.registry import ActionRegistry, RiskLevel

        # Explicit rank: RiskLevel values are the strings "LOW"/"MEDIUM"/...
        # and comparing those lexicographically puts MEDIUM below LOW, which
        # would let a high-risk probe through a low ceiling.
        rank = {r.name: i for i, r in enumerate(RiskLevel)}
        try:
            ceiling = rank[str(risk_ceiling).upper()]
        except KeyError:
            ceiling = rank["LOW"]

        candidates: list[tuple[str, str]] = []  # (action_id, source node id)
        considered = 0
        blocked: dict[str, int] = {}

        for nid, node in self.nodes.items():
            if node.node_type not in TESTABLE_NODE_TYPES:
                continue
            url, param = self._surface(node)
            if not url:
                continue
            considered += 1
            armed = False
            for action_id in self.PROBE_ACTIONS:
                entry = ActionRegistry.get(action_id)
                if entry is None:
                    blocked["action not registered"] = \
                        blocked.get("action not registered", 0) + 1
                    continue
                meta = entry[0] if isinstance(entry, tuple) else entry
                if meta.risk.value not in rank or rank[meta.risk.value] > ceiling:
                    blocked[f"{action_id} is {meta.risk.value}, above the "
                            f"{str(risk_ceiling).upper()} ceiling"] = \
                        blocked.get(f"{action_id} is {meta.risk.value}, above "
                                    f"the {str(risk_ceiling).upper()} ceiling", 0) + 1
                    continue
                # An action that needs a parameter cannot be aimed at a URL
                # that has none, and a url-only action is wasted on a bare
                # parameter node.
                if "param" in meta.requires and not param:
                    blocked["no parameter on the surface"] = \
                        blocked.get("no parameter on the surface", 0) + 1
                    continue
                candidates.append((action_id, nid))
                armed = True
                break  # one probe per surface keeps the budget honest
            if not armed and not candidates:
                continue

        created: list[AttackEdge] = []
        for action_id, nid in candidates[:max_edges]:
            node = self.nodes[nid]
            goal_id = f"goal:probe_{nid}"
            if goal_id not in self.nodes:
                self.nodes[goal_id] = AttackNode(
                    id=goal_id,
                    label=f"Prove or clear {node.label}",
                    node_type="goal",
                    confidence="TENTATIVE",
                    attrs={"proposal": True, "action_id": action_id},
                )
            edge = AttackEdge(
                source_id=nid,
                target_id=goal_id,
                edge_type="exploit",
                # A hypothesis, not an observation: the whole point is that we
                # do not know yet, so the prior has to say so.
                likelihood=0.3,
                impact=0.9,
                action_id=action_id,
                attrs={"proposed": True},
            )
            self.edges.append(edge)
            created.append(edge)

        self.probe_plan = {
            "risk_ceiling": str(risk_ceiling).upper(),
            "surfaces_considered": considered,
            "probes_proposed": len(created),
            "capped_at": max_edges,
            "not_proposed": blocked,
        }
        return created

    def _surface(self, node: AttackNode) -> tuple[str, str]:
        """The (url, param) an action could be aimed at, if any.

        Mirrors `ChainExecutor._build_params` deliberately. If the two disagree
        about where a parameter lives, the graph will propose probes the
        executor then reports as unarmable, which looks like a broken planner
        rather than a missing edge.
        """
        attrs = node.attrs or {}
        url = ""
        for key in ("url", "value", "endpoint"):
            candidate = str(attrs.get(key, "")).strip()
            if candidate.startswith(("http://", "https://")):
                url = candidate
                break
        if not url and str(node.label or "").startswith(("http://", "https://")):
            url = str(node.label).strip()
        param = ""
        if str(node.node_type) == "parameter":
            param = str(node.label or "").strip()
        elif attrs.get("param"):
            param = str(attrs["param"]).strip()
        if url and not param:
            query = urlparse(url).query
            parsed = parse_qsl(query)
            param = parsed[0][0] if parsed else ""
        return url, param


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
        # `attrs` and `probe_plan` are persisted because without them the
        # saved graph cannot be audited. Everything needed to explain a result
        # — which parameter a surface had, which action was chosen, and why
        # the other 39 surfaces were skipped — lives in exactly those two
        # fields, so dropping them made the artifact unreadable after the
        # fact.
        out = {
            "nodes": [
                {"id": n.id, "label": n.label, "type": n.node_type,
                 "confidence": n.confidence, "attrs": n.attrs}
                for n in self.nodes.values()
            ],
            "edges": [
                {"source": e.source_id, "target": e.target_id,
                 "type": e.edge_type, "likelihood": e.likelihood,
                 "impact": e.impact, "action_id": e.action_id,
                 "attrs": e.attrs}
                for e in self.edges
            ],
        }
        if self.probe_plan:
            out["probe_plan"] = self.probe_plan
        return out

    def save(self, path: str | Path):
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))
