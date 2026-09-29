"""Execute the exploit chains the attack graph finds, and prove them.

The gap this closes: the graph built edges tagged `exploit`, `pivot` and
`extract`, and `AttackEdge` has an `action_id` field documented as "action that
proves this edge" — which was never set, by anything, ever. `run_pentest()`
then printed the chains it found and returned. Fifteen actions were registered,
including `auth.jwt.none_alg`, `auth.jwt.weak_secret_crack` and
`web.ssrf.cloud_metadata`, and none of them were ever invoked on any target
outside an LLM agent session.

So the tool detected well and exploited never. Every finding it produced was a
claim, because nothing went and checked.

This module is the part that goes and checks. For each edge in a chain it picks
the action that can prove that edge, runs it under a risk ceiling and a request
budget, and promotes a successful result to a finding marked verified with the
evidence the action actually returned. An action that returns
`ActionResult.confidence = CONFIRMED` with real captured evidence is a very
different report from a heuristic that guessed.

Safety is by construction, not by convention:

  * Nothing above the risk ceiling runs. The default is LOW, so
    `web.sqli.sqlmap` and anything DESTRUCTIVE stays parked unless the operator
    asks for it by name. Raising the ceiling is always explicit.
  * The budget is checked before each action, not after.
  * A chain is a proposal, not a mandate: a failed edge does not silently
    promote its neighbours, and a chain with no runnable edge is reported as
    skipped rather than silently dropped.
  * Every action is recorded in the audit log with its outcome, so a scan that
    fired payloads is reconstructable afterwards.

What "exploitation" means here is proving impact on a target the operator is
authorized to test: send the one request that demonstrates the flaw, capture
the response that demonstrates access, and report it. That is also what a
triager wants, because a proven finding with a captured artifact is payable
while a plausible one is not.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from actions.registry import ActionRegistry, RiskLevel
from core.attack_graph import AttackEdge

RISK_ORDER = [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH,
              RiskLevel.DESTRUCTIVE]


def risk_allows(action_risk: str, ceiling: RiskLevel) -> bool:
    """Is this action under the operator's ceiling?"""
    try:
        level = RiskLevel(str(action_risk).upper())
    except ValueError:
        # An unparseable risk is not permission to run it.
        return False
    return RISK_ORDER.index(level) <= RISK_ORDER.index(ceiling)


# Which action can prove which kind of edge. Ordered by preference: the first
# registered action that exists and is under the ceiling wins.
EDGE_ACTIONS: dict[str, list[str]] = {
    "exploit": [
        "web.sqli.detect",
        "web.sqli.blind_detect",
        "web.xss.reflected",
    ],
    "pivot": [
        "web.ssrf.cloud_metadata",
        "web.ssrf.oob_detect",
    ],
    "extract": [
        "verify.differential",
        "verify.reproducible",
    ],
    "authenticate": [
        "auth.jwt.detect",
    ],
}

# Edge type to the vuln-node category that selects a specific action. The graph
# tags vuln nodes with the finding category, so this turns "a SQL finding" into
# "run web.sqli.detect against the URL that produced it".
CATEGORY_ACTIONS: list[tuple[str, str]] = [
    ("sql", "web.sqli.detect"),
    ("injection", "web.sqli.detect"),
    ("xss", "web.xss.reflected"),
    ("ssrf", "web.ssrf.oob_detect"),
    ("cloud", "web.ssrf.cloud_metadata"),
    ("jwt", "auth.jwt.detect"),
    ("token", "auth.jwt.detect"),
    ("auth", "auth.jwt.detect"),
]


@dataclass
class PlannedEdge:
    """One edge, the action chosen to prove it, and the target to point it at."""
    edge: AttackEdge
    action_id: str
    risk: str
    url: str
    reason: str = ""


@dataclass
class EdgeOutcome:
    """What happened when we went and proved one edge."""
    edge: AttackEdge
    action_id: str
    status: str                      # ran | skipped | blocked_risk | no_action
    finding_id: str = ""
    confidence: str = ""
    impact: str = ""
    detail: str = ""
    evidence: dict = field(default_factory=dict)


@dataclass
class ExecutionReport:
    ran: list[EdgeOutcome] = field(default_factory=list)
    blocked: list[EdgeOutcome] = field(default_factory=list)
    skipped: list[EdgeOutcome] = field(default_factory=list)

    @property
    def proven(self) -> int:
        return sum(1 for o in self.ran if o.finding_id)

    def summary(self) -> str:
        return (f"{self.proven} proven, {len(self.blocked)} blocked by risk, "
                f"{len(self.skipped)} skipped")


class ChainExecutor:
    """Runs chain edges for real, under a risk ceiling and a budget."""

    def __init__(self, state, config: Optional[dict] = None,
                 budget=None, audit=None,
                 max_risk: RiskLevel = RiskLevel.LOW,
                 max_actions: int = 25):
        self.state = state
        self.config = config or {}
        self.budget = budget
        self.audit = audit
        self.max_risk = max_risk
        self.max_actions = max(0, int(max_actions))
        self._used = 0

    # ── planning ──────────────────────────────────────────────────

    def plan(self, chain) -> list[PlannedEdge]:
        """Choose, for each edge in a chain, the action that can prove it."""
        planned = []
        for edge in chain.edges:
            action_id, reason = self._select_action(edge, chain)
            if not action_id:
                continue
            entry = ActionRegistry.get(action_id)
            if not entry:
                continue
            meta, _ = entry
            url = self._target_for(edge, chain)
            if not url:
                continue
            # ActionMeta.risk is a plain string, not a RiskLevel, so normalise
            # it here rather than reaching for .value.
            risk = getattr(meta.risk, "value", meta.risk)
            planned.append(PlannedEdge(
                edge=edge, action_id=action_id, risk=str(risk), url=url,
                reason=reason))
        return planned

    def _select_action(self, edge: AttackEdge, chain) -> tuple:
        """Prefer the action the edge declares, then a category match, then the
        edge type's default."""
        if edge.action_id and ActionRegistry.get(edge.action_id):
            return edge.action_id, "declared on edge"

        target = chain.nodes.get(edge.target_id) if hasattr(chain, "nodes") else None
        category = ""
        if target is not None:
            category = str((target.attrs or {}).get("category", "")).lower()

        if category:
            for token, action_id in CATEGORY_ACTIONS:
                if token in category and ActionRegistry.get(action_id):
                    return action_id, f"vuln category '{category}'"

        for action_id in EDGE_ACTIONS.get(edge.edge_type, []):
            if ActionRegistry.get(action_id):
                return action_id, f"edge type '{edge.edge_type}'"
        return "", "no registered action proves this edge"

    def _target_for(self, edge: AttackEdge, chain) -> str:
        """The URL the action should be pointed at."""
        for node_id in (edge.source_id, edge.target_id):
            node = chain.nodes.get(node_id) if hasattr(chain, "nodes") else None
            if node is None:
                continue
            attrs = node.attrs or {}
            for key in ("url", "value", "endpoint"):
                candidate = str(attrs.get(key, "")).strip()
                if candidate.startswith(("http://", "https://")):
                    return candidate
        return ""

    # ── execution ─────────────────────────────────────────────────

    async def execute(self, chains, max_chains: int = 10) -> ExecutionReport:
        report = ExecutionReport()
        for chain in list(chains)[:max_chains]:
            for planned in self.plan(chain):
                if self._used >= self.max_actions:
                    report.skipped.append(EdgeOutcome(
                        edge=planned.edge, action_id=planned.action_id,
                        status="skipped", detail="action budget exhausted"))
                    continue
                outcome = await self._run_one(planned)
                if outcome.status == "ran":
                    report.ran.append(outcome)
                elif outcome.status == "blocked_risk":
                    report.blocked.append(outcome)
                else:
                    report.skipped.append(outcome)
        return report

    async def _run_one(self, planned: PlannedEdge) -> EdgeOutcome:
        if not risk_allows(planned.risk, self.max_risk):
            return EdgeOutcome(
                edge=planned.edge, action_id=planned.action_id,
                status="blocked_risk",
                detail=(f"{planned.action_id} is {planned.risk}, above the "
                        f"{self.max_risk.value} ceiling"),
            )

        if self.budget is not None and not self.budget.check():
            return EdgeOutcome(
                edge=planned.edge, action_id=planned.action_id,
                status="skipped", detail="budget exhausted",
            )

        from actions.registry import ActionContext

        ctx = ActionContext(
            action_id=planned.action_id,
            params={"url": planned.url},
            target=planned.url,
        )
        entry = ActionRegistry.get(planned.action_id)
        ctx.meta = entry[0] if entry else None
        if self.audit is not None:
            ctx.audit = self.audit

        try:
            result = await ActionRegistry.execute(planned.action_id, ctx)
        except Exception as exc:
            # An action that blows up is a bug in the action, not evidence that
            # the target is safe. Record it and keep going.
            return EdgeOutcome(
                edge=planned.edge, action_id=planned.action_id,
                status="skipped", detail=f"action raised: {exc}",
            )

        self._used += 1
        if self.budget is not None:
            try:
                self.budget.record_action()
            except Exception:
                pass

        if not getattr(result, "success", False):
            return EdgeOutcome(
                edge=planned.edge, action_id=planned.action_id,
                status="skipped",
                detail=getattr(result, "error", "") or "action did not confirm",
                confidence=getattr(result, "confidence", ""),
            )

        return self._promote(planned, result)

    def _promote(self, planned: PlannedEdge, result) -> EdgeOutcome:
        """Turn a successful action into a verified finding.

        This is the whole point. A confirmed action result with captured
        evidence becomes a finding the operator can paste into a report, with
        `verified=True` because something actually ran and returned data.
        """
        confidence = getattr(result, "confidence", "TENTATIVE") or "TENTATIVE"
        evidence = dict(getattr(result, "evidence", {}) or {})
        impact = evidence.get("impact") or evidence.get("summary") or ""
        data = getattr(result, "data", None)

        evidence_lines = [
            f"Action: {planned.action_id} ({planned.reason})",
            f"Target: {planned.url}",
        ]
        for key, value in list(evidence.items())[:12]:
            evidence_lines.append(f"{key}: {_stringify(value)}")
        if data is not None:
            evidence_lines.append(f"data: {_stringify(data)}")

        finding_id = self.state.add_finding(
            title=f"Proven: {planned.action_id} on {planned.url}",
            severity=_severity_for(planned.edge, evidence),
            confidence=confidence,
            category=_category_for(planned.action_id),
            description=(
                f"Executed {planned.action_id} against {planned.url} "
                f"(selected because {planned.reason}). The action returned a "
                f"successful result at {confidence} confidence. This was run, "
                "not inferred: the evidence below came back from the target. "
                + (f"Impact observed: {impact}" if impact else "")
            ),
            evidence=evidence_lines[:20],
            remediation=_remediation_for(planned.action_id),
            asset_keys=[],
            verified=True,
        )
        return EdgeOutcome(
            edge=planned.edge, action_id=planned.action_id, status="ran",
            finding_id=finding_id, confidence=confidence, impact=impact,
            evidence=evidence,
        )


def _severity_for(edge: AttackEdge, evidence: dict) -> str:
    """Impact edge, boosted by anything the action said it actually got."""
    base = "MEDIUM" if edge.impact >= 0.6 else "LOW"
    hint = " ".join(
        str(v).lower() for v in evidence.values() if isinstance(v, (str, int))
    )
    for token, severity in (
        ("admin", "HIGH"), ("root", "HIGH"), ("token", "HIGH"),
        ("credential", "HIGH"), ("secret", "HIGH"), ("executed", "HIGH"),
        ("metadata", "HIGH"), ("rce", "CRITICAL"),
    ):
        if token in hint:
            return severity
    return base


def _category_for(action_id: str) -> str:
    if "sqli" in action_id or "sqlmap" in action_id:
        return "SQL Injection"
    if "xss" in action_id:
        return "Cross-Site Scripting"
    if "ssrf" in action_id:
        return "SSRF"
    if "jwt" in action_id or "auth" in action_id:
        return "Authentication Bypass"
    return "Exploitation"


def _remediation_for(action_id: str) -> str:
    return {
        "web.sqli.detect": "Use parameterised queries; the payload was reflected in the response.",
        "web.sqli.blind_detect": "Use parameterised queries; blind injection is confirmed by a differential response.",
        "web.ssrf.oob_detect": "Restrict outbound requests to an allowlist; the server fetched an address we control.",
        "web.ssrf.cloud_metadata": "Block link-local metadata addresses at the egress proxy and require IMDSv2.",
        "auth.jwt.detect": "Pin the algorithm, validate the issuer and audience, and reject `none`.",
        "web.xss.reflected": "Contextually encode output; the payload executed in the response.",
    }.get(action_id, "Review the confirmed behaviour and remediate the root cause.")


def _stringify(value: Any, limit: int = 400) -> str:
    try:
        text = json.dumps(value, default=str)
    except (TypeError, ValueError):
        text = str(value)
    return text if len(text) <= limit else text[:limit] + "…"
