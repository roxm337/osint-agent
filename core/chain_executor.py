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
from urllib.parse import parse_qsl, urlparse

from actions.registry import ActionRegistry, RiskLevel
from core.attack_graph import AttackEdge
from core.validators import inject_param

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


def _reason_rank(reason: str) -> int:
    """Run vuln-driven edges before generic probes.

    An edge carrying a declared action or a vuln-category match names a
    specific suspected flaw; an "edge type" fallback is a surface with a
    generic probe. When the budget only covers some of them, the
    specific suspicion must spend first.
    """
    text = str(reason or "")
    if text.startswith("declared on edge"):
        return 0
    if text.startswith("vuln category"):
        return 1
    return 2


# Which action can prove which kind of edge. Ordered by preference: the first
# registered action that exists, is under the ceiling, and whose required
# params we can actually satisfy wins.
#
# Note verify.differential is deliberately not first for `extract`: it needs
# both baseline_url and test_url, which the graph does not supply, so listing
# it first made every extract edge fail on a missing param.
#
# Note `extract` is deliberately EMPTY: re-fetching a reachable URL proves
# reachability, not vulnerability (verify.reproducible's CONFIRMED-on-200
# filed seventeen junk findings that way). Extract edges with a vuln
# category still resolve through CATEGORY_ACTIONS below; the rest are
# recorded as unarmable instead of spending budget on re-reads.
EDGE_ACTIONS: dict[str, list[str]] = {
    "exploit": [
        "web.sqli.detect",
        "web.sqli.blind_detect",
        "web.xss.reflected",
    ],
    "pivot": [
        "web.ssrf.oob_detect",
        "web.ssrf.cloud_metadata",
    ],
    "extract": [],
    "authenticate": [
        "auth.jwt.none_alg",
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
    ("redirect", "web.redirect.probe"),
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
    params: dict = field(default_factory=dict)


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
    unarmable: list[EdgeOutcome] = field(default_factory=list)

    @property
    def proven(self) -> int:
        return sum(1 for o in self.ran if o.finding_id)

    def summary(self) -> str:
        parts = [f"{self.proven} proven", f"{len(self.blocked)} blocked by risk",
                 f"{len(self.skipped)} skipped"]
        if self.unarmable:
            parts.append(f"{len(self.unarmable)} unarmable")
        return ", ".join(parts)


class ChainExecutor:
    """Runs chain edges for real, under a risk ceiling and a budget."""

    def __init__(self, state, config: Optional[dict] = None,
                 budget=None, audit=None,
                 max_risk: RiskLevel = RiskLevel.LOW,
                 max_actions: int = 25,
                 module_id: str = "chain_executor"):
        self.state = state
        self.config = config or {}
        self.budget = budget
        self.audit = audit
        self.max_risk = max_risk
        self.max_actions = max(0, int(max_actions))
        self.module_id = module_id or "chain_executor"
        self._used = 0
        # Edges we recognised but could not arm, so the operator can see that
        # coverage was limited instead of assuming the run was exhaustive.
        self.unarmable: list[EdgeOutcome] = []

    # ── planning ──────────────────────────────────────────────────

    def plan(self, chain) -> list[PlannedEdge]:
        """Choose, for each edge in a chain, the action that can prove it.

        An action is only planned if we can satisfy every parameter it declares
        in `ActionMeta.requires`. Checking that here rather than at call time is
        the point: a missing param raised as a KeyError inside the action looks
        exactly like "target not vulnerable" in the report, which is how a
        broken executor talks you into a false negative.
        """
        planned = []
        for edge in chain.edges:
            candidates = self._select_action(edge, chain)
            if not candidates:
                if edge.edge_type in EDGE_ACTIONS:
                    # A known edge type with no proving action (extract):
                    # say so out loud instead of dropping it silently or,
                    # worse, spending budget re-proving reachability.
                    self.unarmable.append(EdgeOutcome(
                        edge=edge, action_id="", status="no_action",
                        detail=f"no proving action registered for "
                               f"'{edge.edge_type}' edges"))
                continue

            # Pick the first candidate we can actually arm, not merely the first
            # one that exists. verify.differential needs two URLs, so on a plain
            # URL it is unusable and must not be chosen over a real probe.
            chosen = None
            first_failure = None
            for action_id, reason in candidates:
                entry = ActionRegistry.get(action_id)
                if not entry:
                    continue
                meta, _ = entry
                params, missing = self._build_params(edge, chain, meta)
                if not missing and params.get("url"):
                    chosen = (action_id, reason, meta, params)
                    break
                if first_failure is None:
                    first_failure = (action_id, reason, missing or ["url"])

            if chosen is None:
                # Remember the edges we could not arm, so the operator learns
                # that coverage was limited rather than assuming a clean run.
                action_id, reason, missing = first_failure
                self.unarmable.append(EdgeOutcome(
                    edge=edge, action_id=action_id, status="no_action",
                    detail=reason + " — cannot supply " + ", ".join(missing)))
                continue

            action_id, reason, meta, params = chosen
            risk = getattr(meta.risk, "value", meta.risk)
            planned.append(PlannedEdge(
                edge=edge, action_id=action_id, risk=str(risk),
                url=params["url"], reason=reason, params=params))
        return planned

    def _build_params(self, edge: AttackEdge, chain, meta):
        """Work out the arguments an action needs, from what the graph knows.

        Returns (params, missing) where `missing` names the required parameters
        we could not fill in. The graph is thin: a `parameter` node knows its
        own name and the URL it belongs to, a `url` node only knows its URL, and
        a `vuln` node knows the category and nothing about where to send
        anything. So most edges can supply url+param and little else.
        """
        params: dict[str, Any] = {}
        nodes = [n for n in (self._node(edge.source_id, chain),
                             self._node(edge.target_id, chain))
                 if n is not None]

        url = ""
        param = ""
        for node in nodes:
            attrs = node.attrs or {}
            if not url:
                for key in ("url", "value", "endpoint"):
                    candidate = str(attrs.get(key, "")).strip()
                    if candidate.startswith(("http://", "https://")):
                        url = candidate
                        break
                if not url and str(node.label or "").startswith(
                        ("http://", "https://")):
                    url = str(node.label).strip()
            if not param:
                if str(node.node_type) == "parameter":
                    # A parameter asset's label IS the parameter name.
                    param = str(node.label or "").strip()
                elif attrs.get("param"):
                    param = str(attrs["param"]).strip()
                elif attrs.get("name") and str(attrs.get("name")):
                    param = str(attrs["name"]).strip()

        if url and not param:
            # A URL like https://h/s?a=1 tells us the parameter name.
            query = urlparse(url).query
            if query:
                first = parse_qsl(query)
                param = first[0][0] if first else ""

        # Mirror `AttackGraph._surface`: an object reference names its id in
        # the path segment, not the query string. The two must agree — if the
        # graph proposes a probe the executor cannot arm, the report says
        # "planned" and means "unarmable", which is worse than saying neither.
        if url and not param:
            template = ""
            for node in nodes:
                template = str((node.attrs or {}).get("template") or "")
                if template:
                    break
            if "{id}" in template:
                param = "id"

        if url:
            params["url"] = url
        if param:
            params["param"] = param
        token = ""
        for node in nodes:
            token = str((node.attrs or {}).get("token", "")).strip()
            if token:
                break
        if token:
            params["token"] = token

        # Two-URL oracles: baseline is the same request with a benign value,
        # test is the one carrying the payload. `inject_param` tolerates a
        # parameter that is not yet present, so this is safe to build.
        if "baseline_url" in getattr(meta, "requires", []) and url and param:
            params["baseline_url"] = inject_param(url, param, "1")
            params.setdefault("test_url", inject_param(url, param, "'"))
        if "urls" in getattr(meta, "requires", []) and url:
            params["urls"] = [url]

        missing = [r for r in getattr(meta, "requires", []) if not params.get(r)]
        return params, missing

    @staticmethod
    def _node(node_id, chain):
        """Find a node in a chain, whether it stores nodes as a list or a map.

        `AttackPath.nodes` is a `list[AttackNode]`, so `.get()` on it raises
        `AttributeError` rather than returning None. That made every chain
        built by `find_chains` fail at `_select_action`, which is the first
        thing execution does — so no chain could ever be armed, and the error
        surfaced as a crash instead of a skipped probe.

        Both shapes are accepted because this function is also used with
        hand-built stand-ins in tests, and a helper that only works for one of
        them is how the disagreement stayed invisible.
        """
        nodes = getattr(chain, "nodes", None)
        if nodes is None:
            return None
        if isinstance(nodes, dict):
            return nodes.get(node_id)
        for node in nodes:
            if getattr(node, "id", None) == node_id:
                return node
        return None

    def _select_action(self, edge: AttackEdge, chain) -> list:
        """Candidate actions to prove this edge, best first.

        Returns a list of (action_id, reason) so the caller can fall through to
        the next candidate if the preferred one cannot be armed with the data
        the graph actually has.
        """
        candidates = []
        if edge.action_id and ActionRegistry.get(edge.action_id):
            candidates.append((edge.action_id, "declared on edge"))

        target = self._node(edge.target_id, chain)
        category = ""
        if target is not None:
            category = str((target.attrs or {}).get("category", "")).lower()

        if category:
            for token, action_id in CATEGORY_ACTIONS:
                if token in category and ActionRegistry.get(action_id):
                    candidates.append((action_id, f"vuln category '{category}'"))
                    break

        for action_id in EDGE_ACTIONS.get(edge.edge_type, []):
            if ActionRegistry.get(action_id):
                candidates.append((action_id, f"edge type '{edge.edge_type}'"))

        # Deduplicate, keeping the earliest (strongest) reason for each action.
        seen = set()
        unique = []
        for action_id, reason in candidates:
            if action_id not in seen:
                seen.add(action_id)
                unique.append((action_id, reason))
        return unique

    # ── execution ─────────────────────────────────────────────────

    async def execute(self, chains, max_chains: int = 10) -> ExecutionReport:
        report = ExecutionReport()
        # Execution runs outside any module run, so without this the proven
        # findings were tagged with an empty module id — orphaned from every
        # module view — and every re-run stacked a fresh copy next to the
        # stale ones. Prune our own previous claims, tag the new ones.
        previous_current = self.state.module.get("current")
        self.state.prune_module_findings(self.module_id)
        self.state.module["current"] = self.module_id
        try:
            for chain in list(chains)[:max_chains]:
                # Vuln-driven edges (declared action, category match) run
                # before generic probes: without this ordering one probe
                # family (open redirects on every surface) spends the
                # whole budget while the SQLi that matters never runs.
                planned_edges = sorted(
                    self.plan(chain),
                    key=lambda item: _reason_rank(item.reason))
                for planned in planned_edges:
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
        finally:
            self.state.module["current"] = previous_current
        report.unarmable = list(self.unarmable)
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
            params=dict(planned.params),
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
            # The proof, not just the claim. A verified finding that does not
            # record which url, which parameter and what the action actually
            # returned is not reportable: the title is the only place the
            # target appeared, and `url`/`param` were being dropped on the
            # floor, so a triager had nothing to reproduce from.
            verification={
                "action_id": planned.action_id,
                "selected_because": planned.reason,
                "url": planned.url,
                "param": planned.params.get("param", ""),
                "params": {k: v for k, v in planned.params.items()
                           if k in ("url", "param", "baseline_url", "test_url")},
                "risk": planned.risk,
                "raw_evidence": evidence,
            },
        )
        return EdgeOutcome(
            edge=planned.edge, action_id=planned.action_id, status="ran",
            finding_id=finding_id, confidence=confidence, impact=impact,
            evidence=evidence,
        )


def _severity_for(edge: AttackEdge, evidence: dict) -> str:
    """Impact edge, from the graph's own impact score — not from sniffing
    the evidence text for words like "admin". Substring severity was
    inflation by vocabulary: any finding mentioning a token became HIGH.
    """
    if edge.impact >= 0.85:
        return "HIGH"
    if edge.impact >= 0.6:
        return "MEDIUM"
    return "LOW"


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
