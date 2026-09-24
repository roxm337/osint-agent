"""Agent Supervisor — orchestrates the multi-agent lifecycle.

Execution runs by default. Pass `engage=False` to preview a dry-run
(plan only, no actions executed). An ROE is optional and, when supplied,
is recorded as engagement metadata; it does not gate execution.
"""

from __future__ import annotations

import json
from pathlib import Path

from agents.base_agent import BaseAgent
from agents.blackboard import Blackboard, AgentRole
from agents.supervisor import SupervisorAgent
from agents.recon_agent import ReconAgent
from agents.vuln_analyst import VulnAnalystAgent
from agents.exploitation_agent import ExploitationAgent
from agents.verification_agent import VerificationAgent
from agents.reporting_agent import ReportingAgent
from core.audit_log import AuditLog
from core.budget_manager import BudgetExceededError
from core.roe import ROE
from state.manager import StateManager


class EngagementGateError(Exception):
    """Raised on unrecoverable engagement faults (e.g. budget exceeded)."""


_EXECUTION_PHASES = {"exploit", "verify"}


class AgentSupervisor:
    """Top-level orchestrator that initializes and runs the multi-agent team."""

    def __init__(self, state: StateManager, config: dict, *,
                 roe: ROE | None = None,
                 engage: bool = True,
                 audit: AuditLog | None = None):
        self.state = state
        self._roe = roe
        self._engage = engage

        # ROE is metadata. It populates scope/exclude lists and marks
        # authorization confirmed; it does not gate execution.
        self.config = roe.enforce(config) if roe is not None else config

        self.bb = Blackboard(state, self.config)
        self.audit = audit or AuditLog(self.state.state_dir / "engagement.audit.jsonl")

        self.agents: dict[str, BaseAgent] = {
            "supervisor": SupervisorAgent(state, self.config, self.bb),
            "recon": ReconAgent(state, self.config, self.bb),
            "vuln_analyst": VulnAnalystAgent(state, self.config, self.bb),
            "exploitation": ExploitationAgent(state, self.config, self.bb),
            "verification": VerificationAgent(state, self.config, self.bb),
            "reporting": ReportingAgent(state, self.config, self.bb),
        }
        for agent in self.agents.values():
            agent.audit = self.audit

    # ── engagement entry points ───────────────────────────────────

    async def run_full_engagement(self) -> dict:
        """Run plan + execution, or a pure dry-run plan if engage=False."""
        target = self.config.get("target", {}).get("domain", "?")
        dry_run = not self._engage
        roe_id = self._roe.to_dict().get("engagement_id", "") if self._roe else ""

        print("\n" + "=" * 60)
        print("  AUTONOMOUS PENTEST ENGAGEMENT")
        print(f"  Target: {target}")
        print(f"  Mode: {'DRY RUN (plan only)' if dry_run else 'EXECUTE'}")
        if roe_id:
            print(f"  ROE: {roe_id}")
        print("=" * 60 + "\n")

        self.audit.engagement_start(target, "agent", roe_id=roe_id, dry_run=dry_run)

        if dry_run:
            return await self._run_dry_run()
        return await self._run_engaged()

    async def run_single_phase(self, phase: str) -> dict:
        target = self.config.get("target", {}).get("domain", "?")
        dry_run = not self._engage
        roe_id = self._roe.to_dict().get("engagement_id", "") if self._roe else ""
        self.audit.engagement_start(target, "phase", roe_id=roe_id, dry_run=dry_run)

        if dry_run and phase in _EXECUTION_PHASES:
            self.audit.record("phase.skipped", {
                "phase": phase, "reason": "dry-run: engage=False",
            })
            print(f"  [{phase}] skipped: dry-run")
            return {"phase": phase, "dry_run": True, "skipped_reason": "engage=False"}

        phase_map = {
            "plan": lambda: self.agents["supervisor"].analyze_and_plan(),
            "recon": lambda: self.agents["recon"].audit_asset_confidence(),
            "vuln": lambda: self.agents["vuln_analyst"].analyze_tech_stack(),
            "exploit": self._run_exploitation_phase,
            "verify": self._run_verification_phase,
            "report": lambda: self.agents["reporting"].generate_submission_package(),
        }
        fn = phase_map.get(phase)
        if fn:
            result = await fn()
            self.audit.record("phase.complete", {"phase": phase})
            return {"phase": phase, "result": result}
        return {"error": f"Unknown phase: {phase}"}

    # ── dry-run ───────────────────────────────────────────────────

    async def _run_dry_run(self) -> dict:
        print("[Plan] Supervisor: analyzing attack surface (dry-run)...")
        plan = await self.agents["supervisor"].analyze_and_plan()
        self.audit.plan(plan)
        targets = self._write_plan_artifacts(plan)

        action_targets = [
            h for h in plan.get("hypotheses", []) if h.get("action_id")
            and h.get("action_id") != "manual_review"
        ]
        print(f"  Plan created: {len(plan.get('hypotheses', []))} hypotheses, "
              f"{len(action_targets)} would execute actions")
        print("  No actions were executed — dry run.")
        print(f"  Plan: {targets['plan_json']}")
        print(f"  Markdown: {targets['plan_md']}")
        print(f"  Dry-run report: {targets['dry_report']}\n")

        summary = {
            "mode": "dry_run",
            "hypotheses_proposed": len(plan.get("hypotheses", [])),
            "actions_would_run": len(action_targets),
            "actions_to_endpoints": [
                {
                    "title": h.get("title"),
                    "action_id": h.get("action_id"),
                    "target": h.get("target"),
                    "assigned_to": h.get("assigned_to"),
                }
                for h in plan.get("hypotheses", []) if h.get("action_id")
            ][:50],
        }
        self.state.save()
        return {"plan": plan, "dry_run": True, "summary": summary}

    # ── engaged ───────────────────────────────────────────────────

    async def _run_engaged(self) -> dict:
        roe_id = self._roe.to_dict().get("engagement_id", "") if self._roe else ""

        # Phase 1: Supervisor analyzes and plans
        print("[Phase 1/5] Supervisor: Analyzing attack surface...")
        plan = await self.agents["supervisor"].analyze_and_plan()
        self.audit.plan(plan)
        print(f"  Plan created: {len(plan.get('hypotheses', []))} hypotheses\n")

        # Phase 2: Vuln Analyst maps tech to CVEs
        print("[Phase 2/5] Vuln Analyst: Mapping technologies to vulnerabilities...")
        vuln_candidates = await self.agents["vuln_analyst"].analyze_tech_stack()
        vuln_candidates = vuln_candidates or []
        if vuln_candidates:
            for vc in vuln_candidates[:5]:
                tech = vc.get("technology", "?")
                score = vc.get("score", 0)
                kev = len(vc.get("kev", []))
                print(f"  {tech}: CVSS {score:.1f}" + (f", {kev} KEV matches" if kev else ""))
        print()

        # Phase 3: Recon fills gaps
        print("[Phase 3/5] Recon Agent: Auditing asset confidence...")
        low_conf = await self.agents["recon"].audit_asset_confidence()
        if low_conf:
            print(f"  {len(low_conf)} low-confidence assets identified for re-probe")
        print()

        # Phase 4: Exploitation tests hypotheses
        print("[Phase 4/5] Exploitation Agent: Testing hypotheses...")
        hypotheses = self.bb.get_hypotheses(status="proposed")
        exploitation = self.agents["exploitation"]
        for hyp in hypotheses[:10]:
            self._check_budget(exploitation)
            print(f"  Testing: {hyp.title[:60]}...", end=" ")
            result = await exploitation.test_hypothesis(hyp)
            if result.get("success"):
                print(f"✓ ({result.get('confidence', 'FIRM')})")
            else:
                print(f"✗ ({result.get('error', 'failed')[:40]})")
            self.audit.record("hypothesis.tested", {
                "hypothesis_id": hyp.id,
                "action_id": hyp.action_id,
                "success": result.get("success"),
                "confidence": result.get("confidence", ""),
                "error": str(result.get("error", ""))[:300],
            })
        print()

        # Phase 5: Verification confirms findings
        print("[Phase 5/5] Verification Agent: Confirming findings...")
        to_verify = [
            h for h in self.bb.get_hypotheses()
            if h.status in ("testing", "confirmed")
        ]
        verification = self.agents["verification"]
        for hyp in to_verify[:10]:
            self._check_budget(verification)
            print(f"  Verifying: {hyp.title[:60]}...", end=" ")
            result = await verification.verify_finding(hyp)
            status = result.get("status", "?")
            print(f"✓ ({status})" if result.get("success") else f"✗ ({status})")
            self.audit.record("hypothesis.verified", {
                "hypothesis_id": hyp.id,
                "status": status,
                "success": result.get("success"),
            })
        print()

        # Report generation
        report = await self.agents["reporting"].generate_submission_package()
        confirmed_final = [h for h in self.bb.get_hypotheses() if h.status == "confirmed"]
        rejected = [h for h in self.bb.get_hypotheses() if h.status == "rejected"]

        # Summary
        print("=" * 60)
        print("  ENGAGEMENT COMPLETE")
        print(f"  Hypotheses proposed: {len(self.bb.get_hypotheses())}")
        print(f"  Confirmed: {len(confirmed_final)}")
        print(f"  Rejected: {len(rejected)}")
        print(f"  Vuln candidates identified: {len(vuln_candidates)}")
        print("=" * 60 + "\n")

        summary = {
            "mode": "engaged",
            "roe_id": roe_id,
            "hypotheses_proposed": len(self.bb.get_hypotheses()),
            "confirmed_findings": len(confirmed_final),
            "rejected_hypotheses": len(rejected),
            "vuln_candidates": len(vuln_candidates),
        }
        self.audit.record("engagement.summary", summary)
        self.state.save()

        return {
            "plan": plan,
            "vuln_candidates": vuln_candidates,
            "confirmed_findings": len(confirmed_final),
            "rejected_hypotheses": len(rejected),
            "report": report,
            "summary": summary,
            "hypotheses": [{"id": h.id, "title": h.title, "status": h.status}
                          for h in self.bb.get_hypotheses()],
        }

    # ── helpers ───────────────────────────────────────────────────

    def _write_plan_artifacts(self, plan: dict) -> dict:
        report_dir = Path(self.state.output_dir)
        report_dir.mkdir(parents=True, exist_ok=True)
        domain = self.config.get("target", {}).get("domain", "target")

        plan_json = report_dir / f"{domain}_attack_plan.json"
        plan_md = report_dir / f"{domain}_attack_plan.md"
        dry_report = report_dir / f"{domain}_dry_run_report.json"

        plan_json.write_text(json.dumps(plan, indent=2, default=str))
        plan_md.write_text(_render_plan_markdown(plan, domain))
        dry_report.write_text(json.dumps({
            "mode": "dry_run",
            "target": domain,
            "roe_id": self._roe.to_dict().get("engagement_id", "") if self._roe else "",
            "plan": plan,
            "note": "Dry-run artifact. No actions were executed against the target.",
        }, indent=2, default=str))

        return {"plan_json": plan_json, "plan_md": plan_md, "dry_report": dry_report}

    def _check_budget(self, agent: BaseAgent):
        try:
            agent.budget.check()
        except BudgetExceededError as exc:
            self.audit.budget(agent.budget.summary())
            self.audit.record("engagement.abort", {"reason": str(exc)})
            raise EngagementGateError(str(exc)) from exc

    async def _run_exploitation_phase(self) -> list:
        results = []
        for hyp in self.bb.get_hypotheses(status="proposed"):
            result = await self.agents["exploitation"].test_hypothesis(hyp)
            results.append({"hypothesis": hyp.id, "result": result})
        return results

    async def _run_verification_phase(self) -> list:
        results = []
        for hyp in self.bb.get_hypotheses(status="testing"):
            result = await self.agents["verification"].verify_finding(hyp)
            results.append({"hypothesis": hyp.id, "result": result})
        return results


def _render_plan_markdown(plan: dict, domain: str) -> str:
    lines = [
        f"# Authorized Testing Plan: {domain}",
        "",
        f"Focus: {plan.get('focus', '-')}",
        "",
        "## Hypotheses",
        "",
    ]
    for i, h in enumerate(plan.get("hypotheses", []), 1):
        lines += [
            f"### {i}. {h.get('title', 'Untitled')}",
            "",
            f"- **Description:** {h.get('description', '-')}",
            f"- **Likelihood:** {h.get('likelihood', '-')}",
            f"- **Impact:** {h.get('impact', '-')}",
            f"- **Target:** `{h.get('target', '-')}`",
            f"- **Technique:** {h.get('technique', '-')}",
            f"- **Action ID:** `{h.get('action_id', 'manual_review') or 'manual_review'}`",
            f"- **Assigned to:** {h.get('assigned_to', '-')}",
            "",
        ]
    lines += ["## Module Sequence", ""]
    for m in plan.get("module_sequence", []):
        lines.append(f"- `{m}`")
    lines += ["", "## Watch Items", ""]
    for w in plan.get("watch_items", []):
        lines.append(f"- {w}")
    lines.append("")
    return "\n".join(lines)