"""Agent Supervisor — orchestrates the multi-agent lifecycle."""

from __future__ import annotations

from agents.base_agent import BaseAgent
from agents.blackboard import Blackboard, AgentRole
from agents.supervisor import SupervisorAgent
from agents.recon_agent import ReconAgent
from agents.vuln_analyst import VulnAnalystAgent
from agents.exploitation_agent import ExploitationAgent
from agents.verification_agent import VerificationAgent
from agents.reporting_agent import ReportingAgent
from state.manager import StateManager


class AgentSupervisor:
    """Top-level orchestrator that initializes and runs the multi-agent team."""

    def __init__(self, state: StateManager, config: dict):
        self.state = state
        self.config = config
        self.bb = Blackboard(state, config)

        # Initialize all agents
        self.agents: dict[str, BaseAgent] = {
            "supervisor": SupervisorAgent(state, config, self.bb),
            "recon": ReconAgent(state, config, self.bb),
            "vuln_analyst": VulnAnalystAgent(state, config, self.bb),
            "exploitation": ExploitationAgent(state, config, self.bb),
            "verification": VerificationAgent(state, config, self.bb),
            "reporting": ReportingAgent(state, config, self.bb),
        }

    async def run_full_engagement(self) -> dict:
        """Run the full autonomous pentesting engagement."""
        print("\n" + "=" * 60)
        print("  AUTONOMOUS PENTEST ENGAGEMENT")
        print(f"  Target: {self.config.get('target', {}).get('domain', '?')}")
        print("=" * 60 + "\n")

        # Phase 1: Supervisor analyzes and plans
        print("[Phase 1/5] Supervisor: Analyzing attack surface...")
        plan = await self.agents["supervisor"].analyze_and_plan()
        print(f"  Plan created: {len(plan.get('hypotheses', []))} hypotheses\n")

        # Phase 2: Vuln Analyst maps tech to CVEs
        print("[Phase 2/5] Vuln Analyst: Mapping technologies to vulnerabilities...")
        vuln_candidates = await self.agents["vuln_analyst"].analyze_tech_stack()
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
            print(f"  Testing: {hyp.title[:60]}...", end=" ")
            result = await exploitation.test_hypothesis(hyp)
            if result.get("success"):
                print(f"✓ ({result.get('confidence', 'FIRM')})")
            else:
                print(f"✗ ({result.get('error', 'failed')[:40]})")
        print()

        # Phase 5: Verification confirms findings — run on any tested hypothesis
        print("[Phase 5/5] Verification Agent: Confirming findings...")
        to_verify = [
            h for h in self.bb.get_hypotheses()
            if h.status in ("testing", "confirmed")
        ]
        verification = self.agents["verification"]
        for hyp in to_verify[:10]:
            print(f"  Verifying: {hyp.title[:60]}...", end=" ")
            result = await verification.verify_finding(hyp)
            status = result.get("status", "?")
            print(f"✓ ({status})" if result.get("success") else f"✗ ({status})")
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
        print(f"  Low-confidence assets: {len(low_conf)}")
        print("=" * 60 + "\n")

        return {
            "plan": plan,
            "vuln_candidates": vuln_candidates,
            "confirmed_findings": len(confirmed_final),
            "rejected_hypotheses": len(rejected),
            "report": report,
            "hypotheses": [{"id": h.id, "title": h.title, "status": h.status}
                          for h in self.bb.get_hypotheses()],
        }

    async def run_single_phase(self, phase: str) -> dict:
        """Run a single phase by name."""
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
            return {"phase": phase, "result": await fn()}
        return {"error": f"Unknown phase: {phase}"}

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
