"""Stage 6: LLM-assisted authorized testing plan."""

import json

from agents.attack_planner import AttackPlanner, fallback_plan, render_attack_plan
from core.reporting import build_report_bundle
from modules.base import BaseModule


class LLMAttackPlanner(BaseModule):
    id = "attack_planner"
    name = "LLM Attack Planner"
    stage = 6
    detectability = "low"
    depends_on = ["risk_prioritization"]
    requires_auth = False

    async def run(self) -> str:
        self.log("Building authorized testing plan from OSINT findings...")

        bundle = build_report_bundle(self.state, self.domain)
        planner = AttackPlanner(self.config)
        plan = await planner.build_plan(bundle)
        if not plan.get("top_hypotheses"):
            plan = fallback_plan(bundle)

        json_path = self.state.output_dir / f"{self.domain}_attack_plan.json"
        markdown_path = self.state.output_dir / f"{self.domain}_attack_plan.md"
        json_path.write_text(json.dumps(plan, indent=2, default=str))
        markdown_path.write_text(render_attack_plan(plan, self.domain))

        self.state.add_evidence(
            self.id,
            "attack_plan",
            self.domain,
            {
                "json": str(json_path.relative_to(self.state.output_dir)),
                "markdown": str(markdown_path.relative_to(self.state.output_dir)),
                "hypotheses": len(plan.get("top_hypotheses", [])),
                "module_sequence": plan.get("module_sequence", []),
            },
        )
        self.state.complete_module(self.id)
        self.log(f"Attack plan written to {markdown_path}")
        return "done"
