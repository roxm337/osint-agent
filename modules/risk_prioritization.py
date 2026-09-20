"""Stage 5: Normalize and prioritize findings before reporting."""

from core.prioritization import prioritize_findings
from modules.base import BaseModule


class RiskPrioritization(BaseModule):
    id = "risk_prioritization"
    name = "Risk Prioritization"
    stage = 6
    detectability = "low"
    depends_on = []

    async def run(self) -> str:
        findings = self.state.findings.get("findings", [])
        if not findings:
            self.state.skip_module(self.id, "no findings")
            return "skipped"

        scoring_config = self.config.get("scoring", {})
        prioritized = prioritize_findings(findings, scoring_config)
        self.state.findings["findings"] = prioritized

        top = prioritized[0]
        self.state.add_evidence(
            self.id,
            "priority_summary",
            self.domain,
            {
                "findings": len(prioritized),
                "top_finding": {
                    "id": top.get("id"),
                    "title": top.get("title"),
                    "risk_score": top.get("risk_score"),
                    "priority": top.get("priority"),
                    "severity": top.get("severity"),
                },
            },
        )
        self.state.complete_module(self.id)
        self.log(
            f"Prioritized {len(prioritized)} finding(s); "
            f"top risk {top.get('risk_score', 0)}/100"
        )
        return "done"
