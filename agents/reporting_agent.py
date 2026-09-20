"""Reporting Agent — generates structured findings, PoC writeups, and executive summaries."""

from agents.base_agent import BaseAgent
from agents.blackboard import AgentRole


REPORTING_SYSTEM_PROMPT = """You are a penetration testing report writer. Given confirmed findings, exploit chains, and evidence:

1. Generate submission-ready writeups per finding
2. Include: title, severity, CVSS vector, description, reproduction steps, impact, remediation
3. Structure for bug bounty platform formats (HackerOne, Bugcrowd, Intigriti)
4. Produce an executive summary for non-technical stakeholders

Every finding must reference: asset, technique, payload, evidence, proof-of-concept.
"""


class ReportingAgent(BaseAgent):
    role = AgentRole.REPORTING

    async def generate_finding_writeup(self, hypothesis_id: str) -> dict:
        """Generate a submission-ready writeup for a confirmed finding."""
        hyp = None
        for h in self.bb.hypotheses:
            if h.id == hypothesis_id:
                hyp = h
                break
        if not hyp or hyp.status != "confirmed":
            return {"error": "hypothesis not confirmed", "id": hypothesis_id}

        self.log(f"Generating writeup for: {hyp.title}")

        prompt = (
            f"Generate a bug bounty submission writeup for this finding:\n\n"
            f"Title: {hyp.title}\n"
            f"Description: {hyp.description}\n"
            f"Target: {hyp.target}\n"
            f"Technique: {hyp.technique}\n"
            f"Likelihood: {hyp.likelihood}, Impact: {hyp.impact}\n"
            f"Evidence: {hyp.evidence_refs}\n"
            f"Result: {hyp.result}\n\n"
            f"Format: title, severity, description, reproduction steps (numbered), "
            f"impact, remediation, references."
        )

        response = await self._llm_call(REPORTING_SYSTEM_PROMPT, prompt,
                                         temperature=0.3, max_tokens=2000)

        return {
            "id": hyp.id,
            "title": hyp.title,
            "writeup": response or "Error generating writeup",
            "status": hyp.status,
        }

    async def generate_executive_summary(self) -> str:
        """Generate an executive summary of all confirmed findings."""
        confirmed = [h for h in self.bb.hypotheses if h.status == "confirmed"]
        rejected = [h for h in self.bb.hypotheses if h.status == "rejected"]

        summary = self._build_state_context()
        prompt = (
            f"Generate a one-page executive summary for this engagement:\n\n"
            f"Current state:\n{summary}\n\n"
            f"Confirmed findings ({len(confirmed)}):\n"
            + "\n".join(f"  - {h.title} ({h.technique}, {h.likelihood * h.impact:.0%})" for h in confirmed)
            + f"\n\nRejected hypotheses ({len(rejected)}):\n"
            + "\n".join(f"  - {h.title}" for h in rejected)
            + "\n\nFormat: one-paragraph context, bullet list of findings, risk overview, recommended next steps."
        )

        response = await self._llm_call(REPORTING_SYSTEM_PROMPT, prompt,
                                         temperature=0.3, max_tokens=2000)
        return response or "Error generating summary"

    async def generate_submission_package(self) -> dict:
        """Generate full submission package (writeups + evidence + summary)."""
        self.log("Generating full submission package...")

        confirmed = [h for h in self.bb.hypotheses if h.status == "confirmed"]
        writeups = []
        for h in confirmed:
            w = await self.generate_finding_writeup(h.id)
            writeups.append(w)

        summary = await self.generate_executive_summary()

        return {
            "executive_summary": summary,
            "findings": writeups,
            "total_confirmed": len(confirmed),
        }
