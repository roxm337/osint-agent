"""Recon-Refine Agent — fills OSINT gaps, re-probes stale assets, confirms tech versions."""

from agents.base_agent import BaseAgent
from agents.blackboard import AgentRole


RECON_SYSTEM_PROMPT = """You are a reconnaissance specialist. Your job is to refine OSINT data by:

1. Confirming version details for detected technologies
2. Re-probing assets with stale or low-confidence data
3. Filling gaps: missing subdomains, tech on new assets, email patterns
4. Preparing enrichment data before exploitation begins

You have access to:
- All 40+ OSINT modules (stages 1-4)
- The asset graph with typed nodes and confidence levels
- The findings database

When asked to investigate a target:
- Check what's already known (confidence, sources, last seen)
- Pick the right OSINT module to fill the gap
- Return structured findings about new or updated assets
"""


class ReconAgent(BaseAgent):
    role = AgentRole.RECON

    async def refine_target(self, target: str, tech: str = "") -> dict:
        """Refine OSINT data for a specific target/technology."""
        self.log(f"Refining recon for {target} (tech: {tech or 'any'})")

        context = self._build_state_context()
        prompt = (
            f"Target to refine: {target}\n"
            f"Technology: {tech or 'unknown'}\n\n"
            f"Current state:\n{context}\n\n"
            f"Which OSINT module should run next to fill gaps? "
            f"Respond with RUN_MODULE: <module_id> or COMPLETE if no gaps."
        )

        response = await self._llm_call(RECON_SYSTEM_PROMPT, prompt,
                                         temperature=0.1, max_tokens=500)
        decision = self._parse_decision(response)
        return {"target": target, "action": decision}

    async def confirm_version(self, url: str, tech: str) -> dict:
        """Attempt to confirm the version of a detected technology."""
        self.log(f"Confirming version: {tech} at {url}")
        # Try tech_detection module for fingerprinting
        from modules.tech_detect import TechDetection
        from state.manager import StateManager
        module = TechDetection(self.state, self.config)
        result = await module.run()

        return {"tech": tech, "url": url, "result": result}

    def _parse_decision(self, response: str | None) -> str:
        if not response:
            return "COMPLETE"
        for line in response.split("\n"):
            line = line.strip().lower()
            if line.startswith("run_module:"):
                return line
            if line in ("complete", "done", "finished"):
                return "COMPLETE"
        return "COMPLETE"

    async def audit_asset_confidence(self) -> list:
        """Audit all assets and identify low-confidence entries needing re-probe."""
        low_conf = []
        for node in self.state.assets.get("nodes", []):
            if node.get("confidence") in ("TENTATIVE", None):
                low_conf.append({
                    "key": node["key"],
                    "type": node["type"],
                    "value": node["value"],
                    "sources": node.get("sources", []),
                })
        return low_conf[:20]
