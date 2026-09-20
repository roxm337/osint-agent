"""Vuln Analyst Agent — maps technologies to CVEs, retrieves test procedures, scores risk."""

from __future__ import annotations

from agents.base_agent import BaseAgent
from agents.blackboard import AgentRole


VULN_ANALYST_SYSTEM_PROMPT = """You are a vulnerability analyst. Given a technology stack and OSINT findings:

1. Map each detected technology + version to known CVEs
2. Prioritize: KEV entries > EPSS >= 0.5 > CVSS >= 7.0
3. Bind each CVE to a test method in priority order:
   a. nuclei template exists -> run template
   b. Metasploit module exists -> check mode
   c. public PoC exists -> sandboxed run
   d. none of above -> describe manual test procedure
4. Score each candidate: CVSS × EPSS × KEV × exposure

Return structured, testable hypotheses about what vulnerabilities likely exist
and how to confirm them.
"""


class VulnAnalystAgent(BaseAgent):
    role = AgentRole.VULN_ANALYST

    async def analyze_tech_stack(self) -> list[dict]:
        """Analyze detected technologies for vulnerability candidates."""
        self.log("Analyzing technology stack for vulnerabilities...")

        webapps = self.state.get_assets_by_type("webapp")
        techs = []
        for app in webapps:
            attrs = app.get("attrs", {})
            for key in ("cms", "server", "framework", "php_version"):
                val = attrs.get(key, "")
                if val and val != "unknown" and val not in techs:
                    techs.append(val)
            for plugin in attrs.get("plugins", []) or []:
                techs.append(f"wordpress {plugin}")

        if not techs:
            self.log("No technologies detected to analyze")
            return []

        # Check NVD + KEV + EPSS for each tech
        candidates = []
        for tech in techs[:10]:
            candidate = await self._lookup_cve(tech)
            if candidate:
                candidates.append(candidate)
                self.bb.send(
                    self.role, AgentRole.SUPERVISOR,
                    "hypothesis_candidate",
                    payload=candidate,
                )

        self.log(f"Found {len(candidates)} vulnerability candidates across {len(techs)} techs")
        return candidates

    async def _lookup_cve(self, tech: str) -> dict | None:
        """Check NVD + CISA KEV for a technology."""
        from modules.exploit_lookup import nvd_cve_search, check_cisa_kev

        cves = await nvd_cve_search(tech, results_per_page=5)
        kev_matches = await check_cisa_kev([tech])

        if not cves and not kev_matches:
            return None

        return {
            "technology": tech,
            "cves": [
                {"id": c["id"], "cvss": c.get("cvss_score", 0),
                 "description": c.get("description", "")[:150]}
                for c in cves[:5]
            ],
            "kev": kev_matches[:3],
            "score": max(
                max((c.get("cvss_score", 0) for c in cves), default=0),
                9.0 if kev_matches else 0,
            ),
        }

    async def build_test_plan(self, vuln_candidates: list[dict]) -> list[dict]:
        """Build a plan of actions to test each vulnerability candidate."""
        self.log("Building test plans for vulnerability candidates...")

        test_plans = []
        for candidate in vuln_candidates:
            tech = candidate.get("technology", "")
            best_action = self._action_for_tech(tech)
            test_plans.append({
                "tech": tech,
                "action_id": best_action,
                "params": {"url": "", "param": ""},
                "confidence": "FIRM" if candidate.get("kev") else "TENTATIVE",
            })

        return test_plans

    def _action_for_tech(self, tech: str) -> str:
        tech_lower = tech.lower()
        if "sql" in tech_lower or any(db in tech_lower for db in ("mysql", "postgres", "mssql", "oracle")):
            return "web.sqli.detect"
        if "wp" in tech_lower or "wordpress" in tech_lower:
            return "web.xss.reflected"
        return ""
