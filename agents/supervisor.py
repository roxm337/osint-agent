"""Supervisor Agent — top-level planner that creates hypotheses and delegates tasks."""

from __future__ import annotations

from agents.base_agent import BaseAgent
from agents.blackboard import AgentRole, Hypothesis
from core.attack_graph import AttackPath


SUPERVISOR_SYSTEM_PROMPT = """You are a senior penetration testing lead. You receive OSINT findings and an attack graph showing potential exploit paths. Your job:

1. Analyze the attack graph and identify the most promising exploit chains
2. Formulate testable hypotheses about vulnerabilities
3. Assign tasks to specialized agents

Priority rules:
- Prefer chains with confirmed assets + FIRM/CONFIRMED findings
- Passively confirmed vulns (CVE lookup, tech detection) before active probing
- Order by likelihood × impact
- Never suggest destructive or out-of-scope actions

Available agents and when to use them:
- recon: when you need gap-filling OSINT (version confirmation, stale assets)
- vuln_analyst: when you need CVE mapping, test procedure retrieval
- exploitation: when you have a strong hypothesis ready to test
- verification: after exploitation returns evidence, to confirm deterministically
"""

BUILD_PLAN_PROMPT = """Current investigation state:
{state_context}

Attack graph has {node_count} nodes and {edge_count} edges with {chain_count} exploit chains.

Top exploit chains:
{chains}

Hypotheses already proposed:
{existing_hypotheses}

Available pentesting actions:
{available_actions}

Return only valid JSON. For each hypothesis, action_id must be one of the
catalog action_id values above, or "manual_review" when no safe action exists.
Do not invent action ids.

Return a JSON plan:
{{
  "focus": "short strategic focus",
  "hypotheses": [
    {{
      "title": "hypothesis title",
      "description": "evidence-based reasoning",
      "likelihood": 0.0-1.0,
      "impact": 0.0-1.0,
      "target": "specific target URL/IP",
      "technique": "attack technique name",
      "action_id": "best action to test this (or 'manual_review')",
      "assigned_to": "recon | vuln_analyst | exploitation | verification"
    }}
  ],
  "module_sequence": ["module_ids to run first"],
  "watch_items": ["things to avoid"]
}}
"""


class SupervisorAgent(BaseAgent):
    role = AgentRole.SUPERVISOR

    async def analyze_and_plan(self) -> dict:
        """Build plan from current state and attack graph."""
        self.refresh_attack_graph()
        chains = self.find_chains()

        state_ctx = self._build_state_context()
        chain_text = self._format_chains(chains)
        hyp_text = self._format_hypotheses()
        action_text = self._format_actions()

        prompt = BUILD_PLAN_PROMPT.format(
            state_context=state_ctx,
            node_count=len(self.attack_graph.nodes) if self.attack_graph else 0,
            edge_count=len(self.attack_graph.edges) if self.attack_graph else 0,
            chain_count=len(chains),
            chains=chain_text,
            existing_hypotheses=hyp_text,
            available_actions=action_text,
        )

        response = await self._llm_call(SUPERVISOR_SYSTEM_PROMPT, prompt,
                                         temperature=0.2, max_tokens=3000)

        # Always generate the deterministic fallback plan (path-based hints always included)
        fallback = self._fallback_plan(chains)

        # Parse LLM response if available
        llm_plan = self._parse_plan(response) if response else None

        # Merge: deterministic fallback always wins, LLM adds supplementary hypotheses
        merged_hypotheses = list(fallback.get("hypotheses", []))
        seen_titles = {h["title"] for h in merged_hypotheses}
        valid_action_ids = self._valid_action_ids()

        if llm_plan:
            for h_data in llm_plan.get("hypotheses", []):
                action_id = h_data.get("action_id", "")
                if action_id and action_id not in valid_action_ids and action_id != "manual_review":
                    h_data["action_id"] = "manual_review"
                title = h_data.get("title", "")
                # Keep first occurrence for duplicate titles
                if title not in seen_titles:
                    merged_hypotheses.append(h_data)
                    seen_titles.add(title)

        plan = {
            "focus": fallback.get(
                "focus",
                (llm_plan or {}).get("focus", "Testing target"),
            ),
            "hypotheses": merged_hypotheses[:10],
            "module_sequence": fallback.get("module_sequence", []),
            "watch_items": fallback.get("watch_items", ["Stay in scope"]),
        }

        self.bb.set_plan(plan)

        # Register hypotheses from plan
        for h_data in plan.get("hypotheses", []):
            hyp = Hypothesis(
                id=f"HYP-{len(self.bb.hypotheses) + 1:04d}",
                title=h_data.get("title", "Untitled"),
                description=h_data.get("description", ""),
                likelihood=h_data.get("likelihood", 0.5),
                impact=h_data.get("impact", 0.5),
                target=h_data.get("target", ""),
                technique=h_data.get("technique", ""),
                action_id=h_data.get("action_id", ""),
                status="proposed",
                created_by=self.role.value,
            )
            self.bb.add_hypothesis(hyp)

        self.log(f"Plan built: {len(plan.get('hypotheses', []))} hypotheses, "
                 f"{len(chain_text)} chains")
        return plan

    def _format_chains(self, chains: list[AttackPath]) -> str:
        if not chains:
            return "  (no exploit chains found)"
        lines = []
        for i, c in enumerate(chains[:8], 1):
            lines.append(f"  Chain #{i} (score={c.score:.3f}):")
            lines.append(f"    Path: {c.summary}")
        return "\n".join(lines)

    def _format_hypotheses(self) -> str:
        hyps = self.bb.get_hypotheses()
        if not hyps:
            return "  (none yet)"
        lines = []
        for h in hyps[-5:]:
            lines.append(f"  [{h.status}] {h.title} (likelihood={h.likelihood}, impact={h.impact})")
        return "\n".join(lines)

    def _format_actions(self) -> str:
        import json
        from actions import action_catalog

        catalog = action_catalog()
        return json.dumps(catalog, indent=2) if catalog else "[]"

    def _valid_action_ids(self) -> set[str]:
        from actions import action_catalog
        return {item["action_id"] for item in action_catalog()}

    def _parse_plan(self, response: str) -> dict:
        import json, re
        # Extract JSON from response
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        return self._fallback_plan([])

    def _fallback_plan(self, chains: list) -> dict:
        hyps = []
        raw_url = self.config.get("target", {}).get("raw_url", "")
        domain = self.config.get("target", {}).get("domain", "")

        technique_map = {
            "pivot": "cloud enumeration / SSRF",
            "extract": "secret extraction / JS analysis",
            "exploit": "vulnerability exploitation",
            "api_discovery": "API enumeration",
        }

        for c in chains[:5]:
            edge_type = c.edges[-1].edge_type if c.edges else ""
            target_node = c.nodes[-1].label if c.nodes else ""
            technique = technique_map.get(edge_type, edge_type)

            hyps.append({
                "title": f"Investigate {edge_type} chain from {target_node}",
                "description": c.summary,
                "likelihood": c.score,
                "impact": c.score,
                "target": target_node or raw_url,
                "technique": technique,
                "action_id": "",
                "assigned_to": "exploitation",
            })

        # Always add direct vulnerability hypotheses if there are URL parameters
        if raw_url and "?" in raw_url and "=" in raw_url:
            from urllib.parse import urlparse
            parsed = urlparse(raw_url)
            path = parsed.path or ""
            technique_hints = []

            # Check URL path for vulnerability type hints
            path_lower = path.lower()
            if "xss" in path_lower:
                technique_hints.append(("XSS", "web.xss.reflected"))
            if "sqli" in path_lower or "sql" in path_lower:
                technique_hints.append(("SQLi", "web.sqli.detect"))
            if "lfi" in path_lower or "file" in path_lower:
                technique_hints.append(("LFI", ""))
            if "ssrf" in path_lower:
                technique_hints.append(("SSRF", "web.ssrf.cloud_metadata"))
            if "ssti" in path_lower:
                technique_hints.append(("SSTI", ""))
            if "redirect" in path_lower or "open" in path_lower:
                technique_hints.append(("Open Redirect", ""))

            for vuln_type, action_id in technique_hints:
                hyps.append({
                    "title": f"Potential {vuln_type} on {path}",
                    "description": f"URL path suggests {vuln_type} testing target. Parameter injection may reveal vulnerability.",
                    "likelihood": 0.6,
                    "impact": 0.8,
                    "target": raw_url,
                    "technique": vuln_type,
                    "action_id": action_id,
                    "assigned_to": "exploitation",
                })

            # Generic parameter injection hypothesis
            hyps.append({
                "title": f"Parameter injection testing on {parsed.query}",
                "description": f"URL contains parameters ({parsed.query}) — test for injection vulnerabilities across vector classes.",
                "likelihood": 0.5,
                "impact": 0.7,
                "target": raw_url,
                "technique": "parameter injection",
                "action_id": "",
                "assigned_to": "exploitation",
            })

        # Add basic recon if no chains exist
        if not hyps:
            hyps.append({
                "title": f"Passive reconnaissance of {domain}",
                "description": "No exploit chains found — expand passive coverage first.",
                "likelihood": 0.5,
                "impact": 0.3,
                "target": raw_url or domain,
                "technique": "passive recon",
                "action_id": "",
                "assigned_to": "recon",
            })

            # Always add a web probe hypothesis
            hyps.append({
                "title": f"Web service enumeration on {domain}",
                "description": "Probe the target web service for technology fingerprinting and basic vulnerability signals.",
                "likelihood": 0.7,
                "impact": 0.5,
                "target": raw_url or f"https://{domain}",
                "technique": "technology fingerprinting / banner gathering",
                "action_id": "",
                "assigned_to": "exploitation",
            })

        return {
            "focus": f"Testing {domain} — prioritizing parameter injection and path-based vulnerability classes",
            "hypotheses": hyps[:8],
            "module_sequence": ["tech_detection", "risk_prioritization"],
            "watch_items": ["Stay in scope", "Avoid destructive actions"],
        }
