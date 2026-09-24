"""LLM-assisted offensive testing plan generation."""

from __future__ import annotations

import json
import logging
from typing import Any

from litellm import acompletion

from agents import get_llm_config

logger = logging.getLogger("osint-agent")


SYSTEM_PROMPT = """You are an authorized offensive security planner.

You receive an OSINT report bundle for a target. Produce a ranked, practical
testing plan that maps the most promising paths to impact.

Rules:
- Base every recommendation on the assets and evidence provided.
- Prefer hypotheses that lead to the highest-impact finding in the fewest steps.
- For each hypothesis, state why it is likely, what action or module runs next,
  what evidence confirms it, and what impact it proves.
- Return valid JSON only.
"""


USER_PROMPT = """Build an offensive testing plan from this OSINT bundle.

Return JSON with this shape:
{
  "executive_focus": "one concise paragraph",
  "top_hypotheses": [
    {
      "rank": 1,
      "title": "short hypothesis",
      "likelihood": "high|medium|low",
      "impact": "critical|high|medium|low|info",
      "why": "evidence-based reasoning",
      "recommended_module": "module_id or manual_review",
      "validation": "validation approach",
      "confirming_evidence": "what would prove it"
    }
  ],
  "module_sequence": ["module_id", "module_id"],
  "watch_items": ["operational note"]
}

OSINT bundle:
{bundle}
"""


class AttackPlanner:
    """Generate a ranked offensive testing plan from report/state context."""

    def __init__(self, config: dict):
        self.config = config
        self.llm = get_llm_config(config)
        self.model = self.llm["model"]

    async def build_plan(self, bundle: dict) -> dict:
        """Return an LLM plan, falling back to deterministic heuristics."""
        prompt = _build_user_prompt(bundle)
        kwargs = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": self.llm.get("temperature", 0.1),
            "max_tokens": max(int(self.llm.get("max_tokens", 2000)), 1600),
        }
        if self.llm.get("api_key"):
            kwargs["api_key"] = self.llm["api_key"]

        try:
            response = await acompletion(**kwargs)
            content = response.choices[0].message.content.strip()
            return _parse_plan(content)
        except Exception as exc:
            logger.error(f"Attack planner LLM call failed: {exc}")
            return fallback_plan(bundle)


def fallback_plan(bundle: dict) -> dict:
    """Heuristic plan used when the LLM is unavailable."""
    risk = bundle.get("risk", {})
    assets = bundle.get("assets", {})
    patterns = bundle.get("patterns", [])
    top_findings = risk.get("top_findings", [])
    counts = assets.get("counts_by_type", {})

    hypotheses = []
    for finding in top_findings[:5]:
        hypotheses.append({
            "rank": len(hypotheses) + 1,
            "title": f"Validate and deepen {finding.get('title', 'top finding')}",
            "likelihood": "high",
            "impact": str(finding.get("severity", "MEDIUM")).lower(),
            "why": (
                f"Existing finding {finding.get('id', '')} has score "
                f"{finding.get('risk_score', 0)} and category {finding.get('category', '')}."
            ),
            "recommended_module": _module_for_category(str(finding.get("category", ""))),
            "validation": "Reproduce the observation with rate-limited checks and capture minimal proof.",
            "confirming_evidence": "Fresh evidence showing the same condition on a live asset.",
        })

    if counts.get("api_endpoint") or counts.get("url"):
        hypotheses.append({
            "rank": len(hypotheses) + 1,
            "title": "API surface may expose authorization or input-handling bugs",
            "likelihood": "medium",
            "impact": "high",
            "why": "OSINT discovered API-like URLs or historical endpoints worth structured review.",
            "recommended_module": "parameter_discovery",
            "validation": "Map parameters and compare unauthenticated responses.",
            "confirming_evidence": "Endpoints with sensitive metadata, weak auth boundaries, or reflected parameters.",
        })

    if counts.get("webapp") or counts.get("js_file"):
        hypotheses.append({
            "rank": len(hypotheses) + 1,
            "title": "Client-side assets may reveal hidden routes or exposed secrets",
            "likelihood": "medium",
            "impact": "high",
            "why": "Web applications and JavaScript assets often expose route maps, keys, and feature flags.",
            "recommended_module": "js_analysis",
            "validation": "Review discovered scripts and validate any non-sensitive metadata or disabled keys.",
            "confirming_evidence": "Live routes, tokens, or references that can be responsibly reported.",
        })

    if not hypotheses:
        hypotheses.append({
            "rank": 1,
            "title": "Complete passive coverage before active validation",
            "likelihood": "medium",
            "impact": "medium",
            "why": "No strong high-risk signal exists yet, so coverage gaps are the best next opportunity.",
            "recommended_module": "deep_crawl",
            "validation": "Expand URL coverage with conservative crawl limits.",
            "confirming_evidence": "New endpoints, parameters, technologies, or misconfiguration candidates.",
        })

    sequence = []
    for hypothesis in hypotheses:
        module = hypothesis.get("recommended_module")
        if module and module != "manual_review" and module not in sequence:
            sequence.append(module)
    if "risk_prioritization" not in sequence:
        sequence.append("risk_prioritization")

    focus = "Prioritize existing high-confidence findings first, then expand API, JavaScript, and webapp coverage."
    if patterns:
        focus += f" Notable pattern: {patterns[0].get('title', 'cross-asset signal')}."

    return {
        "executive_focus": focus,
        "top_hypotheses": hypotheses[:8],
        "module_sequence": sequence[:8],
        "watch_items": [
            "Capture reproducible evidence for each confirmed issue.",
        ],
    }


def render_attack_plan(plan: dict, target: str) -> str:
    """Render the JSON plan as markdown."""
    lines = [
        f"# Authorized Testing Plan: {target}",
        "",
        plan.get("executive_focus", "No focus generated."),
        "",
        "## Ranked Hypotheses",
        "",
    ]
    for item in plan.get("top_hypotheses", []):
        lines.extend([
            f"### {item.get('rank', '-')}. {item.get('title', 'Untitled hypothesis')}",
            "",
            f"- **Likelihood:** {item.get('likelihood', '-')}",
            f"- **Impact:** {item.get('impact', '-')}",
            f"- **Why:** {item.get('why', '-')}",
            f"- **Recommended Module:** `{item.get('recommended_module', 'manual_review')}`",
            f"- **Validation:** {item.get('validation', '-')}",
            f"- **Confirming Evidence:** {item.get('confirming_evidence', '-')}",
            "",
        ])

    lines.extend(["## Suggested Module Sequence", ""])
    for module in plan.get("module_sequence", []):
        lines.append(f"- `{module}`")

    lines.extend(["", "## Watch Items", ""])
    for item in plan.get("watch_items", []):
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def _compact_bundle(bundle: dict) -> dict:
    return {
        "metadata": bundle.get("metadata", {}),
        "summary": bundle.get("summary", {}),
        "risk": bundle.get("risk", {}),
        "assets": bundle.get("assets", {}),
        "patterns": bundle.get("patterns", [])[:10],
        "recommendations": bundle.get("recommendations", [])[:12],
        "modules": {
            "completed": bundle.get("modules", {}).get("completed", []),
            "skipped": bundle.get("modules", {}).get("skipped", []),
            "blocked": bundle.get("modules", {}).get("blocked", []),
            "runs": bundle.get("modules", {}).get("runs", [])[-15:],
        },
        "findings": [
            {
                "id": item.get("id"),
                "title": item.get("title"),
                "severity": item.get("severity"),
                "confidence": item.get("confidence"),
                "risk_score": item.get("risk_score"),
                "category": item.get("category"),
                "description": item.get("description"),
                "asset_keys": item.get("asset_keys", [])[:8],
            }
            for item in bundle.get("findings", [])[:12]
        ],
        "evidence": bundle.get("evidence", {}).get("items", [])[:20],
    }


def _build_user_prompt(bundle: dict) -> str:
    bundle_json = json.dumps(_compact_bundle(bundle), indent=2, default=str)
    return USER_PROMPT.replace("{bundle}", bundle_json)


def _parse_plan(content: str) -> dict:
    content = content.strip()
    if content.startswith("```"):
        content = content.strip("`")
        if content.lower().startswith("json"):
            content = content[4:].strip()
    parsed = json.loads(content)
    if not isinstance(parsed, dict):
        raise ValueError("planner response was not a JSON object")
    parsed.setdefault("top_hypotheses", [])
    parsed.setdefault("module_sequence", [])
    parsed.setdefault("watch_items", [])
    return parsed


def _module_for_category(category: str) -> str:
    lowered = category.lower()
    if "api" in lowered:
        return "rest_api_audit"
    if "xss" in lowered:
        return "xss_scan"
    if "sql" in lowered or "injection" in lowered:
        return "sqli_scan"
    if "cloud" in lowered or "bucket" in lowered:
        return "cloud_enum"
    if "dns" in lowered:
        return "dns_takeover"
    if "secret" in lowered or "javascript" in lowered or "js" in lowered:
        return "js_analysis"
    if "redirect" in lowered:
        return "open_redirect"
    if "cors" in lowered:
        return "cors_audit"
    return "manual_review"