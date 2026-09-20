"""LLM orchestrator agent — decides which modules to run via litellm."""

import logging
from litellm import acompletion
from agents import load_system_prompt, get_llm_config

logger = logging.getLogger("osint-agent")


BUILD_CONTEXT_PROMPT = """
## Current Investigation State
Target domain: {domain}

### Modules Already Completed
{completed}

### Modules Skipped
{skipped}

### Modules Blocked
{blocked}

### Assets Discovered ({asset_count})
{assets_summary}

### Findings ({finding_count})
{findings_summary}

### WAF Status
{waf_status}

## Modules Available To Run Now
{pending_modules}

## Your Task
Pick exactly ONE module from the available list above to run next.
Follow the stage order — start with stage 1, then 2, etc.

Respond with exactly one line:
RUN_MODULE: <module_id>

If ALL modules are done (none available), respond:
COMPLETE
"""


SYSTEM_OVERRIDES = {
    "ollama": (
        "You are an OSINT automation agent. You pick the next reconnaissance "
        "module to run. Always pick the lowest-stage module that hasn't been run yet. "
        "Respond ONLY with 'RUN_MODULE: <name>' or 'COMPLETE'."
    ),
}


class LLMOrchestrator:
    """LLM-driven orchestrator that decides next actions via litellm."""

    def __init__(self, state, config: dict):
        self.state = state
        self.config = config
        self.llm = get_llm_config(config)
        self.model = self.llm["model"]
        self.system_prompt = self._build_system_prompt()

    def _build_system_prompt(self) -> str:
        provider = self.model.split("/")[0] if "/" in self.model else ""
        override = SYSTEM_OVERRIDES.get(provider)
        if override:
            return override
        return load_system_prompt()

    def _build_context(self) -> str:
        summary = self.state.summary()

        completed = summary.get("modules_completed", [])
        skipped = summary.get("modules_skipped", [])
        blocked = summary.get("modules_blocked", [])

        by_type = {}
        for node in self.state.assets["nodes"]:
            t = node["type"]
            by_type[t] = by_type.get(t, 0) + 1
        assets_summary_lines = [f"  - {t}: {c}" for t, c in sorted(by_type.items())]

        findings_by_sev = summary.get("findings_by_severity", {})
        findings_lines = [
            f"  - {s}: {findings_by_sev[s]}"
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            if findings_by_sev.get(s, 0)
        ]

        waf = self.state.module.get("waf", {})
        waf_status = (
            f"Detected: {waf.get('detected', False)}, "
            f"Vendor: {waf.get('vendor', 'unknown')}, "
            f"Blocks: {len(waf.get('blocks', []))}"
        )

        from modules import get_all_module_ids, MODULE_REGISTRY
        pending = []
        for mid in get_all_module_ids():
            if mid not in completed and mid not in skipped and mid not in blocked:
                entry = MODULE_REGISTRY.get(mid, {})
                pending.append(f"  [{entry.get('stage', '?')}] {mid}")

        return BUILD_CONTEXT_PROMPT.format(
            domain=self.config.get("target", {}).get("domain", "?"),
            completed="\n".join(f"  - {m}" for m in completed) or "  (none)",
            skipped="\n".join(f"  - {m}" for m in skipped) or "  (none)",
            blocked="\n".join(f"  - {m}" for m in blocked) or "  (none)",
            asset_count=summary.get("assets", 0),
            assets_summary="\n".join(assets_summary_lines) or "  (none)",
            finding_count=summary.get("findings", 0),
            findings_summary="\n".join(findings_lines) or "  (none)",
            waf_status=waf_status,
            pending_modules="\n".join(pending) or "  (none — all done)",
        )

    async def decide_next(self) -> str:
        """Ask the LLM what to do next. Returns 'RUN_MODULE: <id>' or 'COMPLETE'."""
        context = self._build_context()

        kwargs = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": context},
            ],
            "temperature": self.llm.get("temperature", 0.1),
            "max_tokens": self.llm.get("max_tokens", 2000),
        }
        if self.llm.get("api_key"):
            kwargs["api_key"] = self.llm["api_key"]

        try:
            response = await acompletion(**kwargs)
            content = response.choices[0].message.content.strip()
            logger.info(f"LLM raw response: {content[:500]}")
        except Exception as e:
            logger.error(f"LLM API call failed: {e}")
            fallback = self._fallback_decision()
            logger.warning(f"Falling back to deterministic module choice: {fallback}")
            return fallback

        for line in content.split("\n"):
            line = line.strip().lower()
            if line.startswith("run_module:"):
                module_id = line.split(":", 1)[1].strip()
                return f"RUN_MODULE:{module_id}"
            if line in ("complete", "done", "finished"):
                return "COMPLETE"

        # If no keyword found but there are pending modules, log and retry
        fallback = self._fallback_decision()
        logger.warning(f"LLM returned unrecognized response. Defaulting to: {fallback}")
        return fallback

    def _fallback_decision(self) -> str:
        """Pick the next pending module when the LLM is unavailable or unclear."""
        from modules import get_all_module_ids

        summary = self.state.summary()
        completed = set(summary.get("modules_completed", []))
        skipped = set(summary.get("modules_skipped", []))
        blocked = set(summary.get("modules_blocked", []))
        pending = [
            module_id for module_id in get_all_module_ids()
            if module_id not in completed
            and module_id not in skipped
            and module_id not in blocked
        ]
        if pending:
            return f"RUN_MODULE:{pending[0]}"
        return "COMPLETE"
