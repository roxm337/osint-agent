"""Agent registry and LLM configuration — using litellm."""
import os

from dotenv import load_dotenv

load_dotenv()


# Shortcuts: config provider name -> litellm model string
MODEL_SHORTCUTS = {
    "openai": "openai/gpt-4o",
    "anthropic": "anthropic/claude-sonnet-4-20250514",
    "groq": "groq/llama-3.3-70b-versatile",
    "openrouter": "openrouter/openai/gpt-4o",
    "nvidia": "nvidia/meta/llama-3.1-70b-instruct",
    "llama_cloud": "together_ai/meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
}


def resolve_model(model: str) -> str:
    """Resolve a model shortcut or pass through full model string."""
    if "/" in model:
        return model
    if model in MODEL_SHORTCUTS:
        return MODEL_SHORTCUTS[model]
    return f"openai/{model}"


def load_system_prompt() -> str:
    """Load system prompt from OSINT_AGENT docs if available."""
    from pathlib import Path
    paths = [
        Path(__file__).resolve().parent.parent.parent
        / "OSINT_AGENT" / "prompts" / "ORCHESTRATOR.md",
        Path(__file__).resolve().parent
        / ".." / "OSINT_AGENT" / "prompts" / "ORCHESTRATOR.md",
    ]
    for p in paths:
        if p.exists():
            return p.read_text().strip()
    return DEFAULT_SYSTEM_PROMPT


def get_llm_config(config: dict) -> dict:
    """Extract LLM config from app config with env fallbacks."""
    llm = config.get("llm", {})
    raw_model = (
        llm.get("model")
        or os.environ.get("OSINT_AGENT_LLM_MODEL")
        or os.environ.get("LITELLM_MODEL")
        or "openai/gpt-4o"
    )
    model = resolve_model(raw_model)
    api_key = (
        llm.get("api_key")
        or os.environ.get("OSINT_AGENT_LLM_API_KEY")
        or os.environ.get("LITELLM_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or ""
    )
    return {
        "model": model,
        "api_key": api_key,
        "temperature": llm.get("temperature", 0.1),
        "max_tokens": llm.get("max_tokens", 2000),
    }


DEFAULT_SYSTEM_PROMPT = """You are an autonomous OSINT orchestration agent. Your job is to systematically discover, enumerate, and assess the external attack surface of authorized targets.

## Your State
Three files govern all your decisions:
- assets.json — All discovered typed assets (domains, IPs, emails, etc.)
- findings.json — All vulnerability findings
- module.json — Module progress, completed checks, WAF state

## Priority Rules
1. Passive before active — Always prefer LOW-detectability probes first
2. DNS before HTTP — DNS is free, fast, and rarely blocked
3. Sitemaps before fuzzing — Sitemaps are designed to be read; fuzzing triggers WAFs
4. Map WAF before probing — Know what's blocked before you try to bypass
5. Negative results are findings
6. Stop when ROI drops

## Available Modules (stage order)
1. seed_discovery — WHOIS, DNS, ASN, crt.sh
2. subdomain_enum — crt.sh + DNS brute-force
3. wayback_machine — Wayback CDX historical URLs
4. email_harvest — Page scrape, Hunter.io, pattern derivation
5. tech_detection — CMS, server, PHP, plugins, themes
6. email_security — SPF, DMARC, DKIM, BIMI, MTA-STS
7. port_scan — nmap/naabu (HIGH detectability, auth required)
8. social_media — LinkedIn, Twitter, Facebook, Instagram
9. sitemap_exploit — Yoast sitemap, custom post types
10. rest_api_audit — WP REST API, plugin endpoints
11. waf_mapping — WAF detection, classification, bypass
12. login_enum — wp-login, author ID, XML-RPC
13. misconfig_probes — .git, .env, phpinfo, actuators
14. cloud_enum — S3, GCS, Azure buckets
15. breach_check — HudsonRock, HIBP, IntelX
16. reporting — Markdown report + findings JSON

## Module Lifecycle
PENDING -> ACTIVE -> COMPLETE | SKIPPED | BLOCKED

Return one of:
- RUN_MODULE: <module_id>
- COMPLETE: investigation finished
"""
