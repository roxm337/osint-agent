"""Base module class that all modules inherit from."""

import asyncio
import logging
import yaml
from pathlib import Path
from typing import Optional
from core.keyvault import KeyVault
from core.scope import ScopeGuard
from core.verification_oracle import configure_oob
from state.manager import StateManager
from tools.wrappers import bash, configure_http_session, curl, dig, whois_lookup

logger = logging.getLogger("osint-agent")


class BaseModule:
    """Every module extends this."""

    id = "base"
    name = "Base Module"
    stage = 0
    detectability = "low"
    depends_on = []
    requires_auth = False

    def __init__(self, state: StateManager, config: dict):
        self.state = state
        self.config = config
        self.module_config = config.get("modules", {})
        self.waf_config = config.get("waf", {})
        self.target = config.get("target", {})
        self.domain = self.target.get("domain", "")
        self.output_dir = Path(config.get("paths", {}).get("output_dir", "reports"))
        self.scope = ScopeGuard(self.domain, config)
        self.keys = KeyVault(config)
        configure_http_session(config)
        configure_oob(config)

    async def run(self) -> str:
        """Run the module. Returns 'done', 'skipped', or 'blocked'."""
        raise NotImplementedError

    def is_blocked(self) -> bool:
        """Check if module is blocked by WAF or other limits."""
        threshold = self.waf_config.get("max_bypass_attempts", 5)
        if self.state.waf_limit_hit(threshold=threshold) and self.config.get("modules", {}).get("skip_on_waf", True):
            if self.detectability in ("medium", "high"):
                return True
        return False

    async def http_get(self, url: str, **kwargs) -> dict:
        """HTTP GET with WAF tracking."""
        scope_check = kwargs.pop("scope_check", True)
        if scope_check:
            decision = self.scope.check(url)
            if not decision.allowed:
                self.log(f"Blocked out-of-scope HTTP request: {decision.value}")
                return {
                    "status": 0,
                    "body": "",
                    "error": f"out of scope: {decision.reason}",
                }

        result = await curl(url, **kwargs)
        status = result.get("status", 0)

        # Track WAF signals
        block_codes = self.waf_config.get("block_codes", [503, 429])
        honeypot_codes = self.waf_config.get("honeypot_codes", [500])

        if status in block_codes:
            self.state.record_waf_block(url, status)
        elif status == 200:
            self.state.record_waf_allow(url, status)

        self.state.add_check(f"http:{url}")
        if self.module_config.get("record_http_evidence", True):
            evidence_id = self.state.add_evidence(
                self.id,
                "http",
                url,
                {
                    "url": url,
                    "scope_checked": scope_check,
                    "status": status,
                    "output": kwargs.get("output", "status"),
                    "body_preview": str(result.get("body", ""))[:5000],
                    "error": result.get("error"),
                },
            )
            result["evidence_id"] = evidence_id
        return result

    async def resolve(self, subdomain: str) -> Optional[str]:
        """Resolve subdomain to IP."""
        fqdn = f"{subdomain}.{self.domain}"
        decision = self.scope.check(fqdn)
        if not decision.allowed:
            self.log(f"Blocked out-of-scope DNS resolve: {decision.value}")
            return None

        result = await dig("A", fqdn)
        answers = result.get("answers", [])
        for answer in answers:
            # Filter out CNAMEs and non-IP responses
            if answer and answer[0].isdigit():
                return answer
        return None

    def log(self, message: str):
        logger.info(f"  [{self.id}] {message}")

    def merge_config(self, path: str) -> dict:
        """Load YAML config file."""
        p = Path(path)
        if p.exists():
            return yaml.safe_load(p.read_text())
        return {}
