"""Base module class that all modules inherit from."""

import asyncio
import logging
import yaml
from pathlib import Path
from typing import Optional
from core.keyvault import KeyVault
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
    active = False

    def __init__(self, state: StateManager, config: dict):
        self.state = state
        self.config = config
        self.module_config = config.get("modules", {})
        self.waf_config = config.get("waf", {})
        self.target = config.get("target", {})
        self.domain = self.target.get("domain", "")
        self.output_dir = Path(config.get("paths", {}).get("output_dir", "reports"))
        self.keys = KeyVault(config)
        configure_http_session(config)
        configure_oob(config)

    @property
    def base_url(self) -> str:
        """The target as a fetchable URL: correct scheme, port preserved.

        `target.domain` is a hostname. It carries neither scheme nor port, so
        a module that built `https://{domain}` dialled 443 on the wrong port
        for anything that is not a default-HTTPS site, and 25 modules did
        exactly that. Against a target on `localhost:3000` every one of them
        got nothing at all.

        Prefers the scheme the user actually supplied, and only assumes HTTPS
        when they did not say.
        """
        # `target` is normally a dict, but modules are handed loose fixtures
        # and some tests overwrite `module.target` with a bare URL string, so
        # this must not assume it can call `.get()` on it.
        target = self.target if isinstance(self.target, dict) else {}
        for key in ("base_url", "raw_url"):
            raw = str(target.get(key) or "").strip()
            if "://" in raw:
                return raw.rstrip("/")
        scheme = str(target.get("scheme") or "").strip().rstrip(":")
        return f"{scheme or 'https'}://{self.domain}".rstrip("/")

    async def run(self) -> str:
        """Run the module. Returns 'done' or 'skipped'.

        Nothing is refused on policy grounds; a module that cannot run reports
        'skipped' with a reason. The orchestrator records raised exceptions as
        'blocked'.
        """
        raise NotImplementedError

    async def http_get(self, url: str, **kwargs) -> dict:
        """HTTP GET with WAF tracking."""
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
                    "status": status,
                    "output": kwargs.get("output", "status"),
                    "body_preview": str(result.get("body", ""))[:5000],
                    "error": result.get("error"),
                },
            )
            result["evidence_id"] = evidence_id
        return result

    def oob(self):
        """Return an out-of-band callback client, or None if none is configured.

        Modules ask here instead of reading the oracle's config themselves, so
        the "is there somewhere for a callback to land" decision lives in one
        place. Returning None matters: `InteractshClient` will happily build a
        `*.oob.invalid` URL, and a target that dutifully tries to resolve it
        turns an unconfigured check into a silent false negative that still
        costs a request against the target.
        """
        from core.verification_oracle import InteractshClient
        cfg = self.config.get("oob") or {}
        if isinstance(cfg, dict) and cfg.get("enabled") is False:
            return None
        client = InteractshClient(config=cfg if isinstance(cfg, dict) else {})
        return client if client.enabled else None

    async def resolve(self, subdomain: str) -> Optional[str]:
        """Resolve subdomain to IP."""
        fqdn = f"{subdomain}.{self.domain}"
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