"""Central API key lookup with environment and config fallbacks."""

import os
from dataclasses import dataclass
from typing import Any

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class KeySpec:
    service: str
    env: tuple[str, ...]
    config_paths: tuple[str, ...]
    label: str


KEY_SPECS = {
    "virustotal": KeySpec(
        "virustotal",
        ("VIRUSTOTAL_API_KEY", "VT_API_KEY"),
        ("api_keys.virustotal", "virustotal_api_key"),
        "VirusTotal",
    ),
    "greynoise": KeySpec(
        "greynoise",
        ("GREYNOISE_API_KEY",),
        ("api_keys.greynoise", "greynoise_api_key"),
        "GreyNoise",
    ),
    "abuseipdb": KeySpec(
        "abuseipdb",
        ("ABUSEIPDB_API_KEY",),
        ("api_keys.abuseipdb", "abuseipdb_api_key"),
        "AbuseIPDB",
    ),
    "chaos": KeySpec(
        "chaos",
        ("CHAOS_API_KEY", "PDCP_API_KEY"),
        ("api_keys.chaos", "chaos_api_key"),
        "ProjectDiscovery Chaos",
    ),
    "hunter_io": KeySpec(
        "hunter_io",
        ("HUNTER_API_KEY", "HUNTER_IO_API_KEY"),
        ("api_keys.hunter_io", "hunter_api_key"),
        "Hunter.io",
    ),
    "securitytrails": KeySpec(
        "securitytrails",
        ("SECURITYTRAILS_API_KEY",),
        ("api_keys.securitytrails", "securitytrails_api_key"),
        "SecurityTrails",
    ),
    "vulners": KeySpec(
        "vulners",
        ("VULNERS_API_KEY",),
        ("api_keys.vulners", "vulners_api_key"),
        "Vulners",
    ),
    "urlscan": KeySpec(
        "urlscan",
        ("URLSCAN_API_KEY",),
        ("api_keys.urlscan", "urlscan_api_key"),
        "urlscan.io",
    ),
    "hibp": KeySpec(
        "hibp",
        ("HIBP_API_KEY",),
        ("api_keys.hibp", "hibp_api_key"),
        "Have I Been Pwned",
    ),
    "shodan": KeySpec(
        "shodan",
        ("SHODAN_API_KEY",),
        ("api_keys.shodan", "shodan_api_key"),
        "Shodan",
    ),
}


class KeyVault:
    """Resolve optional third-party service keys without exposing secrets."""

    def __init__(self, config: dict):
        self.config = config or {}

    def get(self, service: str, default: str = "") -> str:
        spec = KEY_SPECS.get(service)
        if not spec:
            return default

        for path in spec.config_paths:
            value = self._config_value(path)
            if value:
                return str(value).strip()

        for env_name in spec.env:
            value = os.environ.get(env_name, "").strip()
            if value:
                return value

        return default

    def has(self, service: str) -> bool:
        return bool(self.get(service))

    def require(self, service: str) -> tuple[bool, str]:
        spec = KEY_SPECS.get(service)
        if self.has(service):
            return True, ""
        label = spec.label if spec else service
        env_names = ", ".join(spec.env) if spec else service.upper()
        return False, f"{label} key missing; set {env_names} or api_keys.{service}"

    def presence(self) -> dict:
        return {
            name: {
                "present": self.has(name),
                "label": spec.label,
                "env": list(spec.env),
                "masked": self.mask(self.get(name)),
            }
            for name, spec in sorted(KEY_SPECS.items())
        }

    def available(self, services: list[str]) -> list[str]:
        return [service for service in services if self.has(service)]

    @staticmethod
    def mask(value: str) -> str:
        value = str(value or "")
        if not value:
            return ""
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}...{value[-4:]}"

    def _config_value(self, dotted_path: str) -> Any:
        current: Any = self.config
        for part in dotted_path.split("."):
            if not isinstance(current, dict) or part not in current:
                return ""
            current = current[part]
        return current
