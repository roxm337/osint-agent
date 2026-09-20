"""Scope enforcement for targets, hosts, IPs, and URLs."""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    value: str
    reason: str


class ScopeGuard:
    """Allow/deny matcher with safe defaults around the target domain."""

    def __init__(self, target: str, config: Optional[dict] = None):
        # Normalize target — extract hostname from URL if needed
        raw = (target or "").strip().lower().rstrip(".")
        self.target = self._normalize(raw) or raw
        scope = (config or {}).get("target", {}).get("scope", [])
        deny = (config or {}).get("target", {}).get("deny", [])

        default_allow = [self.target, f"*.{self.target}"] if self.target else []
        self.allow_patterns = self._clean_patterns(scope) or default_allow
        self.deny_patterns = self._clean_patterns(deny)

    def check(self, value: str) -> ScopeDecision:
        host = self._normalize(value)
        if not host:
            return ScopeDecision(False, value, "empty or invalid scope value")

        if self._matches_any(host, self.deny_patterns):
            return ScopeDecision(False, host, "matches deny scope")

        if self._matches_any(host, self.allow_patterns):
            return ScopeDecision(True, host, "matches allow scope")

        return ScopeDecision(False, host, "outside configured scope")

    def require(self, value: str) -> str:
        decision = self.check(value)
        if not decision.allowed:
            raise ValueError(f"Out of scope: {decision.value} ({decision.reason})")
        return decision.value

    def filter(self, values: List[str]) -> List[str]:
        return [v for v in values if self.check(v).allowed]

    def _clean_patterns(self, patterns: List[str]) -> List[str]:
        clean = []
        for pattern in patterns or []:
            value = str(pattern).strip().lower().rstrip(".")
            if value:
                clean.append(value)
        return clean

    def _normalize(self, value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        parsed = urlparse(raw if "://" in raw else f"//{raw}")
        host = parsed.hostname or raw.split("/", 1)[0]
        return host.strip().lower().rstrip(".")

    def _matches_any(self, host: str, patterns: List[str]) -> bool:
        return any(self._matches(host, pattern) for pattern in patterns)

    def _matches(self, host: str, pattern: str) -> bool:
        if self._matches_ip(host, pattern):
            return True
        if fnmatch.fnmatchcase(host, pattern):
            return True
        if pattern.startswith("*."):
            base = pattern[2:]
            return host.endswith(f".{base}") and host != base
        return host == pattern

    def _matches_ip(self, host: str, pattern: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        try:
            if "/" in pattern:
                return ip in ipaddress.ip_network(pattern, strict=False)
            return ip == ipaddress.ip_address(pattern)
        except ValueError:
            return False
