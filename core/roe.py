"""Rules of Engagement (ROE) — engagement metadata for an authorized test.

An ROE file declares engagement context:

  - scope:         domains / wildcards / CIDRs that are in scope
  - exclude:       targets explicitly out of scope
  - allowed_risk_tiers: which action risk tiers the engagement covers
  - window:        optional start/end datetime for the engagement
  - limits:        optional per-engagement resource caps
  - contacts:      operator and emergency contact details

Scope, exclude, and tiers are recorded as METADATA. They populate reports,
audit logs, and the plan artifacts. They do NOT gate execution — ScopeGuard
and RiskGate remain permissive unless explicitly opted into elsewhere.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from core.risk_gate import RiskTier

VALID_TIERS = {t.value for t in RiskTier}


class ROEError(Exception):
    """Raised when an ROE document is malformed or invalid."""


def _parse_dt(value: Any, label: str) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value))
        except ValueError as exc:
            raise ROEError(f"{label} is not a valid ISO-8601 datetime: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class ROE:
    engagement_id: str
    scope: list
    exclude: list = field(default_factory=list)
    allowed_risk_tiers: list = field(default_factory=lambda: ["SAFE", "LOW"])
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    limits: dict = field(default_factory=dict)
    operator: str = ""
    contact: str = ""
    emergency_contact: str = ""
    raw: dict = field(default_factory=dict)

    @property
    def tiers(self) -> list[str]:
        return list(self.allowed_risk_tiers)

    def validate(self) -> "ROE":
        if not self.engagement_id:
            raise ROEError("engagement_id is required")
        if not self.scope:
            raise ROEError("scope.allow must list at least one in-scope target")
        for tier in self.allowed_risk_tiers:
            if tier not in VALID_TIERS:
                raise ROEError(f"invalid risk tier: {tier!r}")
        if self.window_start and self.window_end and self.window_end <= self.window_start:
            raise ROEError("window.end must be after window.start")
        return self

    def enforce(self, config: dict) -> dict:
        """Return an updated config copy carrying ROE metadata.

        Scope/exclude lists are recorded on the config (for reporting and
        audit), and authorization is marked confirmed. ScopeGuard and
        RiskGate remain in permissive mode regardless of ROE.
        """
        cfg = dict(config)
        target = dict(cfg.get("target", {}))

        roe_scope = [str(s).strip().lower().rstrip(".") for s in self.scope if str(s).strip()]
        cfg_scope = [str(s).strip().lower().rstrip(".")
                     for s in target.get("scope", []) if str(s).strip()]
        effective_scope = _intersect_scope(cfg_scope, roe_scope)

        roe_exclude = [str(s).strip().lower().rstrip(".") for s in self.exclude if str(s).strip()]
        cfg_deny = [str(s).strip().lower().rstrip(".")
                    for s in target.get("deny", []) if str(s).strip()]
        effective_deny = _dedupe(cfg_deny + roe_exclude)

        target["scope"] = effective_scope
        target["deny"] = effective_deny
        target["authorization"] = "confirmed"
        target["allowed_risk_tiers"] = list(self.allowed_risk_tiers)
        cfg["target"] = target

        limits = dict(cfg.get("budget_limits", {}))
        for key, value in (self.limits or {}).items():
            if value is not None:
                limits[key] = value
        if limits:
            cfg["budget_limits"] = limits

        # Guardrails stay off — ROE is metadata, not a runtime gate.
        cfg.setdefault("scope", {})["enforce"] = False
        cfg.setdefault("risk_gate", {})["enforce"] = False
        return cfg

    def to_dict(self) -> dict:
        return {
            "engagement_id": self.engagement_id,
            "scope": self.scope,
            "exclude": self.exclude,
            "allowed_risk_tiers": self.allowed_risk_tiers,
            "window_start": self.window_start.isoformat() if self.window_start else None,
            "window_end": self.window_end.isoformat() if self.window_end else None,
            "limits": self.limits,
            "operator": self.operator,
            "contact": self.contact,
            "emergency_contact": self.emergency_contact,
        }


def load_roe(path: str | Path) -> ROE:
    """Load and validate an ROE YAML file."""
    roe_path = Path(path)
    if not roe_path.exists():
        raise ROEError(f"ROE file not found: {roe_path}")
    try:
        raw = yaml.safe_load(roe_path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ROEError(f"ROE file is not valid YAML: {exc}") from exc
    return parse_roe(raw, raw)


def parse_roe(raw: dict, source: dict) -> ROE:
    """Build an ROE from an already-parsed mapping (kept for testability)."""
    p = raw.get("authorization", {})
    scope = raw.get("scope", {})
    if not isinstance(scope, dict):
        raise ROEError("scope must be a mapping with 'allow' and optional 'exclude'")
    if not isinstance(p, dict):
        raise ROEError("authorization must be a mapping")

    roe = ROE(
        engagement_id=str(raw.get("engagement_id", "")).strip(),
        scope=list(scope.get("allow", [])),
        exclude=list(scope.get("exclude", [])) if scope.get("exclude") else [],
        allowed_risk_tiers=[str(t).upper() for t in raw.get("allowed_risk_tiers", ["SAFE", "LOW"])],
        window_start=_parse_dt(p.get("window", {}).get("start"), "window.start"),
        window_end=_parse_dt(p.get("window", {}).get("end"), "window.end"),
        limits=dict(raw.get("limits", {}) or {}),
        operator=str(p.get("operator", "")),
        contact=str(p.get("contact", "")),
        emergency_contact=str(p.get("emergency_contact", "")),
        raw=raw,
    )
    return roe.validate()


def _dedupe(values: list) -> list:
    seen = set()
    out = []
    for v in values:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _intersect_scope(cfg_scope: list, roe_scope: list) -> list:
    """Intersect config scope with ROE scope for metadata purposes."""
    if not roe_scope:
        return cfg_scope
    if not cfg_scope:
        return list(roe_scope)

    roe_matcher = _PatternSet(roe_scope)
    effective = []
    for entry in cfg_scope:
        if roe_matcher.allows(entry):
            effective.append(entry)
        else:
            overlapping = [s for s in roe_scope if entry.endswith(f".{s.strip('.')}")]
            if overlapping:
                effective.append(entry)
    return _dedupe(effective or list(roe_scope))


class _PatternSet:
    """Minimal matcher mirroring ScopeGuard semantics for scope intersection."""

    def __init__(self, patterns: list):
        self.patterns = patterns

    def allows(self, value: str) -> bool:
        value = value.strip().lower().rstrip(".")
        return any(self._matches(value, p) for p in self.patterns)

    def _matches(self, host: str, pattern: str) -> bool:
        pattern = pattern.strip().lower().rstrip(".")
        try:
            if "/" in pattern:
                return ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False)
            if _is_ip(pattern):
                return host == pattern
        except ValueError:
            pass
        if pattern.startswith("*."):
            base = pattern[2:]
            return host.endswith(f".{base}") and host != base
        import fnmatch
        return fnmatch.fnmatchcase(host, pattern) or host == pattern


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False