"""Action Registry — global registry of all offensive capabilities."""

from __future__ import annotations

import asyncio
import functools
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from core.risk_gate import RiskGate, RiskTier
from core.scope import ScopeGuard


class RiskLevel(Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    DESTRUCTIVE = "DESTRUCTIVE"


RISK_TO_TIER = {
    RiskLevel.SAFE: RiskTier.SAFE,
    RiskLevel.LOW: RiskTier.LOW,
    RiskLevel.MEDIUM: RiskTier.MEDIUM,
    RiskLevel.HIGH: RiskTier.HIGH,
    RiskLevel.DESTRUCTIVE: RiskTier.DESTRUCTIVE,
}


@dataclass
class ActionMeta:
    id: str
    risk: RiskLevel
    detectability: str  # low | medium | high
    requires: list[str]  # required parameter names
    produces: str  # result type name
    tools: list[str] = field(default_factory=list)
    idempotent: bool = True
    timeout: int = 120
    description: str = ""
    category: str = ""  # web | api | auth | network | cloud | recon | verify


@dataclass
class ActionContext:
    action_id: str
    params: dict[str, Any]
    target: str
    scope: ScopeGuard
    risk_gate: RiskGate
    timeout: int = 120
    meta: Optional[ActionMeta] = None
    _start_time: float = 0.0

    @property
    def elapsed(self) -> float:
        return time.time() - self._start_time


@dataclass
class ActionResult:
    success: bool
    data: Any = None
    error: str = ""
    confidence: str = "TENTATIVE"  # TENTATIVE | FIRM | CONFIRMED
    evidence: dict = field(default_factory=dict)
    elapsed_ms: float = 0.0


class ActionRegistry:
    """Global registry of all registered actions."""

    _actions: dict[str, tuple[ActionMeta, Callable]] = {}

    @classmethod
    def register(cls, meta: ActionMeta, fn: Callable):
        if meta.id in cls._actions:
            raise ValueError(f"Action already registered: {meta.id}")
        cls._actions[meta.id] = (meta, fn)

    @classmethod
    def get(cls, action_id: str) -> Optional[tuple[ActionMeta, Callable]]:
        return cls._actions.get(action_id)

    @classmethod
    def list(cls) -> list[ActionMeta]:
        return [meta for meta, _ in cls._actions.values()]

    @classmethod
    def list_by_risk(cls, risk: RiskLevel) -> list[ActionMeta]:
        return [meta for meta, _ in cls._actions.values() if meta.risk == risk]

    @classmethod
    def list_by_category(cls, category: str) -> list[ActionMeta]:
        return [
            meta for meta, _ in cls._actions.values()
            if meta.category == category
        ]

    @classmethod
    async def execute(cls, action_id: str, ctx: ActionContext) -> ActionResult:
        entry = cls.get(action_id)
        if not entry:
            return ActionResult(False, error=f"unknown action: {action_id}")

        meta, fn = entry

        # Risk gate
        tier = RISK_TO_TIER.get(meta.risk, RiskTier.SAFE)
        decision = ctx.risk_gate.approve(tier, action_id, ctx.target)
        if not decision.allowed:
            return ActionResult(False, error=f"risk gate blocked: {decision.reason}")

        # Scope check
        scope_decision = ctx.scope.check(ctx.target)
        if not scope_decision.allowed:
            return ActionResult(False, error=f"out of scope: {scope_decision.reason}")

        # Validate required params
        for req in meta.requires:
            if req not in ctx.params:
                return ActionResult(False, error=f"missing required param: {req}")

        # Execute with timeout
        ctx._start_time = time.time()
        try:
            result = await asyncio.wait_for(
                fn(ctx),
                timeout=ctx.timeout or meta.timeout,
            )
            if not isinstance(result, ActionResult):
                result = ActionResult(True, data=result)
            result.elapsed_ms = (time.time() - ctx._start_time) * 1000
            return result
        except asyncio.TimeoutError:
            return ActionResult(False, error=f"timeout after {meta.timeout}s")
        except Exception as e:
            return ActionResult(False, error=str(e))

    @classmethod
    def size(cls) -> int:
        return len(cls._actions)


def action(
    id: str,
    risk: str = "LOW",
    detectability: str = "low",
    requires: Optional[list[str]] = None,
    produces: str = "Finding",
    tools: Optional[list[str]] = None,
    idempotent: bool = True,
    timeout: int = 120,
    description: str = "",
    category: str = "",
):
    """Decorator that registers an action in the global registry."""
    def decorator(fn: Callable):
        meta = ActionMeta(
            id=id,
            risk=RiskLevel(risk.upper()),
            detectability=detectability,
            requires=requires or [],
            produces=produces,
            tools=tools or [],
            idempotent=idempotent,
            timeout=timeout,
            description=description or fn.__doc__ or "",
            category=category or id.split(".")[0],
        )
        ActionRegistry.register(meta, fn)

        @functools.wraps(fn)
        async def wrapper(ctx: ActionContext) -> ActionResult:
            return await fn(ctx)
        return wrapper
    return decorator


# -- Convenience accessors --

def get_action(action_id: str) -> Optional[tuple[ActionMeta, Callable]]:
    return ActionRegistry.get(action_id)


def list_actions() -> list[ActionMeta]:
    return ActionRegistry.list()


def action_catalog() -> list[dict]:
    """Return typed JSON-serializable action metadata for planners."""
    return [
        {
            "action_id": meta.id,
            "risk": meta.risk.value,
            "detectability": meta.detectability,
            "requires": list(meta.requires),
            "produces": meta.produces,
            "tools": list(meta.tools),
            "idempotent": meta.idempotent,
            "timeout": meta.timeout,
            "description": meta.description,
            "category": meta.category,
        }
        for meta in sorted(ActionRegistry.list(), key=lambda item: item.id)
    ]


def list_actions_by_risk(risk: str) -> list[ActionMeta]:
    return ActionRegistry.list_by_risk(RiskLevel(risk.upper()))


def list_actions_by_category(category: str) -> list[ActionMeta]:
    return ActionRegistry.list_by_category(category)
