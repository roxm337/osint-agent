"""Action Library — typed, registered, risk-tiered actions.

Every offensive capability is a registered Action — the only way to
touch a target. Properties: typed input/output, risk tier, detectability,
declared tool deps, scope-checked target, rate-limited, timeout-bounded,
evidence-emitting, replayable.

Usage:
    @action(
        id="web.sqli.test",
        risk="MEDIUM",
        detectability="high",
        requires=["url", "param"],
        produces="VulnCandidate",
        tools=["sqlmap"],
        idempotent=True,
    )
    async def test_sqli(ctx: ActionContext) -> ActionResult: ...
"""

# Import all action modules to register them
from . import web, api, auth, network, cloud, recon, verify
from . import registry as _reg

# Convenience re-exports
ActionRegistry = _reg.ActionRegistry
action = _reg.action
get_action = _reg.get_action
list_actions = _reg.list_actions
list_actions_by_risk = _reg.list_actions_by_risk
list_actions_by_category = _reg.list_actions_by_category
action_catalog = _reg.action_catalog
ActionContext = _reg.ActionContext
ActionResult = _reg.ActionResult
ActionMeta = _reg.ActionMeta

__all__ = [
    "ActionRegistry",
    "action",
    "get_action",
    "list_actions",
    "list_actions_by_risk",
    "list_actions_by_category",
    "action_catalog",
    "ActionContext",
    "ActionResult",
    "ActionMeta",
]
