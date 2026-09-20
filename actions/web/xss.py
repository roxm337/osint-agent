"""Cross-Site Scripting (XSS) actions."""

from actions.registry import action, ActionContext, ActionResult
from core.validators import inject_param
from core.verification_oracle import VerificationOracle
from tools.external import tool_available
from tools.wrappers import curl


XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
]


@action(
    id="web.xss.reflected",
    risk="MEDIUM",
    detectability="high",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=120,
    description="Test a parameter for reflected XSS",
    category="web",
)
async def reflected_xss(ctx: ActionContext) -> ActionResult:
    url = ctx.params["url"]
    param = ctx.params["param"]
    oracle = VerificationOracle()

    for payload in XSS_PAYLOADS:
        test_url = inject_param(url, param, payload)  # noqa: F841 — kept for evidence
        verdict = await oracle.verify_xss(url, param, payload)

        if verdict.confidence.value in ("FIRM", "CONFIRMED"):
            return ActionResult(
                success=True,
                confidence=verdict.confidence.value,
                data={
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "type": "reflected",
                },
                evidence=verdict.evidence,
            )

    return ActionResult(False, error="no reflected XSS detected",
                        confidence="TENTATIVE")


@action(
    id="web.xss.dalfox",
    risk="HIGH",
    detectability="high",
    requires=["urls"],
    produces="VulnCandidate",
    tools=["dalfox"],
    idempotent=True,
    timeout=600,
    description="Run dalfox against a list of URLs for XSS discovery",
    category="web",
)
async def dalfox_xss(ctx: ActionContext) -> ActionResult:
    if not tool_available("dalfox"):
        return ActionResult(False, error="dalfox not installed",
                            confidence="TENTATIVE")

    from tools.external import dalfox_scan
    urls = ctx.params["urls"]
    if isinstance(urls, str):
        urls = [urls]

    result = await dalfox_scan(urls, timeout=ctx.timeout or 600)
    findings = result.get("results", [])

    if findings:
        return ActionResult(
            success=True,
            confidence="FIRM",
            data={"findings": findings},
            evidence={
                "dalfox": {
                    "targets": urls,
                    "findings": findings,
                    "exit_code": result.get("exit_code"),
                }
            },
        )

    return ActionResult(False, error="dalfox found no XSS",
                        confidence="TENTATIVE")
