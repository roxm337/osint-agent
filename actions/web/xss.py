"""Cross-Site Scripting (XSS) actions."""

from actions.registry import action, ActionContext, ActionResult
from core.verification_oracle import probe_reflected_xss
from tools.external import tool_available
from tools.wrappers import curl


@action(
    id="web.xss.reflected",
    risk="MEDIUM",
    detectability="high",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=120,
    description="Test a parameter for reflected XSS (marker gate + verbatim oracle)",
    category="web",
)
async def reflected_xss(ctx: ActionContext) -> ActionResult:
    url = ctx.params["url"]
    param = ctx.params["param"]

    async def fetch(target: str) -> str:
        result = await curl(target, output="full")
        return result.get("body", "") or ""

    payload, test_url, verdict = await probe_reflected_xss(
        url, param,
        [lambda marker: payload_template(marker)
         for payload_template in _payload_templates()],
        fetch,
    )

    if verdict.confidence.value == "FIRM":
        return ActionResult(
            success=True,
            confidence="FIRM",
            data={
                "url": url,
                "param": param,
                "payload": payload,
                "test_url": test_url,
                "type": "reflected",
            },
            evidence=verdict.evidence,
        )

    return ActionResult(False, error="no reflected XSS detected",
                        confidence="TENTATIVE")


def _payload_templates() -> list:
    def element(marker: str) -> str:
        return (f"<sVg/onLOad=document.body.append(`{marker}`.repeat(2))>")

    def attribute(marker: str) -> str:
        return (f"\"><sVg/onLOad=document.body.append(`{marker}`.repeat(2))>")

    def js_string(marker: str) -> str:
        return f"'-document.body.append(`{marker}`.repeat(2))-'"

    def script_break(marker: str) -> str:
        return (f"</script><sVg/onLOad=document.body.append(`{marker}`.repeat(2))>")

    return [element, attribute, js_string, script_break]


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
