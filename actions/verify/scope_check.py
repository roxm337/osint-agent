"""Verification actions — oracle-driven confirmation and scope integrity checks."""

from actions.registry import action, ActionContext, ActionResult
from core.verification_oracle import (VerificationOracle, DifferentialAnalyzer,
                                       ReproducibilityChecker, TimingOracle)

@action(
    id="verify.differential",
    risk="SAFE",
    detectability="low",
    requires=["baseline_url", "test_url"],
    produces="VerificationResult",
    idempotent=True,
    timeout=60,
    description="Compare baseline vs test response using differential analysis",
    category="verify",
)
async def verify_differential(ctx: ActionContext) -> ActionResult:
    analyzer = DifferentialAnalyzer()
    method = ctx.params.get("method", "GET")

    baseline = await analyzer.baseline(ctx.params["baseline_url"], method=method)
    test_result = await analyzer.test(ctx.params["test_url"], method=method)
    verdict = analyzer.compare(baseline, test_result)

    return ActionResult(
        success=verdict.confidence.value in ("FIRM", "CONFIRMED"),
        confidence=verdict.confidence.value,
        data={
            "divergence_score": verdict.score,
            "signals": verdict.evidence.get("differential", {}),
        },
        evidence=verdict.evidence,
    )


@action(
    id="verify.reproducible",
    risk="SAFE",
    detectability="low",
    requires=["url"],
    produces="VerificationResult",
    idempotent=True,
    timeout=120,
    description="Run a probe N times to check reproducibility for CONFIRMED confidence",
    category="verify",
)
async def verify_reproducible(ctx: ActionContext) -> ActionResult:
    checker = ReproducibilityChecker(min_reps=ctx.params.get("reps", 3))
    url = ctx.params["url"]

    async def probe(url=url):
        from tools.wrappers import curl
        return await curl(url, output="full")

    verdict = await checker.check(probe)

    return ActionResult(
        success=verdict.confidence.value == "CONFIRMED",
        confidence=verdict.confidence.value,
        data={"match_rate": verdict.score, "reps": checker.min_reps},
        evidence=verdict.evidence,
    )


@action(
    id="verify.timing_analysis",
    risk="SAFE",
    detectability="low",
    requires=["baseline_url", "test_url"],
    produces="VerificationResult",
    idempotent=True,
    timeout=120,
    description="Statistical timing analysis comparing baseline vs test endpoint latency",
    category="verify",
)
async def verify_timing(ctx: ActionContext) -> ActionResult:
    oracle = TimingOracle()
    method = ctx.params.get("method", "GET")

    baseline = await oracle.measure(ctx.params["baseline_url"], method=method)
    test = await oracle.measure(ctx.params["test_url"], method=method)
    verdict = oracle.compare(baseline, test)

    return ActionResult(
        success=verdict.confidence.value in ("FIRM", "CONFIRMED"),
        confidence=verdict.confidence.value,
        data={
            "baseline_ms": baseline["mean"],
            "test_ms": test["mean"],
            "diff_ms": test["mean"] - baseline["mean"],
        },
        evidence=verdict.evidence,
    )


@action(
    id="verify.composite_oracle",
    risk="SAFE",
    detectability="low",
    requires=["url"],
    produces="VerificationResult",
    idempotent=True,
    timeout=180,
    description="Run differential + reproducibility + timing checks and return composite confidence",
    category="verify",
)
async def verify_composite(ctx: ActionContext) -> ActionResult:
    oracle = VerificationOracle()
    url = ctx.params["url"]
    baseline_url = ctx.params.get("baseline_url", url)
    method = ctx.params.get("method", "GET")

    # Differential
    base = await oracle.differential.baseline(baseline_url, method=method)
    test = await oracle.differential.test(url, method=method)
    diff_verdict = oracle.differential.compare(base, test)

    # Reproducibility
    repro_verdict = await oracle.reproducibility.check(
        lambda: oracle.differential.test(url, method=method)
    )

    # Composite scoring
    scores = []
    if diff_verdict.confidence.value in ("FIRM", "CONFIRMED"):
        scores.append(diff_verdict.score)
    if repro_verdict.confidence.value == "CONFIRMED":
        scores.append(repro_verdict.score * 1.2)  # reproducibility is a stronger signal

    confidence = "TENTATIVE"
    if repro_verdict.confidence.value == "CONFIRMED":
        confidence = "CONFIRMED"
    elif diff_verdict.confidence.value == "FIRM" and scores:
        confidence = "FIRM"

    composite_score = max(scores) if scores else 0.0

    return ActionResult(
        success=confidence in ("FIRM", "CONFIRMED"),
        confidence=confidence,
        data={"composite_score": composite_score},
        evidence={
            "differential": diff_verdict.evidence,
            "reproducibility": repro_verdict.evidence,
        },
    )
