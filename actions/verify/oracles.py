"""Verification actions — oracle-driven confirmation checks."""

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
    description=(
        "Confirm a suspected anomaly by re-running it N times: a `marker` "
        "string must persist in every response, or `baseline_url` vs `url` "
        "must diverge reproducibly. A stable fetch of an unmodified URL "
        "proves reachability only and never confirms a vulnerability."
    ),
    category="verify",
)
async def verify_reproducible(ctx: ActionContext) -> ActionResult:
    checker = ReproducibilityChecker(min_reps=ctx.params.get("reps", 3))
    url = ctx.params["url"]
    method = ctx.params.get("method", "GET")
    marker = str(ctx.params.get("marker") or "").strip()
    baseline_url = str(ctx.params.get("baseline_url") or "").strip()

    async def probe(target=url):
        from tools.wrappers import curl
        return await curl(target, method=method, output="full")

    if marker:
        # The thing we injected must be present in every rep. Stable
        # presence of a canary is confirmation; a stable page is not.
        bodies = []
        statuses = []
        for _ in range(checker.min_reps):
            response = await probe()
            bodies.append(response.get("body", "") or "")
            statuses.append(response.get("status", 0))
        hits = sum(1 for body in bodies if marker in body)
        if bodies and hits == len(bodies):
            return ActionResult(
                success=True,
                confidence="CONFIRMED",
                data={"marker_hits": hits, "reps": len(bodies),
                      "status": statuses[0] if statuses else 0},
                evidence={"marker": marker, "reps": len(bodies),
                          "statuses": statuses},
            )
        return ActionResult(
            success=False,
            confidence="FIRM" if hits else "TENTATIVE",
            data={"marker_hits": hits, "reps": len(bodies)},
            evidence={"marker": marker, "reps": len(bodies),
                      "statuses": statuses},
            error=(f"marker present in {hits}/{len(bodies)} reps — "
                   "not a stable confirmation"),
        )

    if baseline_url:
        analyzer = DifferentialAnalyzer()
        base = await analyzer.baseline(baseline_url, method=method)
        test_result = await analyzer.test(url, method=method)
        verdict = analyzer.compare(base, test_result)
        if verdict.confidence.value not in ("FIRM", "CONFIRMED"):
            return ActionResult(
                success=False,
                confidence=verdict.confidence.value,
                data={"divergence_score": verdict.score},
                evidence=verdict.evidence,
                error=f"no divergence to confirm: {verdict.reason}",
            )
        repro = await checker.check(
            lambda: analyzer.test(url, method=method))
        if repro.confidence.value == "CONFIRMED":
            return ActionResult(
                success=True,
                confidence="CONFIRMED",
                data={"divergence_score": verdict.score,
                      "match_rate": repro.score, "reps": checker.min_reps},
                evidence={**verdict.evidence, **repro.evidence},
            )
        return ActionResult(
            success=False,
            confidence="FIRM",
            data={"divergence_score": verdict.score},
            evidence=verdict.evidence,
            error="diverged once but not reproducibly — flapping, not proof",
        )

    # No marker, no baseline: an unmodified fetch. Reproducibility of a
    # 200 OK is reachability, and reachability is not a vulnerability —
    # returning success here is how static JS bundles became seventeen
    # CONFIRMED "exploitation" findings. Record the stability facts for
    # the audit trail and decline to confirm.
    verdict = await checker.check(probe)
    first_status = 0
    try:
        first = await probe()
        first_status = first.get("status", 0)
    except Exception:
        pass
    return ActionResult(
        success=False,
        confidence="TENTATIVE",
        data={"match_rate": verdict.score, "reps": checker.min_reps,
              "status": first_status},
        evidence=verdict.evidence,
        error=(f"HTTP {first_status} stable across {checker.min_reps} reps — "
               "reachability only, nothing to confirm"),
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

    # Composite scoring. Reproducibility strengthens a divergence that
    # already exists; on its own it confirms nothing — a stable page is
    # not a vulnerability, and treating it as one is how static assets
    # became CONFIRMED findings.
    scores = []
    diff_strong = diff_verdict.confidence.value in ("FIRM", "CONFIRMED")
    repro_strong = repro_verdict.confidence.value == "CONFIRMED"
    if diff_strong:
        scores.append(diff_verdict.score)
    if diff_strong and repro_strong:
        scores.append(repro_verdict.score * 1.2)  # reproducibility is a stronger signal

    confidence = "TENTATIVE"
    if diff_strong and repro_strong:
        confidence = "CONFIRMED"
    elif diff_strong:
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
        error="" if confidence in ("FIRM", "CONFIRMED") else (
            f"no stable divergence: {diff_verdict.reason}; {repro_verdict.reason}"
        ),
    )
