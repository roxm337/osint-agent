"""Open-redirect probe action — Location-oracle, never follows."""

from urllib.parse import urlparse, urlunparse

from actions.registry import action, ActionContext, ActionResult
from core.validators import inject_param
from tools.wrappers import curl


# Reserved TLD, guaranteed by RFC 2606 never to resolve. Mirrors the
# module's PROBE_HOST so action and module evidence agree with each other.
PROBE_HOST = "redirect-probe.invalid"

_PAYLOADS = [
    f"https://{PROBE_HOST}/",
    f"//{PROBE_HOST}/",
    f"/\\{PROBE_HOST}/",
]


def _location_offsite(location: str) -> bool:
    """Mirror of the module's check: the Location names the probe host.

    Only ever compared as a string; the host is never resolved, so this
    cannot become a request to a third party.
    """
    value = (location or "").strip()
    if not value:
        return False
    host = (urlparse(value).hostname or "").lower()
    if host:
        return host == PROBE_HOST
    lowered = value.lower()
    for prefix in ("//", "/\\", "\\/", "https:", "https:/"):
        if lowered.startswith(prefix) and PROBE_HOST in lowered:
            return True
    return False


@action(
    id="web.redirect.probe",
    risk="LOW",
    detectability="medium",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=60,
    description="Test a parameter for open redirect via the Location header",
    category="web",
)
async def redirect_probe(ctx: ActionContext) -> ActionResult:
    url = ctx.params["url"]
    param = ctx.params["param"]

    from urllib.parse import parse_qsl, urlencode
    attempted = []
    for payload in _PAYLOADS:
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[param] = payload
        probe = urlunparse(parsed._replace(query=urlencode(query)))
        try:
            result = await curl(probe, output="full", timeout=15,
                                follow_redirects=False)
        except Exception as exc:
            attempted.append({"payload": payload, "error": str(exc)})
            continue
        status = result.get("status", 0)
        if status in (429, 503):
            return ActionResult(False, error="WAF block observed, stopping",
                                confidence="TENTATIVE")
        location = ""
        headers = result.get("headers", "") or ""
        if isinstance(headers, dict):
            location = str(headers.get("location", headers.get("Location", "")))
        else:
            for line in str(headers).splitlines():
                if line.lower().startswith("location"):
                    location = line.split(":", 1)[1].strip() if ":" in line else ""
                    break
        attempted.append({"payload": payload, "status": status,
                          "location": location})
        if location and _location_offsite(location):
            return ActionResult(
                success=True,
                confidence="CONFIRMED",
                data={"url": url, "param": param, "payload": payload,
                      "status": status, "location": location},
                evidence={"redirect": {"url": url, "param": param,
                                        "payload": payload, "status": status,
                                        "location": location}},
            )

    return ActionResult(False, error="no off-site Location observed",
                        confidence="TENTATIVE",
                        data={"attempted": attempted})
