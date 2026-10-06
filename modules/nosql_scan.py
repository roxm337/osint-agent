"""Stage 5: NoSQL operator injection — differential, read-only.

Mongo-style operators (`$gt`, `$ne`, `$regex`, `$in`, `$where`) in
query parameters or JSON bodies change WHAT the database returns. The
oracle is differential, never syntactic: a baseline request with a
value that matches nothing is compared against operator requests that
should also match nothing unless the operator executes. More rows,
different rows, or a structurally different response means the
operator ran.

Timing (`$where` + sleep) is deliberately out of scope: it is slow,
flaky across networks, and destructive-adjacent. Documented, not
attempted.
"""

from urllib.parse import urlencode, urlparse, urlunparse

from core.probe_targets import iter_probe_points
from modules.base import BaseModule
from tools.wrappers import curl


# (label, operator): each must match nothing when NOT executed, and
# everything when it is. Two shapes per operator: `param[$op]=` for
# backends fed by Express-style nested query parsing, and a JSON
# operator object as the value for backends that decode values.
OPERATOR_PROBES = ("$gt", "$ne", "$regex", "$in")

# A value that matches nothing on a sane backend. If even the baseline
# returns rows, the endpoint lists without filtering and there is no
# differential to measure — skip, do not claim.
BASELINE_VALUE = "zzz_no_such_value_9f8"


class NoSQLScan(BaseModule):
    id = "nosql_scan"
    name = "NoSQL Operator Injection Scan"
    stage = 5
    detectability = "medium"
    depends_on = ["parameter_discovery"]
    active = True

    async def run(self) -> str:
        points = [p for p in iter_probe_points(
            self.state, self.base_url, self.domain) if p["param"]]
        if not points:
            self.state.skip_module(self.id, "no parameterized URLs")
            return "skipped"

        cfg = self._cfg()
        max_points = int(cfg.get("max_points", 40) or 40)
        reported = 0
        for point in points[:max_points]:
            if point.get("method", "GET") != "GET":
                continue
            if await self._test_query_operators(point):
                reported += 1

        self.state.complete_module(self.id)
        self.log(f"NoSQL operator injection: {reported} confirmed")
        return "done"

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}

    async def _fetch(self, url: str) -> dict:
        try:
            result = await curl(url, output="full", timeout=15)
        except Exception:
            return {"status": 0, "body": ""}
        return {"status": result.get("status", 0),
                "body": result.get("body", "") or ""}

    async def _test_query_operators(self, point: dict) -> bool:
        """Baseline (matches nothing) vs operator queries on one point."""
        import json as _json
        url, param = point["url"], point["param"]
        baseline_url = _with_query_value(url, param, BASELINE_VALUE)
        baseline = await self._fetch(baseline_url)
        if baseline["status"] not in (200, 201):
            return False
        base_rows = _row_count(baseline["body"])
        # A baseline that already returns rows lists without filtering:
        # no differential exists, so there is nothing to prove here.
        if base_rows is None or base_rows > 0:
            return False

        candidates = []
        for operator in OPERATOR_PROBES:
            candidates.append((f"{operator}-key",
                               _with_query_key(url, param, operator, "")))
            payload = {operator: "" if operator in ("$gt", "$regex") else
                       ("zzz_no_such_value_9f8" if operator == "$ne"
                        else [BASELINE_VALUE])}
            candidates.append((f"{operator}-json",
                               _with_query_value(
                                   url, param, _json.dumps(payload,
                                                           separators=(",", ":")))))
        for label, probe_url in candidates:
            response = await self._fetch(probe_url)
            if response["status"] not in (200, 201):
                continue
            rows = _row_count(response["body"])
            if rows is not None and rows > 0:
                self.state.add_finding(
                    title=f"NoSQL Operator Injection: {param} on {urlparse(url).path or '/'}",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    category="NoSQL Injection",
                    description=(
                        f"Operator probe `{label}` on parameter {param} "
                        f"returned {rows} row(s) where a non-matching value "
                        f"returns none: the operator executes server-side."),
                    evidence=[
                        f"URL: {probe_url}",
                        f"Baseline ({BASELINE_VALUE}): 0 rows",
                        f"Operator ({label}): {rows} rows",
                        f"Response: {response['body'][:300]}",
                    ],
                    remediation="Never pass client-controlled objects to query "
                                "constructors; validate and cast every operator "
                                "position to a scalar.",
                    asset_keys=[f"url:{url}"],
                    verified=True,
                    verification={"method": "nosql_operator_differential",
                                  "url": probe_url, "param": param},
                )
                return True
        return False


def _with_query_key(url: str, param: str, operator: str,
                    value: str) -> str:
    """Nested-operator shape: ?param[$operator]=value (qs-parser style)."""
    parsed = urlparse(url)
    from urllib.parse import parse_qsl
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[f"{param}[{operator}]"] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


def _with_query_value(url: str, param: str, value: str) -> str:
    """Set a query parameter value (raw operator strings pass through)."""
    parsed = urlparse(url)
    from urllib.parse import parse_qsl
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[param] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


def _row_count(body: str) -> int | None:
    """Count data rows in a JSON response, or None when not JSON shaped."""
    import json as _json
    text = str(body or "").strip()
    if not text.startswith(("{", "[")):
        return None
    try:
        data = _json.loads(text)
    except (ValueError, TypeError):
        return None
    container = data.get("data", data) if isinstance(data, dict) else data
    if isinstance(container, list):
        return len(container)
    if isinstance(container, dict):
        # Single object: 1 row if it carries an id-like key, else 0.
        keys = {str(k).lower() for k in container}
        if keys & {"id", "_id", "orderid", "order_id"}:
            return 1
        return 0
    return None
