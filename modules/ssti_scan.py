"""Stage 5: Server-Side Template Injection — polyglot differential.

Each engine family evaluates a different expression language, so one
payload per family plus a joint polyglot, each computed to a distinct
constant. The oracle is arithmetic, not syntactic: the response must
contain the COMPUTED value (49, 49, 49...) while a control string of
the same shape stays literal. A reflection of the raw payload is
evidence of nothing — it is the evaluation that counts.
"""

from core.probe_targets import iter_probe_points
from modules.base import BaseModule
from tools.wrappers import curl


# (label, payload): every payload evaluates to 49 in its engine.
SSTI_PAYLOADS = (
    ("jinja2-twig", "{{7*7}}"),
    ("pug-jade", "#{7*7}"),
    ("freemarker-velocity", "${7*7}"),
    ("erb-slim", "<%= 7*7 %>"),
    ("tornado", "{{7*7}}"),
    ("polyglot", "{{7*7}}#{7*7}${7*7}"),
)

# Must stay literal everywhere: same digits, no engine syntax.
CONTROL_STRING = "zz74x74zz"


class SSTIScan(BaseModule):
    id = "ssti_scan"
    name = "SSTI Scan"
    stage = 5
    detectability = "medium"
    depends_on = ["parameter_discovery"]
    active = True

    async def run(self) -> str:
        points = [p for p in iter_probe_points(
            self.state, self.base_url, self.domain)
            if p.get("method", "GET") == "GET" and p["param"]]
        if not points:
            self.state.skip_module(self.id, "no parameterized URLs")
            return "skipped"

        import time as _time_guard
        try:
            _guard_deadline = float(self.config.get("module_timeout", 300) or 300)
        except (TypeError, ValueError):
            _guard_deadline = 300.0
        _stop_at = _time_guard.monotonic() + max(60.0, _guard_deadline - 30.0)
        cfg = self._cfg()
        max_points = int(cfg.get("max_points", 40) or 40)
        reported = 0
        for point in points[:max_points]:
            if _time_guard.monotonic() >= _stop_at:
                break
            if await self._test_point(point):
                reported += 1

        self.state.complete_module(self.id)
        self.log(f"SSTI: {reported} template evaluation(s) confirmed")
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

    async def _test_point(self, point: dict) -> bool:
        """Control stays literal, payload computes: template evaluation.

        Counts, not presence: a shop page full of prices already contains
        "49", so only MORE forty-nines than the control produced — with
        the payload literal itself absent — counts as evaluation.
        """
        from core.validators import inject_param
        url, param = point["url"], point["param"]
        control = await self._fetch(inject_param(url, param, CONTROL_STRING))
        if control["status"] not in (200, 201):
            return False
        control_body = control["body"]
        if CONTROL_STRING not in control_body:
            # The control string itself does not reflect: nothing to
            # measure differentials against on this point.
            return False
        control_count = control_body.count("49")

        for label, payload in SSTI_PAYLOADS:
            response = await self._fetch(inject_param(url, param, payload))
            if response["status"] not in (200, 201):
                continue
            body = response["body"]
            if body.count("49") > control_count and payload not in body:
                self.state.add_finding(
                    title=f"Server-Side Template Injection ({label}): {param}",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    category="SSTI",
                    description=(
                        f"Payload `{payload}` on parameter {param} evaluated "
                        f"server-side to 49 while the control string stayed "
                        f"literal: a {label} template engine renders "
                        f"attacker input."),
                    evidence=[
                        f"URL: {url}",
                        f"Parameter: {param}",
                        f"Payload: {payload}",
                        f"Response: {body[:300]}",
                    ],
                    remediation="Never render user input as a template; use "
                                "logic-less templates with autoescaping, or "
                                "sandbox the engine with no attribute access.",
                    asset_keys=[f"url:{url}"],
                    verified=True,
                    verification={"method": "ssti_arithmetic_differential",
                                  "url": url, "param": param},
                )
                return True
        return False
