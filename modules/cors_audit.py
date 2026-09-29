"""Stage 5: CORS misconfiguration, determined from the response itself.

The exploitability question here is narrow and exactly answerable: a browser
will hand a cross-origin script the response body when the server says
`Access-Control-Allow-Origin` matches the page's origin *and*
`Access-Control-Allow-Credentials: true`. Both headers, on a 200, with a body
worth stealing. Everything else is a different grade of not-a-vulnerability,
and this module says so rather than rounding everything up to MEDIUM.

A simple GET is what a cross-origin page can issue with no preflight, so the
check uses GET. Preflight is not needed to establish exploitability and asking
for it would miss the misconfigurations that only appear on the real read.

`corsy`, when installed, is kept as corroborating evidence only. Its verdict is
a third-party assertion about a third-party tool's idea of risk; the findings
below come from headers this module received and can be replayed by hand.
"""

import json

from core.auth_harness import AuthHarness
from modules.base import BaseModule
from tools.external import corsy_scan, tool_available


# A page we do not own, standing in for an attacker's.
ATTACKER_ORIGIN = "https://cors-probe.invalid"
SANDBOX_ORIGIN = "null"

DEFAULT_ENDPOINTS = (
    "/api/me", "/api/user", "/api/users/me", "/api/profile", "/api/account",
    "/api/session", "/admin", "/dashboard", "/graphql", "/api/v1/me",
)


def _headers(result: dict) -> dict:
    """Lower-cased headers, from whichever shape the transport handed back.

    `output="full"` returns the raw header block as a string; the response
    object is a dict in other paths. Reading the string as a dict silently
    yields nothing, which would turn every probe into "no CORS here".
    """
    raw = result.get("headers")
    if isinstance(raw, dict):
        return {str(k).lower(): v for k, v in raw.items()}
    if not isinstance(raw, str) or not raw:
        return {}
    parsed = {}
    for line in raw.replace("\r\n", "\n").split("\n"):
        if ":" not in line or line.lower().startswith("http/"):
            continue
        name, _, value = line.partition(":")
        # Later values win, so a redirect chain settles on the final response.
        parsed[name.strip().lower()] = value.strip()
    return parsed


def _origin_allowed(value: str, probe: str) -> bool:
    """Whether the server would let the probe origin read the response.

    A wildcard counts as allowed, which is why a wildcard with credentials has
    to be graded separately: browsers reject that pairing outright, so it is a
    hardening note and never a session-theft claim.
    """
    if value == "*":
        return True
    return value.lower() == probe.lower()


class CORSAudit(BaseModule):
    id = "cors_audit"
    name = "CORS Audit"
    stage = 5
    detectability = "medium"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        base = self._base_url()
        if not base:
            self.state.skip_module(self.id, "no base URL")
            return "skipped"

        cfg = self._cfg()
        if cfg.get("enabled", True) is False:
            self.state.skip_module(self.id, "disabled in config")
            return "skipped"

        harness = AuthHarness(self.config)
        identities = await harness.establish_all(base)
        identity = identities[0].name if identities else None

        urls = self._urls(cfg, base)
        if not urls:
            self.state.skip_module(
                self.id,
                "no endpoint to test (set modules.cors_audit.endpoints)",
            )
            return "skipped"

        probed = []
        for url in urls:
            outcome = await self._check(harness, identity, url)
            if outcome is None:
                continue
            probed.append(outcome)
            finding = outcome.get("finding")
            if finding:
                self.state.add_finding(**finding)

        await self._corsy_corroboration(urls)

        self.state.complete_module(self.id)
        self.log(f"cors: {len(probed)} permissive endpoint(s) of {len(urls)}")
        return "done"

    async def _check(self, harness: AuthHarness, identity, url: str):
        """Probe one endpoint and grade what comes back."""
        observations = []
        for probe, label in ((ATTACKER_ORIGIN, "attacker origin"),
                             (SANDBOX_ORIGIN, "null origin")):
            observed = await self._observe(harness, identity, url, probe)
            if observed is None:
                continue
            observations.append(observed)
            if observed["finding"]:
                return observed

        if not observations:
            return None
        return {"observations": observations, "finding": None}

    async def _observe(self, harness: AuthHarness, identity, url: str,
                       probe: str):
        result = await self._get(harness, identity, url, probe)
        status = result.get("status", 0)
        if status in self._waf_codes():
            self.state.record_waf_block(url, status)
            return None
        if status == 0:
            return None

        headers = _headers(result)
        allow = str(headers.get("access-control-allow-origin", "") or "")
        credentials = str(
            headers.get("access-control-allow-credentials", "") or ""
        ).lower() == "true"
        varies = "origin" in str(headers.get("vary", "") or "").lower()
        body = result.get("body") or ""

        record = {
            "url": url, "probe_origin": probe, "status": status,
            "allow_origin": allow, "allow_credentials": credentials,
            "vary_origin": varies, "body_bytes": len(body),
        }

        # Nothing is exposed if the origin is refused, whatever else is set.
        if not _origin_allowed(allow, probe):
            record["verdict"] = "origin refused"
            return {"observations": [record], "finding": None}

        finding = None
        if allow == "*" and not credentials:
            # The normal posture of a public API: anyone may read it, and it
            # carries nothing of the caller's. A finding here would be a line
            # of noise on every public endpoint in scope.
            record["verdict"] = "wildcard without credentials (public posture)"
            return {"observations": [record], "finding": None}
        if credentials and allow == "*":
            # Browsers refuse `*` together with credentials, so this is not
            # exploitable today. Saying otherwise is how a triage queue fills
            # up with things nobody can act on.
            record["verdict"] = "wildcard with credentials (browser-rejected)"
            finding = self._finding(
                url, record,
                severity="LOW", confidence="FIRM",
                title="CORS: wildcard origin combined with Allow-Credentials",
                body=(
                    f"{url} answers with Access-Control-Allow-Origin: * together "
                    "with Access-Control-Allow-Credentials: true. Browsers reject "
                    "that combination, so it is not exploitable as it stands — "
                    "but it shows credentials are in scope for the CORS policy, "
                    "and the same code path usually becomes exploitable the moment "
                    "the wildcard is replaced with a reflected origin."
                ),
            )
        elif credentials and probe == SANDBOX_ORIGIN:
            record["verdict"] = "null origin with credentials"
            finding = self._finding(
                url, record,
                severity="HIGH", confidence="CONFIRMED",
                title="CORS: null origin accepted with credentials",
                body=(
                    f"{url} answers a request from a null origin with "
                    "Access-Control-Allow-Origin: null and "
                    "Access-Control-Allow-Credentials: true. A sandboxed iframe "
                    "or a data: page is sent as the null origin, so an attacker "
                    "page can read this endpoint with the victim's cookies "
                    "attached."
                ),
            )
        elif credentials:
            record["verdict"] = "arbitrary origin reflected with credentials"
            finding = self._finding(
                url, record,
                severity="HIGH", confidence="CONFIRMED",
                title="CORS: any origin accepted with credentials",
                body=(
                    f"{url} reflects an arbitrary Origin into "
                    "Access-Control-Allow-Origin and sets "
                    "Access-Control-Allow-Credentials: true, on a "
                    f"{status} response carrying {len(body)} bytes. Any website "
                    "can read this endpoint while the victim's session cookie is "
                    "attached, so this is a direct account-data disclosure."
                ),
            )
        else:
            record["verdict"] = "arbitrary origin reflected, no credentials"
            finding = self._finding(
                url, record,
                severity="INFO", confidence="FIRM",
                title="CORS: any origin reflected without credentials",
                body=(
                    f"{url} reflects an arbitrary Origin but does not allow "
                    "credentials, so only the unauthenticated response body is "
                    "readable cross-origin. Worth a look if this endpoint is "
                    "meant to be session-only, otherwise expected."
                ),
            )

        if not varies and allow and allow != "*":
            # A shared cache can store the attacker's ACAO and hand it to
            # everyone else. Only worth saying when the origin is echoed.
            record["missing_vary"] = True
            finding["description"] += (
                " The response also omits Vary: Origin, so a shared cache may "
                "serve this ACAO to other users."
            )
        return {"observations": [record], "finding": finding}

    def _finding(self, url: str, record: dict, *, severity: str,
                 confidence: str, title: str, body: str) -> dict:
        return {
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "category": "CORS Misconfiguration",
            "description": body,
            "evidence": [json.dumps(record)],
            "asset_keys": [f"url:{url}"],
            "remediation": (
                "Serve an explicit allowlist of trusted origins. Never combine "
                "credentials with a reflected or wildcard origin, and return "
                "Vary: Origin so caches do not cross-serve the header."
            ),
            "verified": True,
        }

    async def _corsy_corroboration(self, urls: list):
        """Record what corsy thinks, if it is installed. Never a finding:
        its severity model is not ours to defend in a report."""
        if not tool_available("corsy"):
            return
        for url in urls[:5]:
            try:
                result = await corsy_scan(url, timeout=120)
            except Exception as exc:  # a broken helper must not fail the module
                self.log(f"corsy failed on {url}: {exc}")
                continue
            self.state.add_evidence(
                self.id, "corsy", url,
                {"results": result.get("results", []),
                 "exit_code": result.get("exit_code")},
            )

    # ── Plumbing ─────────────────────────────────────────────────

    def _get(self, harness: AuthHarness, identity, url: str, origin: str):
        kwargs = {
            "method": "GET",
            "headers": {"Origin": origin},
            "output": "full",
        }
        if identity:
            return harness.request(identity, url, **kwargs)
        return harness.request_anonymous(url, **kwargs)

    def _urls(self, cfg: dict, base: str) -> list:
        candidates = cfg.get("endpoints") or self._discovered() or DEFAULT_ENDPOINTS
        limit = int(cfg.get("max_endpoints", 20) or 20)
        urls = []
        for candidate in candidates:
            url = self._absolute(str(candidate))
            if url and url not in urls:
                urls.append(url)
            if len(urls) >= limit:
                break
        return urls

    def _discovered(self) -> list:
        found = []
        for asset_type in ("url", "webapp", "endpoint"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "")).strip()
                if value.startswith(("http://", "https://")):
                    found.append(value)
        return found

    def _base_url(self) -> str:
        return str(self.target.get("base_url")
                   or (f"https://{self.domain}" if self.domain else ""))

    def _absolute(self, path: str) -> str:
        path = (path or "").strip()
        if not path:
            return ""
        if path.startswith(("http://", "https://")):
            return path
        base = self._base_url().rstrip("/")
        return f"{base}/{path.lstrip('/')}" if base else ""

    def _waf_codes(self) -> set:
        codes = (self.waf_config or {}).get("block_codes") or [429, 503]
        return set(codes) if isinstance(codes, (list, tuple, set)) else {429, 503}

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}
