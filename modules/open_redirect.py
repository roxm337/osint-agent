"""Stage 5: Open redirect, determined from the Location header.

The question is binary and needs no heuristics: send a destination on a host
we control the name of, and see whether the server hands that host back in
`Location`. If it does, the redirect is open. Nothing is inferred from response
codes, body text, or a third-party tool's opinion.

Two safety rules, both load-bearing:

- Redirects are never followed. The whole check is one `Location` header; a
  client that follows it would send a request to a host that has nothing to do
  with the engagement. The probe host uses the reserved `.invalid` TLD, so even
  a mistake here cannot reach a real site.
- The probe host is never resolved, only compared. Confirmation means the string
  in `Location` starts with the probe host, which is checkable by hand from the
  recorded evidence.

Severity follows where the redirect sits. An open redirect on a login, SSO or
OAuth endpoint is a credential-phishing primitive, because the victim arrives
at the real page first and is handed over afterwards. The same bug on a
documentation page is a nuisance.
"""

import json
from urllib.parse import urlparse, urlunparse

from core.auth_harness import AuthHarness
from modules.base import BaseModule
from tools.external import openredirex_scan, tool_available


# Reserved TLD, guaranteed by RFC 2606 never to resolve. Using a real domain
# here would mean a following client could hit somebody else's server.
PROBE_HOST = "redirect-probe.invalid"

REDIRECT_NAMES = (
    "redirect", "redir", "url", "next", "return", "continue", "dest",
    "destination", "goto", "target", "ref", "out", "view", "to", "link",
)

DEFAULT_PATHS = (
    "/login", "/signin", "/auth/callback", "/oauth/authorize",
    "/sso/login", "/logout", "/continue", "/go", "/out", "/r",
)

# Paths where a redirect is a credential-phishing primitive rather than a
# nuisance, because the victim reaches the genuine page before being handed on.
HIGH_VALUE_HINTS = (
    "login", "signin", "sign-in", "auth", "oauth", "sso", "saml", "cas",
    "verify", "confirm", "magic", "password", "reset", "callback", "logout",
)

# The shapes that defeat a naive "must start with /" or "must contain the host"
# check. Every one of these points somewhere off-site once a browser resolves
# it, which is the whole reason they are worth sending.
def _payloads(host: str) -> list:
    return [
        f"https://{host}/",
        f"//{host}/",
        f"/\\{host}/",
        f"\\/{host}/",
        f"https:/{host}/",
        f"https:\\\\{host}/",
        f" https://{host}/",
        f"https://{host}#",
        f"https://x@{host}/",
        f"https://{host}/\\.target",
    ]


class OpenRedirectScan(BaseModule):
    id = "open_redirect"
    name = "Open Redirect Scan"
    stage = 5
    detectability = "medium"
    depends_on = ["parameter_discovery"]
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

        params = self._params(cfg)
        targets = self._targets(cfg, base, params)
        if not targets:
            self.state.skip_module(self.id, "no redirect-like parameter to test")
            return "skipped"

        payloads = _payloads(PROBE_HOST)
        findings = []
        for url, param in targets:
            finding = await self._probe(harness, identity, url, param, payloads)
            if finding:
                findings.append(finding)
                self.state.add_finding(**finding)

        await self._openredirex_corroboration([u for u, _ in targets])

        self.state.complete_module(self.id)
        self.log(f"open redirect: {len(findings)} confirmed of {len(targets)} target(s)")
        return "done"

    async def _probe(self, harness: AuthHarness, identity, url: str,
                     param: str, payloads: list):
        """One endpoint, one parameter. Stops at the first payload that lands.

        A single confirmed destination is enough to report, and every further
        payload is another visit to a page the owner is watching for strangers.
        """
        attempted = []
        for payload in payloads:
            probe = self._with_param(url, param, payload)
            result = await self._get(harness, identity, probe)
            status = result.get("status", 0)
            if status in self._waf_codes():
                self.state.record_waf_block(url, status)
                return None

            location = self._location(result)
            attempted.append({"payload": payload, "status": status,
                              "location": location})
            if location and self._is_offsite(location):
                return self._finding(url, param, payload, status, location,
                                     attempted)
        return None

    def _finding(self, url: str, param: str, payload: str, status: int,
                 location: str, attempted: list) -> dict:
        high_value = any(hint in urlparse(url).path.lower()
                         for hint in HIGH_VALUE_HINTS)
        return {
            "title": f"Open redirect via {param} on {urlparse(url).path or '/'}",
            "severity": "HIGH" if high_value else "MEDIUM",
            "confidence": "CONFIRMED",
            "category": "Open Redirect",
            "description": (
                f"{url} accepts {param}={payload!r} and answers {status} with "
                f"Location: {location}. The destination host is one the target "
                "does not control, so a link built from this endpoint sends a "
                "victim to an attacker's site while the URL still shows the "
                "genuine domain."
                + (
                    " This endpoint is part of a sign-in or authorisation flow, "
                    "which is what turns the redirect into a credential-phishing "
                    "route: the victim completes the real login first and is "
                    "handed on afterwards."
                    if high_value else
                    " On a page outside the sign-in flow the practical risk is "
                    "phishing and link-filter bypass rather than credential theft."
                )
            ),
            "evidence": [json.dumps({
                "url": url, "param": param, "payload": payload,
                "status": status, "location": location,
                "attempts_before_confirmation": attempted,
            })],
            "asset_keys": [f"url:{url}"],
            "remediation": (
                "Resolve the destination and allow only relative paths on the "
                "same origin, or match it against an allowlist of known hosts. "
                "Reject protocol-relative (//host) and backslash (\\host) forms "
                "explicitly: they pass a `startswith('/')` check and still leave "
                "the site."
            ),
            "verified": True,
        }

    async def _openredirex_corroboration(self, urls: list):
        """Record openredirex's take when it is installed, never as a finding.

        Note that it follows redirects, so it can send requests to the
        destination hosts it discovers. The URLs handed over are this module's
        own candidates, not the probe destinations, which keeps that to targets
        already in scope.
        """
        if not tool_available("openredirex") or not urls:
            return
        try:
            result = await openredirex_scan(urls[:20], timeout=180)
        except Exception as exc:  # a broken helper must not fail the module
            self.log(f"openredirex failed: {exc}")
            return
        self.state.add_evidence(
            self.id, "openredirex", self.domain,
            {"results": result.get("results", []),
             "exit_code": result.get("exit_code")},
        )

    # ── Plumbing ─────────────────────────────────────────────────

    def _get(self, harness: AuthHarness, identity, url: str) -> dict:
        kwargs = {
            "method": "GET",
            "output": "full",
            # The entire check is the Location header. Following it would send
            # a request to a host that is not part of the engagement.
            "follow_redirects": False,
        }
        if identity:
            return harness.request(identity, url, **kwargs)
        return harness.request_anonymous(url, **kwargs)

    def _location(self, result: dict) -> str:
        from modules.cors_audit import _headers
        return str(_headers(result).get("location", "") or "")

    def _is_offsite(self, location: str) -> bool:
        """Whether the destination host is the probe host.

        Only ever compared as a string. The host is never resolved, so this
        cannot become a request to a third party.
        """
        value = location.strip()
        if not value:
            return False
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        if host:
            return host == PROBE_HOST
        # Protocol-relative and backslash forms carry no scheme for urlparse to
        # read a host from, so fall back to the literal prefix.
        for prefix in ("//", "/\\", "\\/", "https:", "https:/", "https:///"):
            if value.lower().startswith(prefix) and PROBE_HOST in value.lower():
                return True
        return False

    def _with_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        from urllib.parse import parse_qsl, urlencode
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[param] = value
        return urlunparse(parsed._replace(query=urlencode(query)))

    def _params(self, cfg: dict) -> list:
        configured = cfg.get("params")
        if configured:
            return [str(p) for p in configured if p]
        found = set(REDIRECT_NAMES)
        for asset in self.state.get_assets_by_type("parameter"):
            name = str(asset.get("value", "")).lower()
            if name and any(token in name for token in REDIRECT_NAMES):
                found.add(name)
        return sorted(found)

    def _targets(self, cfg: dict, base: str, params: list) -> list:
        """(url, param) pairs, capped so a large scope cannot run away."""
        limit = int(cfg.get("max_targets", 40) or 40)
        candidates = cfg.get("endpoints") or self._discovered() or DEFAULT_PATHS
        targets = []
        for candidate in candidates:
            url = self._absolute(str(candidate))
            if not url:
                continue
            for param in params:
                if (url, param) not in targets:
                    targets.append((url, param))
                if len(targets) >= limit:
                    return targets
        return targets

    def _discovered(self) -> list:
        found = []
        for asset in self.state.get_assets_by_type("url"):
            value = str(asset.get("value", "")).strip()
            if value.startswith(("http://", "https://")):
                found.append(value.split("?")[0])
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
