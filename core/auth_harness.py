"""Authenticated session harness.

Every module in this toolkit runs unauthenticated, which means the highest
paying bug class in bug bounty — broken object-level authorisation — has
been structurally untestable. This module supplies the missing half: named
identities, each with its own session, that can be driven independently.

The hard part is not sending cookies, it is knowing the session is real. A
failed login usually returns HTTP 200 with the login form again, so a harness
that trusts the status code produces false negatives against every protected
endpoint. `Identity.verify()` therefore checks that the session actually
reaches authenticated content before anything downstream relies on it.

Identities are configured, never discovered. Two accounts are a prerequisite
for horizontal privilege testing, and you supply them.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from tools.wrappers import curl, get_engine


# Markers that indicate the request landed back on an unauthenticated page.
# Matched case-insensitively against the response body.
_ANON_MARKERS = (
    "name=\"password\"",
    "type=\"password\"",
    "name='password'",
    "please log in",
    "please sign in",
    "log in to continue",
    "sign in to continue",
    "session expired",
    "authentication required",
    "unauthorized",
)

_LOGIN_PATH_HINTS = ("/login", "/signin", "/sign-in", "/auth", "/session")


class AuthError(RuntimeError):
    """Identity configuration is unusable."""


@dataclass
class Identity:
    """One named account and the session that represents it."""

    name: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    bearer_token: str = ""
    login: dict[str, Any] = field(default_factory=dict)
    verify_url: str = ""
    success_marker: str = ""
    verified: bool = False
    verification_note: str = ""

    def describe(self) -> str:
        bits = []
        if self.cookies:
            bits.append(f"{len(self.cookies)} cookie(s)")
        if self.bearer_token:
            bits.append("bearer token")
        if self.login:
            bits.append("login flow")
        return f"{self.name} ({', '.join(bits) or 'no credentials'})"

    def request_headers(self) -> dict[str, str]:
        headers = dict(self.headers)
        if self.bearer_token and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        return headers

    # ── Session establishment ────────────────────────────────────

    async def establish(self, base_url: str = "") -> bool:
        """Log in if configured, then confirm the session is authenticated.

        Returns True only when the session reaches authenticated content. A
        caller that gets False must not treat this identity as a victim or an
        attacker — the resulting findings would be meaningless.
        """
        if self.login:
            ok = await self._perform_login(base_url)
            if not ok:
                self.verified = False
                self.verification_note = "login request failed"
                return False

        if self.cookies or self.bearer_token:
            # Seed the engine jar so every later request carries the session.
            get_engine().set_cookies(self.cookies, identity=self.name)

        return await self.verify(base_url)

    async def _perform_login(self, base_url: str) -> bool:
        """Submit the configured login and adopt any session cookie set."""
        spec = self.login
        url = spec.get("url", "")
        if not url and base_url:
            url = urlparse(base_url)._replace(path="/login").geturl()
        if not url:
            self.verification_note = "login block has no url"
            return False

        method = str(spec.get("method", "POST")).upper()
        payload = spec.get("data", {}) or {}
        content_type = spec.get("content_type", "")

        kwargs: dict[str, Any] = {"output": "full", "follow_redirects": True}
        if content_type == "json" or spec.get("json") is True:
            # The wrapper takes a body string, not a dict, so the JSON is
            # encoded here and the content type set explicitly.
            kwargs["data"] = json.dumps(payload)
            kwargs["headers"] = {"Content-Type": "application/json"}
        else:
            kwargs["data"] = payload if isinstance(payload, str) else _form_encode(payload)
            # Required: aiohttp sends a string body as text/plain, which makes
            # the server see an empty form. Without this every scripted
            # form login fails while looking like a network error.
            kwargs["headers"] = {
                "Content-Type": content_type or "application/x-www-form-urlencoded"
            }

        try:
            result = await curl(url, method=method, identity=self.name, **kwargs)
        except Exception as exc:  # network failure is not a hard error here
            self.verification_note = f"login raised: {exc}"
            return False

        if result.get("status", 0) in (0, 500, 502, 503):
            self.verification_note = f"login returned {result.get('status')}"
            return False

        # Adopt cookies the server handed us during login so later requests
        # reuse the session instead of re-authenticating.
        engine = get_engine()
        harvested = engine.cookies_for(self.name)
        if harvested:
            self.cookies = {**harvested, **self.cookies}

        if spec.get("extract_token"):
            token = _extract_token(result.get("body", ""))
            if token:
                self.bearer_token = token
                self.headers.setdefault("Authorization", f"Bearer {token}")

        return True

    # ── Verification ─────────────────────────────────────────────

    async def verify(self, base_url: str = "") -> bool:
        """Confirm this session reaches authenticated content.

        A login that fails typically returns 200 and the login form again, so
        status alone proves nothing. Three independent signals are required:
        a non-login response, no password field in the body, and the
        configured success marker when one is given.
        """
        url = self.verify_url or base_url
        if not url:
            self.verified = bool(self.cookies or self.bearer_token)
            self.verification_note = (
                "assumed authenticated — no verify_url configured"
                if self.verified else "no credentials and no verify_url"
            )
            return self.verified

        try:
            result = await curl(
                url,
                headers=self.request_headers(),
                identity=self.name,
                output="body",
                follow_redirects=True,
            )
        except Exception as exc:
            self.verified = False
            self.verification_note = f"verify raised: {exc}"
            return False

        status = result.get("status", 0)
        body = (result.get("body", "") or "").lower()
        final_url = (result.get("url", "") or url).lower()

        if status in (401, 403):
            self.verified = False
            self.verification_note = f"server returned {status}"
            return False
        if status == 0:
            self.verified = False
            self.verification_note = f"transport error: {result.get('error', 'unknown')}"
            return False

        # Redirected back to a login page means the session never took.
        path = urlparse(final_url).path.lower()
        if any(hint in path for hint in _LOGIN_PATH_HINTS):
            self.verified = False
            self.verification_note = f"redirected to {path}"
            return False

        for marker in _ANON_MARKERS:
            if marker in body:
                self.verified = False
                self.verification_note = f"anonymous marker present: {marker!r}"
                return False

        if self.success_marker:
            if self.success_marker.lower() not in body:
                self.verified = False
                self.verification_note = (
                    f"success marker {self.success_marker!r} absent"
                )
                return False

        self.verified = True
        self.verification_note = f"verified against {final_url} (HTTP {status})"
        return True


def _form_encode(payload: Any) -> str:
    """Encode a dict as application/x-www-form-urlencoded."""
    if isinstance(payload, str):
        return payload
    from urllib.parse import urlencode
    return urlencode({k: v for k, v in (payload or {}).items() if v is not None})


_TOKEN_RE = re.compile(
    r'"(?:access_token|token|id_token|jwt)"\s*:\s*"([^"]{8,})"', re.IGNORECASE
)


def _extract_token(body: str) -> str:
    match = _TOKEN_RE.search(body or "")
    return match.group(1) if match else ""


class AuthHarness:
    """The set of configured identities, plus the request helper they share."""

    def __init__(self, config: dict | None = None):
        config = config or {}
        auth_cfg = (config.get("auth") or {}) if isinstance(config, dict) else {}
        self.raw_config = auth_cfg
        self.identities: dict[str, Identity] = {}
        self._load(auth_cfg)

    def _load(self, auth_cfg: dict) -> None:
        entries = auth_cfg.get("identities") or []
        if isinstance(entries, dict):
            # Also accept `identities: {user_a: {...}, user_b: {...}}`.
            entries = [{"name": k, **v} for k, v in entries.items()]
        if not isinstance(entries, list):
            return

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").strip()
            if not name:
                continue
            identity = Identity(
                name=name,
                cookies=_as_str_dict(entry.get("cookies")),
                headers=_as_str_dict(entry.get("headers")),
                bearer_token=str(entry.get("bearer_token") or entry.get("token") or ""),
                login=entry.get("login") or {},
                verify_url=str(entry.get("verify_url") or ""),
                success_marker=str(entry.get("success_marker") or ""),
            )
            self.identities[name] = identity

    # ── Introspection ────────────────────────────────────────────

    @property
    def usable(self) -> list[Identity]:
        """Identities that have been proven to hold a live session."""
        return [i for i in self.identities.values() if i.verified]

    def has_pair(self) -> bool:
        """True when at least two verified accounts exist.

        Horizontal privilege testing needs two; with one, only anonymous
        exposure can be checked.
        """
        return len(self.usable) >= 2

    def summary(self) -> str:
        if not self.identities:
            return "no identities configured"
        return ", ".join(
            f"{i.name}{'' if i.verified else ' (unverified)'}"
            for i in self.identities.values()
        )

    # ── Lifecycle ────────────────────────────────────────────────

    async def establish_all(self, base_url: str = "") -> list[Identity]:
        for identity in self.identities.values():
            try:
                await identity.establish(base_url)
            except AuthError:
                identity.verified = False
                identity.verification_note = "invalid identity configuration"
        return self.usable

    # ── Requests ─────────────────────────────────────────────────

    async def request(self, identity: str, url: str, **kwargs) -> dict:
        """Issue a request as a named identity.

        Merges the identity's headers into whatever the caller passed, so a
        module can supply per-request headers without discarding the session.
        """
        ident = self.identities.get(identity)
        headers = dict(kwargs.pop("headers", None) or {})
        if ident is not None:
            merged = ident.request_headers()
            merged.update(headers)
            headers = merged
        kwargs.setdefault("output", "body")
        return await curl(url, headers=headers or None, identity=identity, **kwargs)

    async def request_anonymous(self, url: str, **kwargs) -> dict:
        """Issue a request with no session at all.

        Uses a dedicated identity so it cannot inherit cookies from the
        authenticated sessions.
        """
        kwargs.setdefault("output", "body")
        return await curl(url, identity="__anonymous__", **kwargs)


def _as_str_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items() if k and v is not None and str(v) != ""}


def fingerprint_body(body: str) -> dict:
    """A stable summary of a response body, for cross-identity comparison.

    Deliberately not a hash: the caller needs to inspect the actual values to
    decide whether leaked content is genuinely another user's data.
    """
    text = body or ""
    lowered = text.lower()
    return {
        "length": len(text),
        "words": len(text.split()),
        "lines": len(text.splitlines()),
        # Stable identity for "same page or different page" comparisons.
        "digest": _stable_digest(text),
        "emails": sorted(set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", text))),
        "json": _maybe_json(text),
        "has_login_form": any(m in lowered for m in _ANON_MARKERS),
    }


def _stable_digest(text: str) -> str:
    """Process-independent hash — `hash()` is salted per interpreter run."""
    import hashlib
    return hashlib.sha256(text[:20000].encode("utf-8", errors="replace")).hexdigest()[:16]


def _maybe_json(text: str) -> Any:
    stripped = text.strip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return None
