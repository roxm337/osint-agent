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

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

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
    basic_auth: tuple = ()          # (user, password) for HTTP Basic
    login: dict[str, Any] = field(default_factory=dict)
    verify_url: str = ""
    success_marker: str = ""
    verified: bool = False
    verification_note: str = ""
    # Who this account is, so a response can be attributed to it. Usually
    # read from the bearer token's own claims; overridden by config.
    email: str = ""
    owner_id: str = ""
    owner_markers: tuple = ()
    role: str = ""

    _PRIVILEGED_ROLES = frozenset({
        "admin", "administrator", "root", "superadmin", "superuser",
        "owner", "manager", "staff", "moderator", "internal",
    })

    @property
    def privileged(self) -> bool:
        """Whether this account sits above an ordinary peer.

        Used only to choose which direction of a leak gets reported first.
        An administrator reading a customer's record may be entitled to it,
        so naming that pair as the finding would understate the bug, while a
        customer reading another customer's record is the case nobody can
        argue with. The role comes from config or from the account's own
        token claims; an unknown role counts as ordinary.
        """
        role = str(self.role or "").strip()
        if not role:
            role = str(self._token_claims().get("role") or "").strip()
        return role.lower() in self._PRIVILEGED_ROLES

    def describe(self) -> str:
        bits = []
        if self.cookies:
            bits.append(f"{len(self.cookies)} cookie(s)")
        if self.bearer_token:
            bits.append("bearer token")
        if self.basic_auth:
            bits.append("basic auth")
        if self.login:
            bits.append("login flow")
        return f"{self.name} ({', '.join(bits) or 'no credentials'})"

    def request_headers(self) -> dict[str, str]:
        headers = dict(self.headers)
        if "Authorization" not in headers:
            if self.bearer_token:
                headers["Authorization"] = f"Bearer {self.bearer_token}"
            elif self.basic_auth:
                import base64
                raw = f"{self.basic_auth[0]}:{self.basic_auth[1]}"
                encoded = base64.b64encode(raw.encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"
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

        if self.cookies:
            # Seed the engine jar so every later request carries the session.
            get_engine().set_cookies(self.cookies, identity=self.name)

        return await self.verify(base_url)

    def has_credentials(self) -> bool:
        """Whether any authentication material is configured at all.

        Basic auth is stateless, so there is nothing to seed into the cookie
        jar — the header travels with each request. It still counts as a
        credential, and leaving it out made a correctly configured Basic
        identity look credential-less to the fallback path.
        """
        return bool(self.cookies or self.bearer_token or self.basic_auth
                    or self.headers.get("Authorization"))

    # Claims that name a specific account rather than a role or a scope.
    # `role: admin` and `iss:` are deliberately absent: they are shared by
    # every admin and would attribute one account's record to another.
    _TOKEN_OWNER_CLAIMS = frozenset({
        "id", "sub", "email", "username", "user_id", "userid",
        "preferred_username", "name",
    })

    def own_markers(self) -> set[str]:
        """Values that mark a response as belonging to *this* account.

        Attribution needs the other side: without your own id you cannot say
        whether `UserId: 27` in a basket you just read is yours or somebody
        else's, and every leak collapses to "unattributed" no matter how
        complete the payload is.

        Sourced from the account's own bearer token, whose claims it is
        entitled to read, so no extra endpoint or configuration is needed.
        Only account-naming claims are taken — `role` and `iss` identify a
        class, not a person.
        """
        markers: set[str] = set()

        for configured in (self.email, self.owner_id, *self.owner_markers):
            value = str(configured).strip().lower()
            if value:
                markers.add(value)

        claims = self._token_claims()
        for key, value in claims.items():
            flat = str(key).lower().replace("-", "_").replace("_", "")
            if flat in {c.replace("_", "") for c in self._TOKEN_OWNER_CLAIMS}:
                raw = str(value).strip().lower()
                if raw:
                    markers.add(raw)
        return markers

    def _token_claims(self) -> dict[str, Any]:
        """Flattened claims of a JWT, without verifying it.

        No signature check: the token belongs to this identity and we are
        only asking it who it says it is.
        """
        token = str(self.bearer_token or "")
        if token.count(".") != 2:
            return {}
        try:
            segment = token.split(".")[1]
            segment += "=" * (-len(segment) % 4)
            decoded = json.loads(base64.urlsafe_b64decode(segment.encode()))
        except Exception:
            return {}

        flat: dict[str, Any] = {}

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    if isinstance(value, (dict, list)):
                        walk(value)
                    elif not isinstance(value, bool):
                        flat[str(key)] = value
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        if isinstance(decoded, dict):
            walk(decoded)
        return flat

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
        is_json = content_type == "json" or spec.get("json") is True

        # Hidden fields the server put in the form: CSRF tokens, authenticity
        # tokens, and framework bookkeeping. Django, Rails, Laravel, Spring and
        # most enterprise stacks reject a login POST that omits these, so a
        # scripted login that skips the page fetch fails for a reason that has
        # nothing to do with the credentials.
        extra_headers: dict[str, str] = {}
        if spec.get("csrf", True) and not is_json:
            page = await self._fetch_form_page(url, spec)
            # A raw string body is parsed first so hidden fields can still be
            # merged; dropping the page fields there would silently discard
            # the caller's own credentials.
            if isinstance(payload, str):
                merged = dict(parse_qsl(payload.lstrip("?"), keep_blank_values=True))
            else:
                merged = dict(payload or {})
            payload = {**page["fields"], **merged}
            for cookie_name, cookie_value in page["cookies"].items():
                get_engine().set_cookies({cookie_name: cookie_value}, identity=self.name)
            if page["referer"]:
                extra_headers["Referer"] = page["referer"]

        kwargs: dict[str, Any] = {"output": "full", "follow_redirects": True}
        if is_json:
            # The wrapper takes a body string, not a dict, so the JSON is
            # encoded here and the content type set explicitly.
            kwargs["data"] = json.dumps(payload)
            kwargs["headers"] = {"Content-Type": "application/json"}
        else:
            kwargs["data"] = _form_encode(payload)
            # Required: aiohttp sends a string body as text/plain, which makes
            # the server see an empty form. Without this every scripted
            # form login fails while looking like a network error.
            kwargs["headers"] = {
                "Content-Type": content_type or "application/x-www-form-urlencoded",
                **extra_headers,
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

        if spec.get("extract_token", True):
            token = _extract_token(result.get("body", ""))
            if token and not self.bearer_token:
                self.bearer_token = token
                self.headers.setdefault("Authorization", f"Bearer {token}")

        return True

    async def _fetch_form_page(self, url: str, spec: dict) -> dict:
        """GET the login page and harvest its hidden fields and cookies.

        A failure here is not fatal: plenty of applications need no CSRF token,
        and the login POST is still worth sending.
        """
        page = {"fields": {}, "cookies": {}, "referer": url}
        try:
            result = await curl(url, method="GET", identity=self.name, output="body")
        except Exception:
            return page

        if result.get("status", 0) in (0, 404, 500, 502, 503):
            return page

        body = result.get("body", "") or ""
        page["fields"] = _hidden_form_fields(body)
        page["cookies"] = dict(get_engine().cookies_for(self.name))
        return page

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
            self.verified = self.has_credentials()
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
    return urlencode({k: v for k, v in (payload or {}).items() if v is not None})


_TOKEN_RE = re.compile(
    r'"(?:access_token|token|id_token|jwt)"\s*:\s*"([^"]{8,})"', re.IGNORECASE
)

# `<input type="hidden" name="csrfmiddlewaretoken" value="...">` in any
# attribute order, which is how every mainstream framework emits them.
_HIDDEN_INPUT_RE = re.compile(
    r"<input\b[^>]*\btype\s*=\s*[\"']?hidden[\"']?[^>]*>", re.IGNORECASE
)
_ATTR_RE = re.compile(r"""(\w[\w:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")


def _hidden_form_fields(html: str) -> dict:
    """Name/value pairs from every hidden input on the page.

    Returned fields are merged *under* the caller's explicit `data`, so a
    configured field always wins over one scraped from the page and a stale
    token in the config cannot silently override the live one.
    """
    fields: dict[str, str] = {}
    for tag in _HIDDEN_INPUT_RE.findall(html or ""):
        attrs: dict[str, str] = {}
        for match in _ATTR_RE.finditer(tag):
            name = match.group(1).lower()
            value = match.group(2) or match.group(3) or match.group(4) or ""
            attrs[name] = value
        name = attrs.get("name")
        if name:
            fields[name] = attrs.get("value", "")
    return fields


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
                basic_auth=_basic_pair(entry.get("basic_auth") or entry.get("basic")),
                login=entry.get("login") or {},
                verify_url=str(entry.get("verify_url") or ""),
                email=str(entry.get("email") or ""),
                owner_id=str(entry.get("owner_id") or ""),
                owner_markers=tuple(
                    str(v) for v in (entry.get("owner_markers") or [])
                ),
                role=str(entry.get("role") or ""),
                # Earlier documentation put this inside `login`, so both are
                # honoured. A top-level value wins.
                success_marker=str(
                    entry.get("success_marker")
                    or (entry.get("login") or {}).get("success_marker")
                    or ""
                ),
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

    # ── Lifecycle ────────────────────────────────────────────

    def adopt_discovered(self, state, log=None) -> int:
        """Adopt sessions auth_audit captured earlier in the run.

        Config identities are static; a SQLi-bypassed admin session or a
        default credential discovered ten minutes ago is a live identity
        too. Without this merge, differential testing stays parked behind
        a config file nobody filled in. Returns the adopted count.
        """
        adopted = 0
        for asset in state.get_assets_by_type("identity_credential"):
            attrs = asset.get("attrs", {}) or {}
            token = str(attrs.get("token", "") or "")
            if not token or token.startswith("cookie:"):
                continue
            name = str(asset.get("value", "")
                       or attrs.get("technique", "discovered"))
            if name in self.identities:
                continue
            self.identities[name] = Identity(
                name=name,
                bearer_token=token,
                email=str(attrs.get("endpoint", "")),
                role=str(attrs.get("role", "") or ""),
            )
            adopted += 1
            if log is not None:
                try:
                    log(f"  Adopted discovered session: {name}")
                except Exception:
                    pass
        return adopted

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
        authenticated sessions, and additionally drops the globally configured
        `Cookie`/`Authorization` headers. Without that, a run configured with
        the legacy single-session `auth.cookies` would send a live credential
        here and report an ordinary authenticated read as a public exposure.
        """
        kwargs.setdefault("output", "body")
        return await curl(url, identity="__anonymous__", no_session=True, **kwargs)


def _as_str_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items() if k and v is not None and str(v) != ""}


def _basic_pair(value: Any) -> tuple:
    """Accept `basic_auth: {user: a, password: b}` or a two-item sequence."""
    if isinstance(value, dict):
        user = str(value.get("user") or value.get("username") or "")
        password = str(value.get("password") or value.get("pass") or "")
        return (user, password) if user else ()
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return (str(value[0]), str(value[1]))
    return ()


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
