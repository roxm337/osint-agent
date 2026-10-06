"""Stage 3: HTTP response-header audit — CSP policy, cookie flags, methods.

Missing headers are tech_detection's beat (one collapsed LOW). This
module reads the policies that ARE present: a CSP of
`script-src * unsafe-inline` is worse than no CSP for triage purposes
because it claims protection, session cookies without HttpOnly or
SameSite are session theft waiting for one XSS, and TRACE enabled
with echo is cross-site tracing. Absence is not re-reported here.
"""

from urllib.parse import urlparse

from modules.base import BaseModule
from tools.wrappers import curl


# Cookie names that carry sessions; everything else is audited only in
# aggregate, never filed on.
_SESSION_COOKIE_HINTS = (
    "session", "sess", "auth", "token", "jwt", "sid", "phpsessid",
    "jsession", "aspsession", "csrf", "xsrf", "remember", "login",
)

# script-src allowances that defeat the policy they sit in.
_CSP_UNSAFE = ("unsafe-inline", "unsafe-eval")


class HeadersAudit(BaseModule):
    id = "headers_audit"
    name = "HTTP Header Audit"
    stage = 3
    detectability = "low"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        pages = self._pages()
        if not pages:
            self.state.skip_module(self.id, "no pages discovered")
            return "skipped"

        csp_seen = set()
        cookies_seen: dict[str, dict] = {}
        for url in pages[:12]:
            try:
                result = await curl(url, output="full", timeout=15)
            except Exception:
                continue
            headers = _parse_headers(result.get("headers", ""))
            csp = headers.get("content-security-policy", "")
            if csp and csp not in csp_seen:
                csp_seen.add(csp)
                self._audit_csp(url, csp)
            for name, attrs in _parse_cookies(
                    result.get("headers", "")).items():
                cookies_seen.setdefault(name, attrs)
            if len(cookies_seen) > 40:
                break

        for name, attrs in cookies_seen.items():
            self._audit_cookie(name, attrs)

        await self._audit_methods()

        self.state.add_asset(
            "headers_audit",
            f"headers:{self.domain}",
            self.domain,
            confidence="CONFIRMED",
            sources=[self.id],
            attrs={"pages_checked": min(len(pages), 12),
                   "csp_policies": len(csp_seen),
                   "cookies": sorted(cookies_seen)},
        )
        self.state.complete_module(self.id)
        self.log(f"Header audit: {len(csp_seen)} CSP(s), "
                 f"{len(cookies_seen)} cookie(s)")
        return "done"

    def _pages(self) -> list:
        pages = []
        for asset in self.state.get_assets_by_type("url"):
            value = str(asset.get("value", "") or "")
            if value.startswith(("http://", "https://")) \
                    and value not in pages:
                pages.append(value)
        for asset in self.state.get_assets_by_type("webapp"):
            value = str(asset.get("value", "") or "")
            if value.startswith(("http://", "https://")) \
                    and value not in pages:
                pages.append(value)
        if self.base_url not in pages:
            pages.append(self.base_url)
        return pages

    def _audit_csp(self, url: str, csp: str) -> None:
        """A present-but-permissive policy is a finding; absence is not."""
        directives = {}
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            directives[tokens[0].lower()] = [t.strip("'\"") for t in tokens[1:]]
        script_src = directives.get("script-src", [])
        problems = []
        if any(token in _CSP_UNSAFE for token in script_src):
            problems.append("script-src allows %s" % ", ".join(
                token for token in script_src if token in _CSP_UNSAFE))
        if "*" in script_src or "data:" in script_src:
            problems.append("script-src allows wildcard/data: sources")
        if "object-src" not in directives:
            problems.append("no object-src directive (plugins unrestricted)")
        if problems:
            self.state.add_finding(
                title="Weak Content-Security-Policy",
                severity="MEDIUM",
                confidence="CONFIRMED",
                category="Hardening Deficiency",
                description=(
                    f"CSP at {url} is present but permissive: "
                    f"{'; '.join(problems)}. A policy claiming protection "
                    f"while allowing inline scripts misleads triage worse "
                    f"than no policy."),
                evidence=[f"URL: {url}", f"CSP: {csp[:300]}"]
                + [f"Issue: {problem}" for problem in problems],
                remediation="Remove unsafe-inline/unsafe-eval, drop wildcards "
                            "from script-src, add object-src 'none'.",
                asset_keys=[f"url:{url}"],
            )

    def _audit_cookie(self, name: str, attrs: dict) -> None:
        lowered = name.lower()
        if not any(hint in lowered for hint in _SESSION_COOKIE_HINTS):
            return
        issues = []
        if not attrs.get("httponly"):
            issues.append("missing HttpOnly (script-readable session)")
        samesite = str(attrs.get("samesite", "") or "").lower()
        if samesite not in ("lax", "strict"):
            issues.append(f"SameSite {samesite or 'unset'} "
                          "(cross-site sending allowed)")
        if not issues:
            return
        self.state.add_finding(
            title=f"Session Cookie Missing Flags: {name}",
            severity="MEDIUM" if not attrs.get("httponly") else "LOW",
            confidence="CONFIRMED",
            category="Hardening Deficiency",
            description=(
                f"Session cookie {name} sets "
                f"{'; '.join(issues)}. One stored XSS becomes session "
                f"theft without HttpOnly; lax CSRF posture without SameSite."),
            evidence=[f"Cookie: {name}",
                      f"Attributes: {attrs.get('raw', '')[:200]}"],
            remediation="Set HttpOnly and SameSite=Lax (Strict for "
                        "high-value sessions); Secure on HTTPS.",
            asset_keys=[],
        )

    async def _audit_methods(self) -> None:
        """OPTIONS per origin: TRACE/TRACK echo and write verbs."""
        origins = set()
        for asset in (self.state.get_assets_by_type("url")
                      + self.state.get_assets_by_type("webapp")):
            try:
                parsed = urlparse(str(asset.get("value", "") or ""))
            except ValueError:
                continue
            if parsed.scheme and parsed.hostname:
                origins.add(f"{parsed.scheme}://{parsed.netloc}")
        origins.add(self.base_url.rstrip("/"))
        for origin in sorted(origins)[:3]:
            try:
                result = await curl(origin + "/", method="OPTIONS",
                                    output="full", timeout=15)
            except Exception:
                continue
            headers = _parse_headers(result.get("headers", ""))
            allow = headers.get("allow", "") or headers.get(
                "access-control-allow-methods", "")
            allowed = {method.strip().upper()
                       for method in allow.split(",") if method.strip()}
            if "TRACE" in allowed or "TRACK" in allowed:
                # TRACE echo check: does the server reflect the request?
                echo = await self._trace_echo(origin)
                self.state.add_finding(
                    title=f"HTTP TRACE Enabled: {origin}",
                    severity="MEDIUM" if echo else "LOW",
                    confidence="CONFIRMED",
                    category="Hardening Deficiency",
                    description=(
                        f"{origin} answers TRACE"
                        f"{' and echoes request content (cross-site tracing '
                          'primitive)' if echo else ''}. "
                        f"Allowed: {allow or 'TRACE/TRACK advertised'}."),
                    evidence=[f"Origin: {origin}", f"Allow: {allow}"]
                    + (["TRACE body echoed the request"] if echo else []),
                    remediation="Disable TRACE and TRACK; they exist for "
                                "debugging, not production.",
                    asset_keys=[],
                )
            write_verbs = sorted({"PUT", "DELETE", "PATCH"} & allowed)
            if write_verbs:
                self.state.add_finding(
                    title=f"Write Verbs Advertised: {origin}",
                    severity="INFO",
                    confidence="CONFIRMED",
                    category="Attack Surface",
                    description=(
                        f"{origin} advertises {', '.join(write_verbs)} via "
                        f"Allow. Not a flaw alone — but write-access probes "
                        f"should include this origin."),
                    evidence=[f"Origin: {origin}", f"Allow: {allow}"],
                    remediation="No action unless a verb proves reachable "
                                "without authorization.",
                    asset_keys=[],
                )

    async def _trace_echo(self, origin: str) -> bool:
        """TRACE with a marker body: echoed back means XST-shape."""
        marker = "trace-echo-probe-7f3a"
        try:
            result = await curl(
                origin + "/", method="TRACE",
                headers={"Content-Type": "text/plain"},
                data=marker, output="full", timeout=15)
        except Exception:
            return False
        return marker in (result.get("body", "") or "")


def _parse_headers(raw) -> dict:
    """Raw header block (or dict) to lowercase-name mapping."""
    if isinstance(raw, dict):
        return {str(k).lower(): v for k, v in raw.items()}
    headers = {}
    for line in str(raw or "").splitlines():
        if ":" in line and not line.startswith("HTTP/"):
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    return headers


def _parse_cookies(raw) -> dict:
    """Set-Cookie lines to {name: {httponly, secure, samesite, raw}}."""
    if isinstance(raw, dict):
        lines = [f"{k}: {v}" for k, v in raw.items()
                 if k.lower() == "set-cookie"]
        if isinstance(raw.get("set-cookie"), list):
            lines = [f"set-cookie: {v}" for v in raw["set-cookie"]]
    else:
        lines = [line for line in str(raw or "").splitlines()
                 if line.lower().startswith("set-cookie:")]
    cookies = {}
    for line in lines:
        _, _, remainder = line.partition(":")
        parts = [part.strip() for part in remainder.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name, _, _ = parts[0].partition("=")
        flags = {part.lower() for part in parts[1:]}
        samesite = ""
        for part in parts[1:]:
            if part.lower().startswith("samesite="):
                samesite = part.split("=", 1)[1].strip()
        cookies[name.strip()] = {
            "httponly": "httponly" in flags,
            "secure": "secure" in flags,
            "samesite": samesite,
            "raw": remainder.strip()[:200],
        }
    return cookies
