"""Stage 4: Verbose error disclosure — stack traces and internals.

Error pages are recon: paths, framework versions, SQL fragments, and
internal hostnames leak through them. The oracle is a signature list
over 500s and error-shaped 200s/400s, gated on the site profile so a
branded error page (same shell, different title) does not count.
Triggers come from garbage paths, type violations on known endpoints,
and the error-shaped responses other modules already walked past.
"""

import re

from core.probe_targets import iter_probe_points
from modules.base import BaseModule
from tools.wrappers import curl


# (name, matcher): framework and runtime fingerprints in error bodies.
ERROR_SIGNATURES = (
    ("python-traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("node-stack", re.compile(r"at\s+[\w.]+\s+\([^)]*\.js:\d+:\d+\)")),
    ("express-error", re.compile(r"Error: .*?\n\s+at ", re.I)),
    ("sequelize-error", re.compile(r"Sequelize\w*Error")),
    ("sqlite-error", re.compile(r"SQLITE_ERROR")),
    ("mysql-error", re.compile(r"mysql_|mysqli?\.|You have an error in your SQL")),
    ("postgres-error", re.compile(r"pg_|PostgreSQL.*ERROR|relation .* does not exist")),
    ("mssql-error", re.compile(r"OLE DB|SQL Server.*[Ee]rror|Unclosed quotation")),
    ("oracle-error", re.compile(r"ORA-\d{5}")),
    ("java-stack", re.compile(r"at [\w.$]+\([\w.]+java:\d+\)")),
    ("dotnet-stack", re.compile(r"System\.\w+Exception|at System\.")),
    ("php-error", re.compile(r"Fatal error|Parse error|Warning: .*\.php")),
    ("ruby-stack", re.compile(r"\.rb:\d+:in ")),
    ("go-panic", re.compile(r"goroutine \d+ \[|panic:")),
    ("rust-panic", re.compile(r"panicked at .*\.rs:")),
    ("django-debug", re.compile(r"Django Version|Traceback.*django")),
    ("laravel-error", re.compile(r"Whoops|ignition|laravel\.log")),
    ("spring-error", re.compile(r"Whitelabel Error Page|org\.springframework")),
    ("path-disclosure", re.compile(r"/(?:home|var|opt|srv|app|usr)/[\w\-./]+")),
    ("sql-fragment", re.compile(r"SELECT .* FROM .* WHERE", re.I | re.S)),
)

_GARBAGE_PATHS = (
    "/nonexistent-zz9/[id",
    "/api/[%22",
    "/rest/%ff%fe",
)


class ErrorAudit(BaseModule):
    id = "error_audit"
    name = "Verbose Error Disclosure Audit"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        self.profile = await self._profile()
        reported = 0

        # 1. Garbage paths: what does the error page say?
        for path in _GARBAGE_PATHS:
            if await self._check_url(f"{self.base_url}{path}", "garbage path"):
                reported += 1

        # 2. Type violations on known endpoints: /api/Users/abc,
        # /rest/basket/xyz — typed routers confess in 500s.
        for asset in self.state.get_assets_by_type("api_endpoint"):
            value = str(asset.get("value", "") or "")
            if "{id}" in value or value.rstrip("/").split("/")[-1].isdigit():
                continue
            base = value.rstrip("/")
            if await self._check_url(f"{base}/abcXYZ", "type violation"):
                reported += 1
                if reported >= 5:
                    break

        # 3. Replays: error-shaped 200s other modules recorded. A 200
        # carrying a stack trace passed every status gate upstream.
        for point in iter_probe_points(self.state, self.base_url,
                                       self.domain)[:20]:
            url = point["url"]
            try:
                result = await curl(url, output="full", timeout=15)
            except Exception:
                continue
            body = result.get("body", "") or ""
            if result.get("status", 0) == 200 and body:
                if await self._grade(url, body, result.get("status", 0),
                                     "replay"):
                    reported += 1
                    if reported >= 8:
                        break

        self.state.complete_module(self.id)
        self.log(f"Error disclosure: {reported} verbose error(s)")
        return "done"

    async def _profile(self):
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

    async def _check_url(self, url: str, source: str) -> bool:
        try:
            result = await curl(url, output="full", timeout=15)
        except Exception:
            return False
        return await self._grade(url, result.get("body", "") or "",
                                 result.get("status", 0), source)

    async def _grade(self, url: str, body: str, status: int,
                     source: str) -> bool:
        """File when a stack/internal signature fires on a non-default page."""
        if status not in (200, 400, 404, 500, 502, 503):
            return False
        if not body or len(body) < 100:
            return False
        profile = getattr(self, "profile", None)
        if profile is not None:
            from core.response_fingerprint import fingerprint as make_fingerprint
            if profile.baseline.catch_all(make_fingerprint(status, body)):
                return False
        matched = sorted({name for name, pattern in ERROR_SIGNATURES
                          if pattern.search(body)})
        if not matched:
            return False
        self.state.add_finding(
            title=f"Verbose Error Disclosure: {url}",
            severity="LOW",
            confidence="CONFIRMED",
            category="Information Disclosure",
            description=(
                f"Error responses at {url} carry internals "
                f"({', '.join(matched)}): framework, paths, or query "
                f"fragments useful for targeting."),
            evidence=[f"URL: {url} ({source})",
                      f"Signatures: {', '.join(matched)}",
                      f"Excerpt: {body[:250]}"],
            remediation="Replace verbose errors with generic messages; log "
                        "details server-side only.",
            asset_keys=[f"url:{url}"],
            verified=True,
            verification={"method": "error_signature_match", "url": url},
        )
        return True
