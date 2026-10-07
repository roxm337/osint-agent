"""Stage 2: Wayback Machine + URLScan — URL mining, JS extraction, parameter analysis."""

import asyncio
import re
from urllib.parse import urlparse, parse_qs
from modules.base import BaseModule
from tools.wrappers import wayback_cdx, urlscan_search, curl_with_status, gau_urls


SENSITIVE_URL_PARAMS = {
    "api_key", "apikey", "api-key", "token", "access_token", "auth_token",
    "secret", "password", "passwd", "pwd", "private_key", "client_secret",
    "client_id", "session", "sessionid", "jwt", "bearer", "key", "hash",
}

INTERESTING_EXTENSIONS = {
    ".js", ".json", ".xml", ".yml", ".yaml", ".env", ".bak", ".sql",
    ".log", ".txt", ".pdf", ".xlsx", ".xls", ".docx", ".zip", ".tar.gz",
    ".conf", ".config", ".inc", ".php", ".asp", ".aspx",
}


def _classify_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path.lower()
    ext = "." + path.rsplit(".", 1)[-1] if "." in path.split("/")[-1] else ""
    params = parse_qs(parsed.query)

    if any(p in params for p in SENSITIVE_URL_PARAMS):
        return "sensitive_param"
    if ext in (".js",):
        return "javascript"
    if any(kw in path for kw in ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"]):
        return "api_endpoint"
    if ext in (".json", ".xml", ".yml", ".yaml"):
        return "data_file"
    if ext in (".env", ".bak", ".sql", ".conf", ".config", ".inc", ".log"):
        return "sensitive_file"
    if ext in (".pdf", ".xlsx", ".xls", ".docx", ".zip"):
        return "document"
    if any(kw in path for kw in ["/admin", "/backend", "/dashboard", "/manage",
                                   "/panel", "/private", "/internal"]):
        return "admin_path"
    return "normal"


class WaybackMachine(BaseModule):
    id = "wayback_machine"
    name = "Wayback Machine"
    stage = 2
    detectability = "low"
    depends_on = ["seed_discovery"]

    async def run(self) -> str:
        from core.validators import is_public_target
        if not is_public_target(self.domain):
            self.state.skip_module(self.id, "no web archives for non-public targets")
            return "skipped"
        self.log(f"Fetching Wayback CDX for {self.domain}...")

        # 1. Wayback CDX — include mimetype for filtering
        snapshots = await wayback_cdx(self.domain, limit=5000)

        # 2. gau (GetAllUrls) — combines Wayback, OTX, CommonCrawl
        self.log("Fetching URLs via gau (if available)...")
        gau_result = await gau_urls(self.domain, timeout=90)
        gau_urls_set = set(gau_result)

        if not snapshots and not gau_urls_set:
            self.log("No Wayback/gau results.")
            self.state.skip_module(self.id, "no data")
            return "skipped"

        # Merge all URLs
        all_urls = set()
        for snap in snapshots:
            url = snap.get("original", snap.get("url", ""))
            if url:
                all_urls.add(url)
        all_urls.update(gau_urls_set)

        self.log(f"Total unique URLs from all sources: {len(all_urls)}")

        # Categorize URLs
        categories = {
            "sensitive_param": [],
            "javascript": [],
            "api_endpoint": [],
            "data_file": [],
            "sensitive_file": [],
            "document": [],
            "admin_path": [],
            "normal": [],
        }

        unique_paths = set()
        unique_params = {}
        js_files = set()

        for url in all_urls:
            parsed = urlparse(url)
            path = parsed.path or "/"
            unique_paths.add(path)

            # Collect GET parameters
            params = parse_qs(parsed.query)
            for param in params:
                unique_params.setdefault(param, 0)
                unique_params[param] += 1

            category = _classify_url(url)
            categories[category].append(url)

            if category == "javascript":
                js_files.add(url)

        # Register JS files as assets for later analysis
        for js_url in list(js_files)[:100]:
            self.state.add_asset(
                "js_file",
                f"js:{js_url}",
                js_url,
                confidence="FIRM",
                sources=["wayback CDX", "gau"],
                attrs={"url": js_url},
            )

        # API endpoints
        for api_url in categories["api_endpoint"][:50]:
            self.state.add_asset(
                "api_endpoint",
                f"api:{api_url}",
                api_url,
                confidence="TENTATIVE",
                sources=["wayback CDX"],
                attrs={"url": api_url, "source": "historical"},
            )

        # Findings: sensitive URL parameters (potential secret leakage).
        # An archived ?key= is history, not a leak: only live URLs whose
        # values are secret-shaped get HIGH. Everything else is context.
        sensitive_param_urls = categories["sensitive_param"]
        if sensitive_param_urls:
            found_params = set()
            for url in sensitive_param_urls[:20]:
                params = parse_qs(urlparse(url).query)
                found_params.update(k for k in params if k.lower() in SENSITIVE_URL_PARAMS)
            live = await self._live_check(sensitive_param_urls, limit=8)
            live_with_values = {
                url: result for url, result in live.items() if result["live"]
            }
            secret_shaped = {}
            for url in live_with_values:
                values = []
                for value in parse_qs(urlparse(url).query).values():
                    values.extend(value)
                hits = [v for v in values if _secret_shaped(v)]
                if hits:
                    secret_shaped[url] = hits[:3]
            if secret_shaped:
                self.state.add_finding(
                    title="Live URLs With Secret-Shaped Parameter Values",
                    severity="MEDIUM",
                    confidence="FIRM",
                    category="Credential Exposure",
                    description=(
                        f"{len(secret_shaped)} currently reachable URL(s) carry "
                        "secret-shaped parameter values. Shape is not proof "
                        "a credential works — rotate on suspicion and never "
                        "pass secrets in URL parameters."),
                    evidence=[f"{url} :: {', '.join(vals)}"
                              for url, vals in list(secret_shaped.items())[:10]],
                    remediation="Rotate any credentials found in historical URLs; "
                                "never pass secrets in URL parameters.",
                    verified=True,
                    verification={"method": "live_shape_observed",
                                  "url": next(iter(secret_shaped))},
                )
            elif live_with_values:
                self.state.add_finding(
                    title="Live Historical URLs With Sensitive Parameter Names",
                    severity="LOW",
                    confidence="FIRM",
                    category="Credential Exposure",
                    description=(
                        f"{len(live_with_values)} archived URL(s) with sensitive "
                        f"parameter names ({sorted(found_params)}) are still "
                        "reachable, but no value is secret-shaped. Watch these "
                        "parameters during active testing."),
                    evidence=list(live_with_values)[:10],
                    remediation="Confirm handlers validate these parameters; "
                                "never pass secrets in URL parameters.",
                )
            else:
                self.state.add_finding(
                    title="Sensitive Parameters in Historical URLs (Archive Only)",
                    severity="INFO",
                    confidence="FIRM",
                    category="Credential Exposure",
                    description=(
                        f"{len(sensitive_param_urls)} historical URL(s) with "
                        f"sensitive parameter names ({sorted(found_params)}); "
                        "none is reachable now. Archive context only."),
                    evidence=[url for url in sensitive_param_urls[:10]],
                    remediation="Rotate any credentials found in historical URLs; "
                                "never pass secrets in URL parameters.",
                )

        # Findings: sensitive file extensions in history. A live 200 with a
        # body that is not the site default is exposure; anything else is
        # archive context.
        sensitive_files = categories["sensitive_file"]
        if sensitive_files:
            live = await self._live_check(sensitive_files, limit=8)
            confirmed = [url for url, result in live.items() if result["live"]]
            if confirmed:
                self.state.add_finding(
                    title="Sensitive Files Reachable Now",
                    severity="MEDIUM",
                    confidence="FIRM",
                    category="Information Disclosure",
                    description=f"{len(confirmed)} historically sensitive file(s) "
                                "return live content distinct from the site default.",
                    evidence=[f"{url} (HTTP {live[url]['status']})"
                              for url in confirmed[:10]],
                    remediation="Verify these files are no longer accessible; check current state.",
                    verified=True,
                    verification={"method": "live_distinct_content",
                                  "url": confirmed[0] if confirmed else ""},
                )
            else:
                self.state.add_finding(
                    title="Sensitive File URLs in Archive (Not Live)",
                    severity="INFO",
                    confidence="FIRM",
                    category="Information Disclosure",
                    description=f"{len(sensitive_files)} historically accessed sensitive files "
                                f"found (.env, .bak, .sql, .conf, .log, etc.); "
                                "none is reachable now.",
                    evidence=[url for url in sensitive_files[:10]],
                    remediation="Verify these files are no longer accessible; check current state.",
                )

        # Findings: admin paths in history. A live 200/401/403 is
        # authenticated surface worth noting; dead paths are context.
        admin_paths = categories["admin_path"]
        if admin_paths:
            unique_admin = list({urlparse(u).path for u in admin_paths})[:15]
            live = await self._live_check(admin_paths, limit=8)
            live_admin = sorted({urlparse(u).path for u, result in live.items()
                                 if result["live"]})
            if live_admin:
                self.state.add_finding(
                    title="Admin/Internal Paths Reachable Now",
                    severity="LOW",
                    confidence="FIRM",
                    category="Attack Surface",
                    description=f"{len(live_admin)} admin/internal path(s) answer "
                                "live (200 with distinct content, or auth challenge).",
                    evidence=live_admin[:10],
                    remediation="Verify admin paths require authentication and are not publicly accessible.",
                )
            else:
                self.state.add_finding(
                    title="Admin/Internal Paths in Archive (Not Live)",
                    severity="INFO",
                    confidence="FIRM",
                    category="Attack Surface",
                    description=f"{len(admin_paths)} historical admin/internal paths enumerated; "
                                "none answers live.",
                    evidence=unique_admin[:10],
                    remediation="Verify admin paths require authentication and are not publicly accessible.",
                )

        # Store main asset
        top_params = sorted(unique_params.items(), key=lambda x: -x[1])[:30]
        self.state.add_asset(
            "wayback_data",
            f"wayback:{self.domain}",
            f"{self.domain} wayback",
            confidence="CONFIRMED",
            sources=["wayback CDX", "gau"],
            attrs={
                "total_urls": len(all_urls),
                "unique_paths": len(unique_paths),
                "js_files": len(js_files),
                "api_endpoints": len(categories["api_endpoint"]),
                "sensitive_files": len(categories["sensitive_file"]),
                "sensitive_param_urls": len(categories["sensitive_param"]),
                "top_parameters": [p for p, _ in top_params],
                "oldest": min((s.get("timestamp", "") for s in snapshots), default=""),
                "newest": max((s.get("timestamp", "") for s in snapshots), default=""),
            },
        )

        self.state.complete_module(self.id)
        self.log(
            f"Wayback: {len(all_urls)} URLs | JS: {len(js_files)} | "
            f"API: {len(categories['api_endpoint'])} | "
            f"Sensitive params: {len(sensitive_param_urls)}"
        )
        return "done"

    async def _live_check(self, urls: list, limit: int = 8) -> dict:
        """Fetch the live equivalent of archived URLs.

        Returns {original_url: {"live", "status", "note"}}. Liveness is
        judged through the shared site profile, not a bare status: a 200
        of the SPA shell is the catch-all talking, and only a response
        distinct from the site's own default counts as live. Only
        in-scope hosts are probed.
        """
        from core.response_fingerprint import fingerprint as make_fingerprint
        from core.site_profile import get_profile

        base = (self.base_url or f"https://{self.domain}").rstrip("/")

        async def fetch(path: str):
            try:
                result = await curl_with_status(base + path, timeout=10)
            except Exception:
                return 0, "", ""
            return (result.get("status", 0),
                    result.get("body", "") or "", "")

        try:
            profile = await get_profile(base, fetch)
        except Exception:
            profile = None

        targets = []
        for original in urls[:limit]:
            try:
                parsed = urlparse(str(original))
            except Exception:
                continue
            host = (parsed.hostname or "").lower()
            apex = self.domain.lower()
            if host != apex and not host.endswith("." + apex):
                continue
            live_path = (parsed.path or "/")
            if parsed.query:
                live_path += "?" + parsed.query
            targets.append((original, live_path))

        semaphore = asyncio.Semaphore(6)

        async def probe(original: str, live_path: str):
            async with semaphore:
                status, body, _content_type = await fetch(live_path)
            if profile is not None:
                is_default = profile.baseline.catch_all(
                    make_fingerprint(status, body))
            else:
                is_default = not body
            if status == 200 and body and not is_default:
                return original, {"live": True, "status": status,
                                  "note": "live 200, distinct from site default"}
            if status in (401, 403):
                return original, {"live": True, "status": status,
                                  "note": f"live {status} (protected)"}
            return original, {"live": False, "status": status,
                              "note": f"HTTP {status}"}

        probed = await asyncio.gather(
            *(probe(original, live_path) for original, live_path in targets),
            return_exceptions=True,
        )
        return {original: result for original, result in probed
                if isinstance(result, dict)}


def _secret_shaped(value: str) -> bool:
    """Could this query value be a real credential, not a placeholder?"""
    text = str(value or "")
    if len(text) < 16:
        return False
    lowered = text.lower()
    if any(marker in lowered for marker in (
            "example", "test", "demo", "sample", "public", "undefined",
            "null", "none", "default", "changeme", "xxx")):
        return False
    return len(set(text)) >= 8
