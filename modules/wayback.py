"""Stage 2: Wayback Machine + URLScan — URL mining, JS extraction, parameter analysis."""

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

        # Findings: sensitive URL parameters (potential secret leakage)
        sensitive_param_urls = categories["sensitive_param"]
        if sensitive_param_urls:
            found_params = set()
            for url in sensitive_param_urls[:20]:
                params = parse_qs(urlparse(url).query)
                found_params.update(k for k in params if k.lower() in SENSITIVE_URL_PARAMS)

            self.state.add_finding(
                title="Sensitive Parameters in Historical URLs",
                severity="HIGH",
                confidence="FIRM",
                category="Credential Exposure",
                description=f"Wayback Machine contains {len(sensitive_param_urls)} historical URLs "
                            f"with sensitive parameter names: {sorted(found_params)}. "
                            f"These may contain leaked API keys or tokens.",
                evidence=[url for url in sensitive_param_urls[:10]],
                remediation="Rotate any credentials found in historical URLs; "
                            "never pass secrets in URL parameters.",
            )

        # Findings: sensitive file extensions in history
        sensitive_files = categories["sensitive_file"]
        if sensitive_files:
            self.state.add_finding(
                title="Sensitive File URLs in Archive",
                severity="MEDIUM",
                confidence="FIRM",
                category="Information Disclosure",
                description=f"{len(sensitive_files)} historically accessed sensitive files "
                            f"found (.env, .bak, .sql, .conf, .log, etc.).",
                evidence=[url for url in sensitive_files[:10]],
                remediation="Verify these files are no longer accessible; check current state.",
            )

        # Findings: admin paths in history
        admin_paths = categories["admin_path"]
        if admin_paths:
            unique_admin = list({urlparse(u).path for u in admin_paths})[:15]
            self.state.add_finding(
                title="Admin/Internal Paths in Archive",
                severity="LOW",
                confidence="FIRM",
                category="Attack Surface",
                description=f"{len(admin_paths)} historical admin/internal paths enumerated.",
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
