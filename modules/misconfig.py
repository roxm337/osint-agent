"""Stage 4: Misconfiguration Probes — sensitive files, API docs, CI/CD, vendor paths."""

import asyncio
import re

from core.site_profile import get_profile
from modules.base import BaseModule
from tools.wrappers import curl_with_status


FINDING_RULES = [
    # Git / source control
    (["/.git/config", "/.git/HEAD", "/.git/index", "/.git/COMMIT_EDITMSG"],
     "CRITICAL", "Exposed Git Repository",
     "Git repository metadata is publicly accessible. Attackers can reconstruct source code."),
    # Secrets
    (["/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.old"],
     "CRITICAL", "Exposed Environment File",
     ".env file accessible. Likely contains database credentials, API keys, and secrets."),
    (["/.ssh/id_rsa", "/id_rsa", "/server.key", "/private.key", "/private.pem"],
     "CRITICAL", "Exposed Private Key",
     "Private key file accessible. Immediate credential rotation required."),
    # WordPress
    (["/wp-config.php", "/wp-config.bak", "/wp-config.txt", "/wp-config.php.bak",
      "/wp-config.php~"],
     "CRITICAL", "Exposed WordPress Configuration",
     "wp-config.php accessible — contains database credentials and secret keys."),
    # Backup files (including null-byte-bypass variants like .bak%2500.md,
    # which servers decode past the extension filter).
    (["package.json.bak", "composer.json.bak", ".env.bak", ".bak%25",
      ".backup"],
     "HIGH", "Backup File Exposed",
     "Backup file accessible — may contain source code, credentials, or customer data."),
    (["/wp-content/debug.log", "/wp-content/error_log"],
     "HIGH", "WordPress Debug Log Exposed",
     "WordPress debug log accessible — may contain error details and path disclosures."),
    # PHP info
    (["/phpinfo.php", "/info.php", "/test.php", "/php.php", "/i.php", "/0.php"],
     "MEDIUM", "phpinfo() Page Exposed",
     "PHP configuration page accessible — exposes PHP version, loaded modules, and server paths."),
    # SQL/Database dumps
    (["/backup.sql", "/db_backup.sql", "/database.sql", "/dump.sql"],
     "CRITICAL", "Database Dump Exposed",
     "SQL database dump accessible. Full database contents may be downloadable."),
    (["/backup.zip", "/backup.tar.gz", "/site.zip", "/www.zip", "/old.zip"],
     "CRITICAL", "Site Backup Archive Exposed",
     "Site backup archive accessible. May contain source code, credentials, and sensitive data."),
    # Application logs
    (["/debug.log", "/error.log", "/error_log", "/app.log", "/application.log",
      "/laravel.log", "/storage/logs/laravel.log"],
     "HIGH", "Application Log Exposed",
     "Application log file accessible — may contain stack traces, user data, and credentials."),
    # Admin panels
    (["/phpmyadmin/", "/pma/", "/adminer.php", "/dbadmin/"],
     "HIGH", "Database Admin Panel Exposed",
     "Database administration interface accessible. Often targeted for credential brute-force."),
    (["/manager/html", "/manager/", "/jmx-console/", "/web-console/"],
     "HIGH", "Application Server Console Exposed",
     "Application server management console accessible."),
    # CI/CD configs
    (["/.gitlab-ci.yml", "/.travis.yml", "/.circleci/config.yml",
      "/Jenkinsfile", "/azure-pipelines.yml", "/bitbucket-pipelines.yml"],
     "MEDIUM", "CI/CD Configuration Exposed",
     "CI/CD pipeline configuration accessible — may reveal deployment secrets and infrastructure details."),
    (["/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml"],
     "MEDIUM", "Docker Configuration Exposed",
     "Docker configuration accessible — reveals infrastructure layout and potentially secrets."),
    # Config files
    (["/config.php", "/configuration.php", "/settings.php"],
     "HIGH", "Application Config File Exposed",
     "Application configuration file accessible — may contain database credentials."),
    (["/application.properties", "/application.yml", "/web.config"],
     "HIGH", "Application Properties Exposed",
     "Application configuration file accessible — may contain service credentials."),
    (["/config/database.yml", "/app/config/database.yml", "/config/secrets.yml"],
     "CRITICAL", "Rails/Framework Database Config Exposed",
     "Framework database configuration accessible — contains database credentials."),
    # Spring Boot actuator
    (["/actuator/env", "/actuator/heapdump"],
     "CRITICAL", "Spring Boot Sensitive Actuator Exposed",
     "Spring Boot actuator endpoint exposes environment variables and/or heap dump."),
    (["/actuator", "/actuator/mappings", "/actuator/beans", "/actuator/info"],
     "MEDIUM", "Spring Boot Actuator Exposed",
     "Spring Boot actuator exposes application internals."),
    # Kubernetes/Container
    (["/api/v1/namespaces", "/api/v1/pods", "/api/v1/services"],
     "CRITICAL", "Kubernetes API Exposed",
     "Kubernetes API endpoint is publicly accessible."),
    (["/debug/vars", "/debug/pprof/"],
     "HIGH", "Go Debug Endpoint Exposed",
     "Go pprof/expvar debug endpoint accessible — exposes runtime metrics and goroutine dumps."),
    (["/metrics"],
     "MEDIUM", "Prometheus Metrics Exposed",
     "Prometheus metrics endpoint accessible — reveals internal service names and performance data."),
    # Source package metadata
    (["/package.json", "/composer.json", "/Gemfile", "/requirements.txt", "/go.mod"],
     "LOW", "Dependency Manifest Exposed",
     "Dependency manifest exposed — reveals application framework versions for targeted attacks."),
    (["/yarn.lock", "/package-lock.json", "/composer.lock", "/Gemfile.lock"],
     "LOW", "Dependency Lockfile Exposed",
     "Dependency lockfile exposed — reveals exact version numbers including vulnerable packages."),
    # Misc
    (["/.DS_Store"],
     "LOW", ".DS_Store File Exposed",
     ".DS_Store file accessible — reveals directory structure from macOS development machine."),
    (["/.well-known/security.txt"],
     "INFO", "Security.txt Found",
     "security.txt present — useful for responsible disclosure contact information."),
]


def _shared_rules() -> list:
    """FINDING_RULES re-expressed so core.site_profile can gate them.

    The rules stay exactly as specific as they were — this module knows about
    `.env.backup` and `wp-config.php~` in a way a generic list does not. What
    changes is that matching a path no longer implies a finding: a match now
    has to survive the catch-all comparison and the content assertion before
    anything is filed. The pattern keys below are what those assertions are
    written against, so the two stay in step.
    """
    rules = []
    for paths, severity, title, _desc in FINDING_RULES:
        joined = "|".join(re.escape(p) for p in paths)
        rules.append((re.compile(joined), severity, title))
    rules.append((re.compile(r"swagger|openapi|api-docs|redoc"), "MEDIUM",
                  "API Documentation Exposed"))
    rules.append((re.compile(r"graphql|gql|graphiql"), "MEDIUM",
                  "GraphQL Endpoint Accessible"))
    return rules


SHARED_RULES = _shared_rules()

# Rule key -> what the real artifact contains. Kept alongside the rules so a
# path can never be declared exposed on the strength of a 200 alone.
CONTENT_HINTS: dict[str, str] = {
    r"/\.git/config": r"^\s*\[core\]",
    r"/\.git/HEAD": r"^ref:\s*refs/",
    r"/\.env": r"^[A-Z][A-Z0-9_]{2,}\s*=",
    r"\.ssh/id_rsa|\.pem$|\.key$": r"-----BEGIN",
    r"wp-config": r"define\s*\(\s*['\"]DB_NAME|table_prefix",
    r"phpinfo": r"phpinfo\(\)|PHP Version",
    r"actuator": r'"(?:_links|activeProfiles)"|Spring',
    r"swagger|openapi|api-docs|redoc": r'"(?:openapi|swagger|info)"\s*:',
    r"graphql|gql|graphiql": r"__schema|\"data\"\s*:",
    r"docker|docker-compose": r"^\s*\{|image:|services:",
    r"\.k8s|kubernetes|configmap": r"apiVersion:|kind:",
    r"backup\.sql|\.sql\.gz|dump\.sql": r"CREATE TABLE|INSERT INTO|PRAGMA",
    r"phpmyadmin|adminer": r"phpMyAdmin|Adminer|select\.php",
    r"debug\.log|error_log": r"\[(?:error|warning|notice|fatal)\]",
}


def _hint_for(path: str) -> "re.Pattern[str] | None":
    for key, pattern in CONTENT_HINTS.items():
        if re.search(key, path):
            return re.compile(pattern, re.I | re.M)
    return None


def _is_distinguishable(profile, status: int, body: str) -> bool:
    """Is this response something other than the site's own answer to anything?

    A profile that could not be established returns True, so a failed baseline
    degrades to the old behaviour instead of silently disabling the module.
    That is the right way round: a noisy scan is recoverable, a scan that
    reports nothing looks like a clean target.
    """
    if profile is None:
        return True
    from core.response_fingerprint import fingerprint
    return not profile.baseline.catch_all(fingerprint(status, body, ""))


class MisconfigProbes(BaseModule):
    id = "misconfig_probes"
    name = "Misconfiguration Probes"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        base_url = self.base_url
        self.log("Probing for misconfigurations...")

        # Build full path list from config
        all_paths = set()
        for key in ["misconfig_paths", "wp_paths", "swagger_paths", "graphql_paths",
                    "spring_actuator_paths", "vendor_paths", "container_k8s_paths"]:
            all_paths.update(self.config.get("wordlists", {}).get(key, []))

        probe_cfg = self.config.get("misconfig", {})
        if not isinstance(probe_cfg, dict):
            probe_cfg = {}
        # Knowledge packs merge under modules:{id:}; honor both so pack
        # extras (extra_backup_bases) work without config surgery.
        pack_cfg = (self.config.get("modules", {}) or {}).get("misconfig", {})
        if isinstance(pack_cfg, dict):
            probe_cfg = {**pack_cfg, **probe_cfg}
        timeout = int(probe_cfg.get("timeout", 5) or 5)
        concurrency = max(1, int(probe_cfg.get("concurrency", 12) or 12))
        max_paths = int(probe_cfg.get("max_paths", 160) or 160)
        max_empty = int(probe_cfg.get("max_consecutive_empty", 60) or 60)
        progress_every = max(1, int(probe_cfg.get("progress_every", 25) or 25))

        paths = self._prioritized_paths(sorted(all_paths))[:max_paths]
        self.log(
            f"  Checking {len(paths)} of {len(all_paths)} paths "
            f"(concurrency={concurrency}, timeout={timeout}s)..."
        )
        findings_found = []
        exposed_paths = []
        consecutive_empty = 0

        profile = await self._establish_profile(base_url, timeout)
        if profile is None:
            self.log("  [!] Baseline could not be established; "
                     "probing without catch-all filtering.")

        index = 0
        async for item in self._probe_paths(base_url, paths, concurrency, timeout):
            index += 1
            path = item["path"]
            status = item["status"]
            body = item["body"]
            if status in (0, 404):
                consecutive_empty += 1
            else:
                consecutive_empty = 0

            self._analyze_result(base_url, path, status, body, findings_found,
                                 exposed_paths, profile)

            if index % progress_every == 0:
                self.log(
                    f"  Progress: {index}/{len(paths)} paths | "
                    f"findings={len(findings_found)} | exposed={len(exposed_paths)}"
                )

            if consecutive_empty >= max_empty and len(exposed_paths) == 0:
                self.log(
                    f"  Stopping early after {consecutive_empty} consecutive empty responses."
                )
                break

        # Backup-file combinations + filter-bypass variants. Servers
        # that block ".bak" often decode past the filter: %2500.md and
        # ";.md" suffixes served package.json.bak live on one target.
        await self._probe_backup_combinations(
            base_url, timeout, concurrency, profile,
            findings_found, exposed_paths, probe_cfg)

        # Record all findings
        for f in findings_found:
            evidence = [f"URL: {base_url}{f['path']}"]
            if f.get("body_preview"):
                evidence.append(f"Preview: {f['body_preview'][:200]}")
            self.state.add_finding(
                title=f["title"],
                severity=f["severity"],
                confidence="CONFIRMED" if f["severity"] != "INFO" else "FIRM",
                category="Information Disclosure" if f["severity"] != "INFO" else "Enumeration",
                description=f["desc"],
                evidence=evidence,
                remediation=self._remediation(f["path"]),
                asset_keys=[f"webapp:{base_url}"],
            )

        self.state.complete_module(self.id)
        self.log(f"Misconfig: {len(findings_found)} findings across {len(exposed_paths)} exposed paths")
        return "done"

    async def _probe_backup_combinations(self, base_url: str, timeout: int,
                                              concurrency: int, profile,
                                              findings_found: list,
                                              exposed_paths: list,
                                              probe_cfg: dict) -> None:
        """Backup names × suffixes at webroot and file-drop dirs, plus
        filter-bypass variants of anything the server blocks with 403."""
        bases = ("package.json", ".env", "composer.json", "wp-config.php",
                 "config.php")
        suffixes = ("", ".bak", ".old", "~", ".backup", ".save")
        bypasses = ("%2500.md", ";.md")
        # Lab packs and operators extend the base list without touching
        # code: target-specific backup names live in config, not here.
        bases = tuple(bases) + tuple(
            str(b) for b in probe_cfg.get("extra_backup_bases", []) or [])
        dirs = [""]
        try:
            check = await curl_with_status(f"{base_url}/ftp/", timeout=timeout)
            if check.get("status", 0) in (200, 301, 302, 403):
                dirs.append("/ftp")
        except Exception:
            pass

        candidates = []
        for directory in dirs:
            for base in bases:
                for suffix in suffixes:
                    path = f"{directory}/{base}{suffix}"
                    if path not in candidates:
                        candidates.append(path)
        candidates = candidates[:60]
        self.log(f"  Backup combinations: {len(candidates)} paths...")

        blocked: list[str] = []
        async for item in self._probe_paths(base_url, candidates,
                                            concurrency, timeout):
            self._analyze_result(base_url, item["path"], item["status"],
                                 item["body"], findings_found,
                                 exposed_paths, profile)
            if item["status"] == 403 and any(
                    item["path"].endswith(suffix) for suffix in
                    (".bak", ".old", "~", ".backup", ".env", ".sql", ".log")):
                blocked.append(item["path"])

        # Bypass wave: only the blocked names, only the cheap variants.
        variants = []
        for path in blocked[:10]:
            for bypass in bypasses:
                variant = path + bypass
                if variant not in variants:
                    variants.append(variant)
        if variants:
            self.log(f"  Filter-bypass variants: {len(variants)} paths...")
            async for item in self._probe_paths(base_url, variants,
                                                concurrency, timeout):
                self._analyze_result(base_url, item["path"], item["status"],
                                     item["body"], findings_found,
                                     exposed_paths, profile)

    async def _probe_paths(self, base_url: str, paths: list[str],
                           concurrency: int, timeout: int):
        semaphore = asyncio.Semaphore(concurrency)

        async def probe(path: str) -> dict:
            async with semaphore:
                result = await curl_with_status(f"{base_url}{path}", timeout=timeout)
                return {
                    "path": path,
                    "status": result.get("status", 0),
                    "body": result.get("body", ""),
                    "error": result.get("error"),
                }

        tasks = [asyncio.create_task(probe(path)) for path in paths]
        try:
            for task in asyncio.as_completed(tasks):
                yield await task
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()

    async def _establish_profile(self, base_url: str, timeout: int):
        """Learn what this origin returns when nothing matches.

        Root plus four control paths, via the same HTTP client the probes use,
        so the baseline cannot drift away from how the module actually asks.
        """
        async def fetch(path: str):
            r = await curl_with_status(base_url.rstrip("/") + path,
                                       timeout=timeout,
                                       follow_redirects=True)
            return (r.get("status", 0), r.get("body", "") or "",
                    r.get("content_type", "") or "")

        try:
            profile = await get_profile(base_url, fetch)
        except Exception as exc:  # noqa: BLE001 - baseline is best-effort
            self.log(f"  [!] baseline failed: {type(exc).__name__}")
            return None
        cov = profile.coverage()
        self.log(f"  Baseline: {profile.baseline.describe()}")
        if cov["probed"] and cov["judgable_pct"] == 0:
            self.log("  [!] every control path returned the site default; "
                     "exposure findings will be suppressed")
        return profile

    def _analyze_result(self, base_url: str, path: str, status: int, body: str,
                        findings_found: list[dict], exposed_paths: list[str],
                        profile=None):
        if status == 200:
            # A 200 proves the server answered, not that it answered with the
            # thing we asked for. This used to be `len(body.strip()) > 50`,
            # which any SPA shell satisfies, and it is how a target that
            # returns one 9393-byte index.html for everything produced a
            # critical "exposed git repository" finding.
            hint = _hint_for(path)
            if hint is not None and not hint.search(body or ""):
                self.log(f"  [content-gate] {path}: 200 but not {path} content")
                return

            if profile is not None and not _is_distinguishable(profile, status, body):
                self.log(f"  [catch-all] {path}: 200 but matches site baseline")
                return

            has_content = len(body.strip()) > 50

            self.state.add_asset(
                "webapp",
                f"webapp:{base_url}{path}",
                f"{base_url}{path}",
                confidence="CONFIRMED",
                sources=["misconfig probe"],
                attrs={"status": 200, "has_content": has_content,
                       "body_preview": body[:500]},
            )

            exposed_paths.append(path)

            # Match against finding rules
            matched = False
            for path_list, severity, title, desc in FINDING_RULES:
                if any(p in path for p in path_list):
                    findings_found.append({
                        "path": path,
                        "title": title,
                        "severity": severity,
                        "desc": desc,
                        "body_preview": body[:300],
                    })
                    matched = True
                    break

            # Swagger/OpenAPI specific analysis
            if not matched and any(kw in path for kw in
                                   ["swagger", "openapi", "api-docs", "redoc"]):
                findings_found.append({
                    "path": path,
                    "title": "API Documentation Exposed",
                    "severity": "MEDIUM",
                    "desc": f"API documentation at {path} is publicly accessible. "
                            f"Reveals all API endpoints, parameters, and authentication schemes.",
                    "body_preview": body[:300],
                })

            # GraphQL specific analysis
            elif not matched and any(kw in path for kw in ["graphql", "gql", "graphiql"]):
                findings_found.append({
                    "path": path,
                    "title": "GraphQL Endpoint Accessible",
                    "severity": "MEDIUM",
                    "desc": f"GraphQL endpoint at {path} is accessible. "
                            f"Test for introspection, field suggestion, and IDOR.",
                    "body_preview": body[:300],
                })

        elif status == 403:
            if any(kw in path for kw in [".git", ".htpasswd", ".env", "wp-config"]):
                self.state.add_asset(
                    "webapp",
                    f"webapp:{base_url}{path}",
                    f"{base_url}{path}",
                    confidence="FIRM",
                    sources=["misconfig probe"],
                    attrs={"status": 403, "note": "Exists but access-controlled"},
                )
                findings_found.append({
                    "path": path,
                    "title": f"Restricted File Exists: {path}",
                    "severity": "INFO",
                    "desc": f"{path} returns 403 — file exists but is access-controlled. "
                            f"Try WAF bypass techniques.",
                    "body_preview": "",
                })

    def _prioritized_paths(self, paths: list[str]) -> list[str]:
        critical_tokens = (
            ".git", ".env", "wp-config", "swagger", "openapi", "api-docs",
            "graphql", "actuator", "backup", ".sql", ".zip", "debug",
            "metrics", "phpinfo", "adminer", "phpmyadmin",
        )
        return sorted(
            paths,
            key=lambda path: (
                not any(token in path.lower() for token in critical_tokens),
                len(path),
                path,
            ),
        )

    def _remediation(self, path: str) -> str:
        if ".git" in path:
            return "Remove .git directory from web root; use .htaccess/nginx deny or move outside webroot."
        if ".env" in path:
            return "Move .env outside web root; restrict access via server config."
        if "wp-config" in path:
            return "Protect wp-config.php with server-level deny rules."
        if "swagger" in path or "openapi" in path or "api-docs" in path:
            return "Restrict API documentation to authenticated users or internal networks."
        if "actuator" in path:
            return "Secure Spring Boot actuator endpoints with Spring Security; only expose /health and /info publicly."
        if "graphql" in path:
            return "Disable introspection in production; add authentication and rate limiting."
        if any(kw in path for kw in [".sql", ".zip", ".tar.gz", "backup"]):
            return "Remove backup files from web root immediately."
        if "debug" in path or "pprof" in path or "metrics" in path:
            return "Restrict debug/metrics endpoints to localhost or internal monitoring networks."
        return "Remove or restrict access to this file/path via server configuration."
