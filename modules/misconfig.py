"""Stage 4: Misconfiguration Probes — sensitive files, API docs, CI/CD, vendor paths."""

import asyncio

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


class MisconfigProbes(BaseModule):
    id = "misconfig_probes"
    name = "Misconfiguration Probes"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        base_url = f"https://{self.domain}"
        self.log("Probing for misconfigurations...")

        # Build full path list from config
        all_paths = set()
        for key in ["misconfig_paths", "wp_paths", "swagger_paths", "graphql_paths",
                    "spring_actuator_paths", "vendor_paths", "container_k8s_paths"]:
            all_paths.update(self.config.get("wordlists", {}).get(key, []))

        probe_cfg = self.config.get("misconfig", {})
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

            self._analyze_result(base_url, path, status, body, findings_found, exposed_paths)

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

    def _analyze_result(self, base_url: str, path: str, status: int, body: str,
                        findings_found: list[dict], exposed_paths: list[str]):
        if status == 200:
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
