"""Stage 4: REST API & OpenAPI Audit — WP REST, Swagger/OpenAPI discovery, JWT checks."""

import json
import re
from modules.base import BaseModule
from tools.wrappers import curl, curl_json, curl_with_status


class RestAPIAudit(BaseModule):
    id = "rest_api_audit"
    name = "REST API Audit"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]

    WP_NAMESPACE_CHECKS = [
        "/wp/v2/pages?per_page=100",
        "/wp/v2/users?per_page=100",
        "/wp/v2/media?per_page=100",
        "/wp/v2/types",
        "/wp/v2/categories",
        "/wp/v2/tags",
        "/wp/v2/settings",
    ]

    WP_PLUGIN_ENDPOINTS = [
        "/yoast/v1/get_head?url=https://example.com",
        "/yoast/v1/file_size?url=https://example.com",
        "/yoast/v1/configurator",
        "/yoast/v1/statistics",
        "/wp-statistics/v2/check",
        "/wp-statistics/v2/metabox?name=hits",
        "/contact-form-7/v1/contact-forms",
        "/akismet/v1/key",
        "/akismet/v1/stats",
        "/wp-super-cache/v1/status",
        "/wp-super-cache/v1/settings",
        "/woocommerce/store-api/v1/cart",
        "/gravityforms/v2/forms",
    ]

    async def run(self) -> str:
        base_url = f"https://{self.domain}"

        # 1. WordPress REST API
        await self._audit_wordpress_api(base_url)

        # 2. Generic Swagger/OpenAPI discovery
        await self._discover_openapi(base_url)

        # 3. Generic REST API probes
        await self._probe_generic_api(base_url)

        self.state.complete_module(self.id)
        return "done"

    async def _audit_wordpress_api(self, base_url: str):
        """Audit WordPress REST API if present."""
        root = await curl_json(f"{base_url}/wp-json/")
        if not root or not isinstance(root, dict):
            self.log("No WP REST API detected.")
            return

        self.log("WP REST API found — auditing...")
        namespaces = root.get("namespaces", [])
        routes = root.get("routes", {})

        self.state.add_asset(
            "api_endpoint",
            f"api:{base_url}/wp-json/",
            f"{base_url}/wp-json/",
            confidence="CONFIRMED",
            sources=["REST API probe"],
            attrs={
                "namespaces": namespaces,
                "total_routes": len(routes),
                "type": "wordpress",
            },
        )

        # Check for user enumeration
        users_result = await curl_json(f"{base_url}/wp-json/wp/v2/users?per_page=100")
        if isinstance(users_result, list) and len(users_result) > 0:
            usernames = [u.get("slug", u.get("name", "")) for u in users_result]
            self.state.add_finding(
                title=f"WP REST API: {len(users_result)} Users Enumerated",
                severity="HIGH",
                confidence="CONFIRMED",
                category="Information Disclosure",
                description=(
                    f"WordPress REST API exposes {len(users_result)} user accounts "
                    f"without authentication: {usernames[:10]}"
                ),
                evidence=[
                    f"Endpoint: {base_url}/wp-json/wp/v2/users",
                    f"Users: {usernames[:10]}",
                ],
                remediation="Restrict REST API to authenticated users. Add: "
                            "add_filter('rest_endpoints', ...) to block /users.",
            )

        # Check plugin endpoints
        for path in self.WP_PLUGIN_ENDPOINTS:
            full_url = f"{base_url}/wp-json{path}"
            r = await curl_with_status(full_url)
            status = r.get("status", 0)
            body = r.get("body", "")

            if status == 200 and body:
                self.state.add_asset(
                    "api_endpoint",
                    f"api:{full_url}",
                    full_url,
                    confidence="CONFIRMED",
                    sources=["REST API probe"],
                    attrs={"auth_required": False, "status": 200, "type": "wp_plugin"},
                )

                if "file_size" in path:
                    self.state.add_finding(
                        title="Yoast file_size SSRF Vector",
                        severity="MEDIUM",
                        confidence="CONFIRMED",
                        category="SSRF",
                        description=f"Yoast SEO file_size endpoint at {full_url} "
                                    f"may allow server-side request forgery.",
                        evidence=[f"Endpoint: {full_url}"],
                        remediation="Update Yoast SEO; restrict endpoint to admins.",
                    )
                elif "akismet/v1/key" in path:
                    # API key may be in response
                    try:
                        data = json.loads(body)
                        if data:
                            self.state.add_finding(
                                title="Akismet API Key Exposed via REST",
                                severity="MEDIUM",
                                confidence="CONFIRMED",
                                category="Credential Exposure",
                                description=f"Akismet API key accessible without auth at {full_url}",
                                evidence=[f"Response: {body[:100]}"],
                                remediation="Restrict /akismet/ endpoints to authenticated admins.",
                            )
                    except json.JSONDecodeError:
                        pass
                elif "gravityforms" in path or "contact-form-7" in path:
                    self.state.add_finding(
                        title=f"Form Plugin API Endpoint Accessible: {path.split('/')[1]}",
                        severity="LOW",
                        confidence="CONFIRMED",
                        category="Information Disclosure",
                        description=f"Form plugin REST endpoint accessible: {full_url}",
                        evidence=[f"Endpoint: {full_url}"],
                        remediation="Restrict plugin REST endpoints to authenticated users.",
                    )

    async def _discover_openapi(self, base_url: str):
        """Discover Swagger/OpenAPI documentation."""
        swagger_paths = self.config.get("wordlists", {}).get("swagger_paths", [
            "/swagger.json", "/openapi.json", "/swagger-ui.html",
            "/api-docs", "/api/swagger.json", "/v1/swagger.json",
            "/swagger/v1/swagger.json", "/redoc", "/docs",
        ])

        self.log(f"Checking {len(swagger_paths)} OpenAPI paths...")

        for path in swagger_paths:
            r = await curl_with_status(f"{base_url}{path}")
            status = r.get("status", 0)
            body = r.get("body", "")

            if status != 200 or not body:
                continue

            # Verify it's actually an API spec
            is_openapi = (
                '"swagger"' in body or '"openapi"' in body
                or '"paths"' in body
                or "Swagger UI" in body or "ReDoc" in body
                or "swagger-ui" in body.lower()
            )

            if not is_openapi:
                continue

            # Try to extract endpoint count
            endpoint_count = 0
            try:
                data = json.loads(body)
                endpoint_count = len(data.get("paths", {}))
                # Check for security definitions
                has_auth = bool(
                    data.get("securityDefinitions")
                    or data.get("components", {}).get("securitySchemes")
                )
                # Check for server URLs that reveal internal infrastructure
                servers = [s.get("url", "") for s in data.get("servers", [])]
                internal_servers = [s for s in servers
                                    if "localhost" in s or "internal" in s
                                    or "staging" in s or "dev." in s]
            except (json.JSONDecodeError, AttributeError):
                has_auth = False
                internal_servers = []

            self.state.add_asset(
                "api_endpoint",
                f"api:{base_url}{path}",
                f"{base_url}{path}",
                confidence="CONFIRMED",
                sources=["openapi discovery"],
                attrs={
                    "type": "openapi",
                    "endpoint_count": endpoint_count,
                    "status": status,
                },
            )

            self.state.add_finding(
                title=f"API Documentation Exposed: {path}",
                severity="MEDIUM",
                confidence="CONFIRMED",
                category="API Security",
                description=(
                    f"OpenAPI/Swagger documentation at {base_url}{path} is publicly "
                    f"accessible. Contains {endpoint_count} endpoint definitions. "
                    f"Authentication required: {'Yes' if has_auth else 'Unknown'}."
                ),
                evidence=[
                    f"URL: {base_url}{path}",
                    f"Endpoints documented: {endpoint_count}",
                ]
                + ([f"Internal server URLs: {internal_servers}"] if internal_servers else []),
                remediation=(
                    "Restrict API documentation to authenticated users or internal networks. "
                    "Remove server URLs that reveal internal infrastructure."
                ),
            )

    async def _probe_generic_api(self, base_url: str):
        """Probe for generic REST API patterns and JWT exposure."""
        api_paths = ["/api", "/api/v1", "/api/v2", "/rest", "/v1", "/v2"]

        for path in api_paths:
            r = await curl_with_status(f"{base_url}{path}")
            status = r.get("status", 0)
            body = r.get("body", "")

            if status not in (200, 401) or not body:
                continue

            # Check for JWT in response
            jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
            jwts = re.findall(jwt_pattern, body)
            if jwts:
                self.state.add_finding(
                    title=f"JWT Token Exposed in API Response: {path}",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    category="Credential Exposure",
                    description=f"JWT token found in API response at {base_url}{path}. "
                                f"May allow account takeover if secret is weak.",
                    evidence=[f"JWT: {jwts[0][:50]}...", f"URL: {base_url}{path}"],
                    remediation="Never include authentication tokens in publicly accessible "
                                "API documentation or sample responses.",
                )

            self.state.add_asset(
                "api_endpoint",
                f"api:{base_url}{path}",
                f"{base_url}{path}",
                confidence="FIRM" if status == 200 else "TENTATIVE",
                sources=["rest api probe"],
                attrs={"status": status, "type": "rest"},
            )
