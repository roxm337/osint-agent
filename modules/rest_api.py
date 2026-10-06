"""Stage 4: REST API & OpenAPI Audit — WP REST, Swagger/OpenAPI discovery, JWT checks."""

import json
import re

from core.response_fingerprint import fingerprint
from core.site_profile import get_profile
from modules.base import BaseModule
from tools.wrappers import curl_json, curl_with_status


def _extract_swagger_doc(body: str) -> dict:
    """Pull the embedded swaggerDoc object out of a Swagger UI init script.

    The spec is a JS object literal, not strict JSON (unquoted keys,
    trailing commas), so brace-match from `"swaggerDoc":` and parse
    leniently. Returns {} when nothing usable is found.
    """
    text = str(body or "")
    anchor = text.find('"swaggerDoc"')
    if anchor < 0:
        return {}
    start = text.find("{", anchor)
    if start < 0:
        return {}
    depth = 0
    in_string: str | None = None
    escaped = False
    for pos in range(start, len(text)):
        char = text[pos]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == in_string:
                in_string = None
            continue
        if char in ("'", '"'):
            in_string = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start:pos + 1]
                break
    else:
        return {}
    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, dict) else {}
    except (json.JSONDecodeError, ValueError):
        pass
    # Lenient pass: quote bare keys, drop trailing commas.
    try:
        fixed = re.sub(r"([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*:)", r'\1"\2"\3', candidate)
        fixed = re.sub(r",(\s*[}\]])", r"\1", fixed)
        parsed = json.loads(fixed)
        return parsed if isinstance(parsed, dict) else {}
    except (json.JSONDecodeError, ValueError):
        return {}


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
        base_url = self.base_url
        self.profile = await self._profile(base_url)

        # 1. WordPress REST API
        await self._audit_wordpress_api(base_url)

        # 2. Generic Swagger/OpenAPI discovery
        await self._discover_openapi(base_url)

        # 3. Generic REST API probes
        await self._probe_generic_api(base_url)

        self.state.complete_module(self.id)
        return "done"

    async def _profile(self, base_url: str):
        """Baseline for the origin, so a 200 means this endpoint exists.

        An API host that returns its own page for every path is not rare — a
        catch-all SPA in front of an API, or a misconfigured rewrite. Without
        this, every probed endpoint becomes a CONFIRMED api_endpoint asset.
        """
        async def fetch(path: str):
            r = await curl_with_status(base_url.rstrip("/") + path,
                                       follow_redirects=True)
            return (r.get("status", 0), r.get("body", "") or "",
                    r.get("content_type", "") or "")

        try:
            return await get_profile(base_url, fetch)
        except Exception:  # noqa: BLE001 - baseline is best-effort
            return None

    def _is_catch_all(self, status: int, body: str) -> bool:
        """No profile means no verdict, so fall back to the old behaviour."""
        if getattr(self, "profile", None) is None:
            return False
        return self.profile.baseline.catch_all(
            fingerprint(status, body or "", ""))

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
                verified=True,
                verification={"method": "rest_users_json",
                              "url": f"{base_url}/wp-json/wp/v2/users"},
            )

        # Check plugin endpoints
        for path in self.WP_PLUGIN_ENDPOINTS:
            full_url = f"{base_url}/wp-json{path}"
            r = await curl_with_status(full_url)
            status = r.get("status", 0)
            body = r.get("body", "")

            if status == 200 and body and not self._is_catch_all(status, body):
                self.state.add_asset(
                    "api_endpoint",
                    f"api:{full_url}",
                    full_url,
                    confidence="CONFIRMED",
                    sources=["REST API probe"],
                    attrs={"auth_required": False, "status": 200, "type": "wp_plugin"},
                )

                if "file_size" in path:
                    await self._check_file_size_ssrf(full_url)
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
                                verified=True,
                                verification={"method": "rest_json_key_returned",
                                              "url": full_url},
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
                        verified=True,
                        verification={"method": "rest_endpoint_accessible",
                                      "url": full_url},
                    )

    async def _check_file_size_ssrf(self, endpoint_url: str) -> None:
        """Prove or downgrade the Yoast file_size SSRF vector with OOB.

        "May allow SSRF" is not a finding. With an OOB channel configured,
        the endpoint fetches a callback URL and a received interaction is
        CONFIRMED SSRF. Without a channel — or without a callback — the
        endpoint is recorded present-but-untested at LOW.
        """
        from tools.wrappers import curl
        client = self.oob()
        if client is None:
            self.state.add_finding(
                title="Yoast file_size SSRF Vector (Untested)",
                severity="LOW",
                confidence="TENTATIVE",
                category="SSRF",
                description=(f"Yoast SEO file_size endpoint at {endpoint_url} "
                             "accepts a URL parameter. No OOB channel is "
                             "configured, so server-side fetching is unproven."),
                evidence=[f"Endpoint: {endpoint_url}"],
                remediation="Update Yoast SEO; restrict endpoint to admins.",
            )
            return
        try:
            corr_id = await client.register_callback(f"yoast-file-size:{endpoint_url}")
            callback = client.callback_url(corr_id, "/yoast")
        except Exception as exc:
            self.log(f"  OOB registration failed: {exc}")
            return
        import asyncio as _asyncio
        from urllib.parse import urlencode
        proven = False
        for param in ("url", "file", "src"):
            probe = f"{endpoint_url}?{urlencode({param: callback})}"
            try:
                await curl(probe, output="status", timeout=15)
            except Exception:
                pass
            for _ in range(3):
                try:
                    interactions = await client.poll(corr_id)
                except Exception:
                    interactions = []
                if interactions:
                    proven = True
                    break
                await _asyncio.sleep(client.poll_interval)
            if proven:
                break
        if proven:
            self.state.add_finding(
                title="Yoast file_size SSRF Confirmed via OOB Callback",
                severity="HIGH",
                confidence="CONFIRMED",
                category="SSRF",
                description=(f"Yoast SEO file_size endpoint at {endpoint_url} "
                             "fetched an out-of-band callback URL: the server "
                             "issues requests to attacker-supplied destinations."),
                evidence=[f"Endpoint: {endpoint_url}",
                          f"OOB callback received (corr {corr_id[:8]})"],
                remediation="Update Yoast SEO; restrict endpoint to admins; "
                            "validate any fetched URL against an allowlist.",
                verified=True,
                verification={"method": "oob_callback",
                              "url": endpoint_url,
                              "param": param},
            )
        else:
            self.state.add_finding(
                title="Yoast file_size SSRF Vector (Unproven)",
                severity="LOW",
                confidence="TENTATIVE",
                category="SSRF",
                description=(f"Yoast SEO file_size endpoint at {endpoint_url} "
                             "accepts a URL parameter but fetched no OOB "
                             "callback during testing."),
                evidence=[f"Endpoint: {endpoint_url}",
                          "OOB probes sent, no callback observed"],
                remediation="Update Yoast SEO; restrict endpoint to admins.",
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
            served_spec = False
            try:
                data = json.loads(body)
                served_spec = True
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

            # `url` is the effective URL after redirects. Following `/api-docs` to
            # `/api-docs/` is normal, but reporting only the request URL makes
            # the finding unreadable: a triager opens it, gets a 301, and has
            # to guess where the documentation actually is.
            final = str(r.get("url") or "").strip() or f"{base_url}{path}"
            if served_spec:
                how = f"{endpoint_count} endpoint definitions"
                detail = f"Endpoints documented: {endpoint_count}"
            else:
                # Swagger UI and ReDoc serve HTML, so there is no `paths` key to
                # count. Reporting "0 endpoint definitions" for a documentation
                # playground states a fact about the app that the response does
                # not support — it is an interactive UI over a spec served
                # somewhere else.
                how = ("an interactive documentation UI (Swagger UI/ReDoc); the "
                       "endpoint count is not in this response")
                detail = "Served an HTML documentation UI, not a JSON spec"
            if final.rstrip("/") != f"{base_url}{path}".rstrip("/"):
                detail += f"; served after redirect from {base_url}{path}"

            self.state.add_finding(
                title=f"API Documentation Exposed: {path}",
                severity="MEDIUM",
                confidence="CONFIRMED",
                category="API Security",
                description=(
                    f"OpenAPI/Swagger documentation at {final} is publicly "
                    f"accessible, serving {how}. "
                    f"Authentication required: {'Yes' if has_auth else 'Unknown'}."
                ),
                evidence=[
                    f"URL: {final}",
                    detail,
                ]
                + ([f"Internal server URLs: {internal_servers}"] if internal_servers else []),
                remediation=(
                    "Restrict API documentation to authenticated users or internal networks. "
                    "Remove server URLs that reveal internal infrastructure."
                ),
                verified=True,
                verification={"method": "openapi_docs_fetched",
                              "url": final},
            )

            # Swagger UI shells embed the spec in swagger-ui-init.js next
            # to the UI. Ingesting it turns one "docs exposed" finding
            # into enumerated, method-annotated endpoints for every
            # downstream testing module.
            if not served_spec:
                await self._ingest_swagger_ui(base_url, path)

    async def _ingest_swagger_ui(self, base_url: str, ui_path: str) -> None:
        """Parse the spec embedded in a Swagger UI shell's init script."""
        import re as _re
        directory = ui_path.rstrip("/").rsplit("/", 1)[0] or ""
        init_url = f"{base_url}{directory}/swagger-ui-init.js"
        try:
            result = await curl_with_status(init_url, timeout=15)
        except Exception:
            return
        body = result.get("body", "") or ""
        if result.get("status", 0) != 200 or "swaggerDoc" not in body:
            return
        spec = _extract_swagger_doc(body)
        if not spec:
            return
        paths = spec.get("paths", {}) or {}
        count = 0
        for route, operations in paths.items():
            if not isinstance(operations, dict):
                continue
            methods = sorted(
                method.upper() for method in operations
                if method.lower() in ("get", "post", "put", "patch", "delete"))
            if not methods:
                continue
            params = []
            for operation in operations.values():
                if not isinstance(operation, dict):
                    continue
                for param in operation.get("parameters", []) or []:
                    if isinstance(param, dict) and param.get("name"):
                        params.append(
                            f"{param.get('in', 'query')}:{param.get('name')}")
            full_url = f"{base_url}{route}"
            self.state.add_asset(
                "api_endpoint",
                f"api:{full_url}",
                full_url,
                confidence="FIRM",
                sources=["swagger spec"],
                attrs={"methods": methods, "params": sorted(set(params)),
                       "spec": init_url},
            )
            count += 1
            if count >= 100:
                break
        if count:
            self.log(f"  Swagger spec: {count} endpoints from {init_url}")

    async def _probe_generic_api(self, base_url: str):
        """Probe for generic REST API patterns and JWT exposure."""
        api_paths = ["/api", "/api/v1", "/api/v2", "/rest", "/v1", "/v2"]

        for path in api_paths:
            r = await curl_with_status(f"{base_url}{path}")
            status = r.get("status", 0)
            body = r.get("body", "")

            if status not in (200, 401) or not body:
                continue

            # Check for JWT in response. A live-shaped token is HIGH;
            # docs/sample tokens and expired ones are context, not takeover.
            jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
            jwts = re.findall(jwt_pattern, body)
            if jwts:
                from core.validators import analyze_jwt, redact_secret
                verdict = analyze_jwt(jwts[0])
                tier = verdict["tier"]
                if tier == "live_shaped":
                    severity, confidence = "HIGH", "CONFIRMED"
                    description = (
                        f"Live-shaped JWT in API response at {base_url}{path}. "
                        f"May allow account takeover if secret is weak.")
                elif tier == "expired":
                    severity, confidence = "LOW", "FIRM"
                    description = (
                        f"Expired JWT in API response at {base_url}{path}. "
                        "Token hygiene issue, not live takeover material.")
                else:
                    severity, confidence = "INFO", "FIRM"
                    description = (
                        f"Docs/sample JWT in API response at {base_url}{path} "
                        f"({verdict['reason']}).")
                self.state.add_finding(
                    title=f"JWT Token Exposed in API Response: {path}",
                    severity=severity,
                    confidence=confidence,
                    category="Credential Exposure",
                    description=description,
                    evidence=[f"JWT: {redact_secret(jwts[0])}...",
                              f"tier: {tier} ({verdict['reason']})",
                              f"URL: {base_url}{path}"],
                    remediation="Never include authentication tokens in publicly accessible "
                                "API documentation or sample responses.",
                )

            # Only a response that stands apart from the site's own default
            # earns FIRM; anything the origin would have said anyway is TENTATIVE.
            distinguishable = status == 200 and not self._is_catch_all(status, body)
            self.state.add_asset(
                "api_endpoint",
                f"api:{base_url}{path}",
                f"{base_url}{path}",
                confidence="FIRM" if distinguishable else "TENTATIVE",
                sources=["rest api probe"],
                attrs={"status": status, "type": "rest"},
            )
