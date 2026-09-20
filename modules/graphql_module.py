"""Stage 4: GraphQL Enumeration — introspection, field suggestion, batch queries."""

import json
from modules.base import BaseModule
from tools.wrappers import curl_with_status, curl


INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
""".strip()

# Field suggestion probe — triggers "Did you mean..." hints
FIELD_SUGGESTION_QUERY = '{ __typename invalidFieldNameXYZ }'

BATCH_TEST_QUERIES = [
    '[{"query": "{ __typename }"},{"query": "{ __typename }"}]',
    '[{"query": "query q1 { __typename }"},{"query": "query q2 { __typename }"}]',
]


class GraphQLAudit(BaseModule):
    id = "graphql_audit"
    name = "GraphQL Enumeration"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        base_url = f"https://{self.domain}"
        self.log("Probing for GraphQL endpoints...")

        graphql_paths = self.config.get("wordlists", {}).get("graphql_paths", [
            "/graphql", "/graphiql", "/api/graphql", "/gql", "/query",
            "/playground", "/__graphql", "/v1/graphql", "/graphql/v1",
        ])

        active_endpoints = []

        for path in graphql_paths:
            url = f"{base_url}{path}"
            r = await curl_with_status(url)
            status = r.get("status", 0)
            body = r.get("body", "")

            if status not in (200, 400, 405):
                continue

            # GraphQL endpoints often return 400 with JSON error on GET
            is_graphql = (
                "graphql" in body.lower()
                or '"errors"' in body
                or '"data"' in body
                or "must provide query string" in body.lower()
                or "syntax error" in body.lower()
                or "unexpected token" in body.lower()
            )

            if not is_graphql and status == 200:
                # Try POST with minimal query to confirm
                r2 = await curl(
                    url, method="POST",
                    headers={"Content-Type": "application/json"},
                    data='{"query":"{ __typename }"}',
                    output="body"
                )
                body2 = r2.get("body", "")
                is_graphql = '"data"' in body2 or '"errors"' in body2

            if is_graphql:
                active_endpoints.append(url)
                self.state.add_asset(
                    "api_endpoint",
                    f"graphql:{url}",
                    url,
                    confidence="CONFIRMED",
                    sources=["graphql probe"],
                    attrs={"type": "graphql", "path": path},
                )
                self.log(f"  GraphQL endpoint found: {url}")

        if not active_endpoints:
            self.state.skip_module(self.id, "no GraphQL endpoints found")
            return "skipped"

        # Audit each endpoint
        for endpoint in active_endpoints:
            await self._audit_endpoint(endpoint)

        self.state.complete_module(self.id)
        self.log(f"GraphQL: {len(active_endpoints)} endpoints audited")
        return "done"

    async def _audit_endpoint(self, endpoint: str):
        # 1. Introspection
        self.log(f"  Testing introspection: {endpoint}...")
        r = await curl(
            endpoint,
            method="POST",
            headers={"Content-Type": "application/json"},
            data=json.dumps({"query": INTROSPECTION_QUERY}),
            output="body",
        )
        body = r.get("body", "")
        try:
            data = json.loads(body)
            introspection_enabled = bool(
                data.get("data", {}).get("__schema")
            )
        except (json.JSONDecodeError, AttributeError):
            introspection_enabled = False

        if introspection_enabled:
            schema = data.get("data", {}).get("__schema", {})
            types = schema.get("types", [])
            user_types = [t for t in types
                         if t.get("kind") in ("OBJECT", "INPUT_OBJECT")
                         and not t.get("name", "").startswith("__")]

            type_names = [t["name"] for t in user_types[:30]]

            evidence_id = self.state.add_evidence(
                self.id, "graphql", endpoint,
                {"introspection": True, "type_count": len(user_types),
                 "types": type_names, "schema_summary": str(schema)[:3000]},
            )

            self.state.add_finding(
                title=f"GraphQL Introspection Enabled: {endpoint}",
                severity="MEDIUM",
                confidence="CONFIRMED",
                category="API Security",
                description=(
                    f"GraphQL introspection is enabled at {endpoint}. "
                    f"Discovered {len(user_types)} schema types including: "
                    f"{', '.join(type_names[:10])}. "
                    f"Attackers can map the entire API schema."
                ),
                evidence=[
                    f"Endpoint: {endpoint}",
                    f"Types: {type_names[:15]}",
                    f"Has mutations: {schema.get('mutationType') is not None}",
                ],
                evidence_refs=[evidence_id],
                remediation="Disable introspection in production. Use query depth limits and complexity analysis.",
            )

            # Look for sensitive types in schema
            sensitive_type_keywords = [
                "user", "password", "token", "secret", "admin", "credential",
                "auth", "payment", "card", "ssn", "private", "internal"
            ]
            sensitive_types = [
                t for t in type_names
                if any(kw in t.lower() for kw in sensitive_type_keywords)
            ]
            if sensitive_types:
                self.state.add_finding(
                    title=f"GraphQL Schema Contains Sensitive Types",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    category="API Security",
                    description=f"Schema reveals sensitive types: {sensitive_types}. "
                                f"Test these types for excessive data exposure and IDOR.",
                    evidence=[f"Sensitive types: {sensitive_types[:10]}"],
                    remediation="Audit sensitive types for proper authorization and field-level restrictions.",
                )
        else:
            # 2. Field suggestion attack (introspection disabled)
            r2 = await curl(
                endpoint,
                method="POST",
                headers={"Content-Type": "application/json"},
                data=json.dumps({"query": FIELD_SUGGESTION_QUERY}),
                output="body",
            )
            suggestion_body = r2.get("body", "")
            if "did you mean" in suggestion_body.lower():
                self.state.add_finding(
                    title=f"GraphQL Field Suggestion Leak: {endpoint}",
                    severity="LOW",
                    confidence="CONFIRMED",
                    category="API Security",
                    description="GraphQL returns field suggestions ('Did you mean...') even with "
                                "introspection disabled. Schema can be enumerated via wordlist attack.",
                    evidence=[
                        f"Endpoint: {endpoint}",
                        f"Suggestion response: {suggestion_body[:300]}",
                    ],
                    remediation="Disable field suggestions in production GraphQL configuration.",
                )

        # 3. Batch query test
        self.log(f"  Testing batch queries: {endpoint}...")
        for batch_query in BATCH_TEST_QUERIES:
            r3 = await curl(
                endpoint,
                method="POST",
                headers={"Content-Type": "application/json"},
                data=batch_query,
                output="body",
            )
            b3 = r3.get("body", "")
            try:
                b3_data = json.loads(b3)
                if isinstance(b3_data, list) and len(b3_data) > 1:
                    self.state.add_finding(
                        title=f"GraphQL Batch Queries Enabled: {endpoint}",
                        severity="MEDIUM",
                        confidence="CONFIRMED",
                        category="API Security",
                        description="GraphQL endpoint accepts batched queries. "
                                    "Can be used to bypass rate limiting by multiplexing many "
                                    "queries in a single request.",
                        evidence=[f"Batch response: {str(b3_data)[:300]}"],
                        remediation="Limit batch query size or disable batching in production.",
                    )
                    break
            except (json.JSONDecodeError, TypeError):
                pass

        # 4. CSRF via GET query
        r4 = await curl(
            f"{endpoint}?query=%7B__typename%7D",
            output="body",
        )
        b4 = r4.get("body", "")
        if '"data"' in b4 or "__typename" in b4:
            self.state.add_finding(
                title=f"GraphQL Query via GET (CSRF Risk): {endpoint}",
                severity="MEDIUM",
                confidence="CONFIRMED",
                category="API Security",
                description="GraphQL endpoint accepts queries via GET request. "
                            "This enables CSRF attacks against authenticated mutations "
                            "and may bypass CORS restrictions.",
                evidence=[f"GET query response: {b4[:200]}"],
                remediation="Only accept POST requests for GraphQL mutations; "
                            "disable query execution via GET.",
            )
