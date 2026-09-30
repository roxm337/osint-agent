"""Stage 4: JavaScript Analysis — secrets, endpoints, source maps."""

import re
from modules.base import BaseModule
from tools.wrappers import curl_with_status, bash
from core.response_fingerprint import establish_baseline, fingerprint
from core.surface import script_urls_from_html


# 43+ secret regex patterns
SECRET_PATTERNS = [
    # AWS
    ("aws_access_key", r"AKIA[0-9A-Z]{16}", "CRITICAL"),
    ("aws_secret_key", r"(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key[\s\"'`]?[:=][\s\"'`]?[A-Za-z0-9/+=]{40}", "CRITICAL"),
    # Anthropic
    ("anthropic_key", r"sk-ant-[a-zA-Z0-9_\-]{48,}", "CRITICAL"),
    # OpenAI
    ("openai_key", r"sk-[a-zA-Z0-9]{48}", "CRITICAL"),
    ("openai_project_key", r"sk-proj-[a-zA-Z0-9\-_]{48,}", "CRITICAL"),
    # GitHub
    ("github_pat", r"ghp_[a-zA-Z0-9]{36}", "CRITICAL"),
    ("github_token", r"(?i)github[_\-\s]?token[\s\"'`]?[:=][\s\"'`]?[a-zA-Z0-9_]{40}", "CRITICAL"),
    # Google
    ("google_api_key", r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
    ("google_oauth", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "HIGH"),
    # Stripe
    ("stripe_live_key", r"sk_live_[0-9a-zA-Z]{24}", "CRITICAL"),
    ("stripe_restricted_key", r"rk_live_[0-9a-zA-Z]{24}", "HIGH"),
    # Twilio
    ("twilio_account_sid", r"AC[a-f0-9]{32}", "HIGH"),
    ("twilio_auth_token", r"(?i)twilio[_\-\s]?auth[_\-\s]?token[\s\"'`]?[:=][\s\"'`]?[a-f0-9]{32}", "HIGH"),
    # Slack
    ("slack_token", r"xox[bpoa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{32}", "CRITICAL"),
    ("slack_webhook", r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+", "HIGH"),
    # SendGrid
    ("sendgrid_key", r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}", "HIGH"),
    # Mailchimp
    ("mailchimp_key", r"[a-f0-9]{32}-us[0-9]{2}", "MEDIUM"),
    # HuggingFace
    ("huggingface_token", r"hf_[a-zA-Z0-9]{34,}", "HIGH"),
    # Cloudflare
    ("cloudflare_token", r"(?i)cloudflare[_\-\s]?token[\s\"'`]?[:=][\s\"'`]?[a-zA-Z0-9_\-]{40}", "HIGH"),
    # DigitalOcean
    ("digitalocean_token", r"(?i)do[_\-\s]?token[\s\"'`]?[:=][\s\"'`]?[a-f0-9]{64}", "HIGH"),
    # npm
    ("npm_token", r"npm_[A-Za-z0-9]{36}", "HIGH"),
    # PyPI
    ("pypi_token", r"pypi-[A-Za-z0-9\-_]{40,}", "HIGH"),
    # Docker Hub
    ("docker_config", r"\"auth\":\s*\"[A-Za-z0-9+/=]{20,}\"", "HIGH"),
    # Atlassian
    ("atlassian_token", r"(?i)atlassian[_\-\s]?token[\s\"'`]?[:=][\s\"'`]?[a-zA-Z0-9]{24,}", "HIGH"),
    # DataDog
    ("datadog_api_key", r"(?i)datadog[_\-\s]?api[_\-\s]?key[\s\"'`]?[:=][\s\"'`]?[a-f0-9]{32}", "HIGH"),
    # Sentry
    ("sentry_dsn", r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+", "MEDIUM"),
    # ngrok
    ("ngrok_token", r"(?i)ngrok[_\-\s]?token[\s\"'`]?[:=][\s\"'`]?[a-zA-Z0-9_\-]{32,}", "MEDIUM"),
    # Private keys
    ("private_key_rsa", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "CRITICAL"),
    # JWT
    ("jwt_token", r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "MEDIUM"),
    # Generic passwords in config
    ("generic_password", r"(?i)\"?password\"?\s*[:=]\s*\"([^\"]{8,})\"", "MEDIUM"),
    ("db_password", r"(?i)db[_\-]?pass(?:word)?[\s\"'`]?[:=][\s\"'`]?[^\s\"'`,]{8,}", "HIGH"),
    ("db_connection", r"(?i)(mysql|postgres|mongodb|redis)://[^:]+:[^@]+@", "HIGH"),
    # Firebase
    ("firebase_key", r"(?i)firebase[_\-\s]?key[\s\"'`]?[:=][\s\"'`]?[a-zA-Z0-9_\-]{32,}", "HIGH"),
    ("firebase_url", r"https://[a-zA-Z0-9\-]+\.firebaseio\.com", "LOW"),
    # Generic API key patterns
    ("generic_api_key", r"(?i)[\"']api[_\-]?key[\"']\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{16,64})[\"']", "MEDIUM"),
    ("generic_secret", r"(?i)[\"']secret[\"']\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{16,64})[\"']", "MEDIUM"),
    # Internal URLs / IPs
    ("internal_ip", r"(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}", "LOW"),
]


# Identifiers that are public by design and cannot be kept secret.
#
# These are not secrets and must not be reported as credential exposure. An
# OAuth client ID is published by the authorisation server, embedded in every
# app that uses the flow, and carries no authority on its own — RFC 8252 and
# the OAuth 2.0 Security BCP both require it to be a public client. The same
# is true of a Twilio Account SID (the secret is the Auth Token) and a Sentry
# DSN (it authenticates event submission, nothing else).
#
# Reporting these as HIGH credential exposure is the same class of error as
# calling a 404 page a leaked database backup: a pattern that reliably matches
# real code is not evidence of a real problem. They are kept, because knowing
# an app's OAuth client and Sentry project is genuinely useful recon, but they
# are reported as INFO with a note explaining why they are not a finding.
PUBLIC_BY_DESIGN = {
    "google_oauth": "OAuth client IDs are public clients by design; the "
                    "security of the flow rests on the client secret and "
                    "redirect URI validation, not on hiding this.",
    "twilio_account_sid": "Account SID is an account identifier; the Auth "
                          "Token is the credential.",
    "sentry_dsn": "DSNs are embedded in client applications by design and "
                  "only authorise event submission.",
    "firebase_url": "The Firebase database URL is not a credential; "
                    "access is controlled by its security rules.",
}


def extract_endpoints(js_content: str, base_url: str) -> list:
    """Extract API endpoints and interesting paths from JS source."""
    patterns = [
        r'["\'`](/(?:api|v[0-9]+|rest|graphql|auth|user|admin|manage)[^"\'`\s]{0,100})["\'\`]',
        r'["\'`](https?://[^\s"\'`]+)["\'\`]',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'url:\s*["\']([^"\']+)["\']',
        r'endpoint:\s*["\']([^"\']+)["\']',
        r'baseURL:\s*["\']([^"\']+)["\']',
        r'baseUrl:\s*["\']([^"\']+)["\']',
        r'API_URL\s*=\s*["\']([^"\']+)["\']',
    ]
    endpoints = set()
    for pattern in patterns:
        for match in re.findall(pattern, js_content):
            if match and len(match) > 2:
                endpoints.add(match)
    return list(endpoints)[:100]


DOM_SINK_PATTERNS = [
    ("innerHTML", r"\.innerHTML\s*="),
    ("outerHTML", r"\.outerHTML\s*="),
    ("insertAdjacentHTML", r"\.insertAdjacentHTML\s*\("),
    ("document.write", r"\bdocument\.write(?:ln)?\s*\("),
    ("eval", r"\beval\s*\("),
    ("Function", r"\bnew\s+Function\s*\("),
    ("setTimeout-string", r"\bsetTimeout\s*\(\s*['\"`]"),
    ("setInterval-string", r"\bsetInterval\s*\(\s*['\"`]"),
    ("location-assignment", r"\b(?:location|window\.location)\s*="),
    ("postMessage-send", r"\.postMessage\s*\("),
    ("postMessage-handler", r"addEventListener\s*\(\s*['\"]message['\"]"),
    ("onmessage-handler", r"\bonmessage\s*="),
    ("dangerouslySetInnerHTML", r"\bdangerouslySetInnerHTML\b"),
]


def extract_dom_sinks(js_content: str, source: str = "") -> list[dict]:
    """Extract DOM-XSS-relevant sinks and message handlers from JS source."""
    sinks = []
    for sink_name, pattern in DOM_SINK_PATTERNS:
        for match in re.finditer(pattern, js_content, flags=re.I):
            start = max(match.start() - 80, 0)
            end = min(match.end() + 140, len(js_content))
            snippet = re.sub(r"\s+", " ", js_content[start:end]).strip()
            sinks.append({
                "sink": sink_name,
                "source": source,
                "offset": match.start(),
                "snippet": snippet[:240],
            })
    return sinks[:200]


class JSAnalysis(BaseModule):
    id = "js_analysis"
    name = "JavaScript Analysis"
    stage = 4
    detectability = "low"
    depends_on = ["wayback_machine", "tech_detection"]

    async def run(self) -> str:
        base_url = self.base_url
        self.log("Analyzing JavaScript files for secrets and endpoints...")

        # Collect JS files from multiple sources
        js_urls = set()

        # From wayback data
        js_assets = self.state.get_assets_by_type("js_file")
        for asset in js_assets:
            js_urls.add(asset["value"])

        # From main page source
        main_result = await curl_with_status(base_url)
        body = main_result.get("body", "")
        if body:
            # Resolve every <script src> against the page it was loaded from.
            #
            # The old code handled only absolute URLs and paths beginning with
            # "/", so a page written `<script src="main.js">` — a plain
            # relative reference, and the most common form there is — yielded
            # nothing at all. That is why this module reported 0 files
            # analysed against a target shipping a 1.2 MB bundle, and it was
            # invisible in the output because "0 files" and "no scripts
            # referenced" look the same in a stats dict.
            for src in script_urls_from_html(body, base_url):
                js_urls.add(src)

        # Common JS guess paths
        js_guess_paths = [
            "/app.js", "/main.js", "/bundle.js", "/app.bundle.js",
            "/assets/app.js", "/static/js/main.js", "/js/app.js",
            "/dist/bundle.js", "/build/app.js", "/public/app.js",
            "/static/bundle.js", "/js/bundle.js", "/assets/index.js",
        ]

        # Establish what this site serves at a path that is not a script,
        # before judging any guess as JavaScript.
        #
        # The old gate was `status == 200 and "function" in body`, which a
        # modern SPA passes for every path: its catch-all index.html contains
        # the word "function" somewhere in a boot script. So `/app.js`,
        # `/bundle.js` and `/js/main.js` were all "found" on a target that
        # serves none of them, each 9 KB of HTML, and each was then analysed
        # as a bundle — reporting the application's own shell as its
        # JavaScript. Comparing against the catch-all body is what separates a
        # real bundle from the shell it is being mistaken for.
        # Three-tuple, in the order `establish_baseline` documents:
        # `(status, body, content_type)`. Returning two here made the unpack
        # raise, the helper's `except` swallowed it, and the baseline came
        # back empty — `root=none controls=0` — so the catch-all gate below
        # matched nothing and the module silently fell back to guessing. A
        # helper that returns "I could not measure" and a helper that returns
        # "everything is catch-all" must not look the same to the caller.
        async def probe(path: str):
            r = await curl_with_status(f"{base_url}{path}")
            ct = ""
            for line in str(r.get("headers", "")).splitlines():
                if line.lower().startswith("content-type:"):
                    ct = line.split(":", 1)[1].strip()
                    break
            return (int(r.get("status", 0) or 0),
                    str(r.get("body", "") or ""),
                    ct)

        baseline = await establish_baseline(probe, base_url)
        self.log(f"  baseline: {baseline.describe()}")
        if baseline.root is None:
            self.log("  baseline unavailable — cannot tell a real bundle "
                     "from the catch-all shell; guessing at script paths is "
                     "unsafe, so only referenced scripts will be analysed.")

        # Only guess at paths at all if we can recognise a miss. Without a
        # baseline, every guess "succeeds" against a catch-all and the module
        # would collect the site's own HTML shell as JavaScript.
        if baseline.root is not None:
            for path in js_guess_paths:
                status, candidate, ct = await probe(path)
                if status != 200 or not candidate:
                    continue
                if baseline.catch_all(fingerprint(status, candidate, ct)):
                    continue
                js_urls.add(f"{base_url}{path}")

        target_js = [
            url for url in js_urls
            if self.domain in url and url.endswith(".js")
        ][:50]  # Limit to 50 files

        self.log(f"  Analyzing {len(target_js)} JS files...")

        all_secrets = []
        all_endpoints = []
        all_dom_sinks = []
        source_maps = []
        analyzed = 0
        skipped_catch_all = 0

        for js_url in target_js:
            result = await curl_with_status(js_url)
            if result.get("status") != 200:
                continue

            content = result.get("body", "")
            if not content or len(content) < 50:
                continue

            # A script src that resolves to the catch-all shell is not a
            # bundle. The page tags it as JavaScript, but what arrives is the
            # same HTML every other path returns, and analysing it as source
            # fills state with the site's own markup as discovered endpoints.
            ct = ""
            for line in str(result.get("headers", "")).splitlines():
                if line.lower().startswith("content-type:"):
                    ct = line.split(":", 1)[1].strip()
                    break
            if baseline.catch_all(fingerprint(int(result.get("status", 0) or 0),
                                               content, ct)):
                skipped_catch_all += 1
                continue

            analyzed += 1

            # Check for source map URL
            if "sourceMappingURL=" in content:
                map_match = re.search(r"sourceMappingURL=([^\s]+\.map)", content)
                if map_match:
                    map_url = map_match.group(1)
                    if not map_url.startswith("http"):
                        map_url = js_url.rsplit("/", 1)[0] + "/" + map_url
                    source_maps.append(map_url)

            # Secret scanning
            for pattern_name, pattern, severity in SECRET_PATTERNS:
                for match in re.findall(pattern, content):
                    matched_text = match if isinstance(match, str) else match[0]
                    # Skip obvious false positives
                    if len(matched_text) < 8 or "example" in matched_text.lower():
                        continue
                    all_secrets.append({
                        "type": pattern_name,
                        "severity": severity,
                        "match": matched_text[:80],
                        "source": js_url,
                    })

            # Endpoint extraction
            endpoints = extract_endpoints(content, base_url)
            for ep in endpoints:
                all_endpoints.append({"endpoint": ep, "source": js_url})

            # DOM-XSS sink discovery
            all_dom_sinks.extend(extract_dom_sinks(content, js_url))

        # Check source maps (may expose original source)
        for map_url in source_maps[:5]:
            r = await curl_with_status(map_url)
            if r.get("status") == 200:
                source_maps_found = True
                self.state.add_finding(
                    title=f"JavaScript Source Map Exposed: {map_url}",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    category="Information Disclosure",
                    description=f"JavaScript source map at {map_url} exposes original "
                                f"pre-compiled source code, potentially including "
                                f"secrets, comments, and internal logic.",
                    evidence=[f"Source map URL: {map_url}", f"Status: 200"],
                    remediation="Remove .map files from production deployments.",
                )

        # Deduplicate secrets
        seen_secrets = set()
        unique_secrets = []
        for s in all_secrets:
            key = (s["type"], s["match"][:40])
            if key not in seen_secrets:
                seen_secrets.add(key)
                unique_secrets.append(s)

        # Split out the identifiers that are public by design before grading.
        # They stay visible as recon, but they must not be graded as credential
        # exposure: a HIGH "secret" that the protocol requires you to publish
        # is a false positive that costs a triager an hour.
        public_hits = [s for s in unique_secrets if s["type"] in PUBLIC_BY_DESIGN]
        unique_secrets = [s for s in unique_secrets
                          if s["type"] not in PUBLIC_BY_DESIGN]

        # Create secret findings by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM"]:
            sev_secrets = [s for s in unique_secrets if s["severity"] == severity]
            if sev_secrets:
                self.state.add_finding(
                    title=f"Secrets Detected in JavaScript [{severity}]: {len(sev_secrets)} found",
                    severity=severity,
                    confidence="FIRM",
                    category="Credential Exposure",
                    description=(
                        f"Pattern-matched {len(sev_secrets)} potential secrets of type "
                        f"{severity} in JavaScript files. Types: "
                        f"{list({s['type'] for s in sev_secrets})}. "
                        f"Manual validation required."
                    ),
                    evidence=[
                        f"{s['type']}: {s['match'][:60]}... (in {s['source'].split('/')[-1]})"
                        for s in sev_secrets[:10]
                    ],
                    remediation="Remove secrets from client-side code; use server-side API proxying.",
                )

        # Store unique API endpoints
        unique_endpoints = list({ep["endpoint"] for ep in all_endpoints})
        for endpoint in unique_endpoints[:30]:
            if endpoint.startswith("http") and self.domain not in endpoint:
                continue
            self.state.add_asset(
                "api_endpoint",
                f"api:{endpoint}",
                endpoint,
                confidence="TENTATIVE",
                sources=["js_analysis"],
                attrs={"discovered_in": "js_analysis"},
            )

        seen_sinks = set()
        unique_dom_sinks = []
        for sink in all_dom_sinks:
            key = (sink["sink"], sink["source"], sink["offset"])
            if key not in seen_sinks:
                seen_sinks.add(key)
                unique_dom_sinks.append(sink)

        for sink in unique_dom_sinks[:200]:
            self.state.add_asset(
                "dom_sink",
                f"dom_sink:{sink['source']}:{sink['offset']}",
                sink["sink"],
                confidence="TENTATIVE",
                sources=["js_analysis"],
                attrs=sink,
            )

        if unique_dom_sinks:
            self.state.add_finding(
                title=f"DOM XSS Sink Candidates in JavaScript: {len(unique_dom_sinks)}",
                severity="MEDIUM",
                confidence="TENTATIVE",
                category="Client-Side Attack Surface",
                description=(
                    "JavaScript contains DOM sinks or postMessage handlers that may "
                    "be exploitable if attacker-controlled sources reach them."
                ),
                evidence=[
                    f"{sink['sink']} in {sink['source'].split('/')[-1]} near: {sink['snippet'][:120]}"
                    for sink in unique_dom_sinks[:12]
                ],
                remediation="Trace controllable sources to sinks, sanitize untrusted input, and enforce CSP.",
            )

        self.state.add_asset(
            "js_analysis",
            f"js_analysis:{self.domain}",
            self.domain,
            confidence="CONFIRMED",
            sources=["js_analysis"],
            attrs={
                "js_files_analyzed": analyzed,
                "total_js_urls": len(target_js),
                "skipped_catch_all": skipped_catch_all,
                "secrets_found": len(unique_secrets),
                "endpoints_found": len(unique_endpoints),
                "source_maps_found": len(source_maps),
                "dom_sinks_found": len(unique_dom_sinks),
            },
        )

        self.state.complete_module(self.id)
        self.log(
            f"JS analysis: {analyzed} files | {len(unique_secrets)} secrets | "
            f"{len(unique_endpoints)} endpoints | {len(source_maps)} source maps | "
            f"{len(unique_dom_sinks)} DOM sinks"
        )
        return "done"
