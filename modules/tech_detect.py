"""Stage 3: Technology Detection — headers, body, vendor fingerprints, whatweb."""

import re
from modules.base import BaseModule
from tools.wrappers import curl, curl_with_status, cert_info
from tools.external import whatweb_scan, httpx_probe, tool_available


VENDOR_FINGERPRINTS = {
    "citrix_netscaler": {
        "paths": ["/vpn/index.html", "/logon/LogonPoint/index.html"],
        "body_patterns": ["NetScaler", "Citrix Gateway", "logon/LogonPoint"],
        "severity": "INFO",
    },
    "f5_bigip": {
        "paths": ["/my.policy", "/tmui/login.jsp"],
        "body_patterns": ["BIG-IP", "F5 Networks", "tmui"],
        "severity": "INFO",
    },
    "fortinet_fortigate": {
        "paths": ["/remote/login", "/remote/fgt_lang?lang=en"],
        "body_patterns": ["FortiGate", "Fortinet", "fortios"],
        "severity": "INFO",
    },
    "pulse_secure": {
        "paths": ["/dana-na/auth/url_default/welcome.cgi"],
        "body_patterns": ["Pulse Secure", "Juniper Networks SSL VPN"],
        "severity": "INFO",
    },
    "paloalto_globalprotect": {
        "paths": ["/global-protect/login.esp", "/php/login.php"],
        "body_patterns": ["GlobalProtect", "Palo Alto Networks"],
        "severity": "INFO",
    },
    "vmware_horizon": {
        "paths": ["/portal/", "/ui/#/login"],
        "body_patterns": ["VMware Horizon", "View-Signature"],
        "severity": "INFO",
    },
    "exchange_owa": {
        "paths": ["/owa/", "/owa/auth/logon.aspx", "/ecp/"],
        "body_patterns": ["Outlook Web App", "OWA", "Microsoft Exchange"],
        "severity": "MEDIUM",
    },
    "jenkins": {
        "paths": ["/jenkins", "/jenkins/login"],
        "body_patterns": ["Jenkins", "hudson.util.Secret", "j_spring_security_check"],
        "severity": "HIGH",
    },
    "gitlab": {
        "paths": ["/users/sign_in", "/explore"],
        "body_patterns": ["GitLab", "gl_user", "gitlab-logo"],
        "severity": "HIGH",
    },
    "kibana": {
        "paths": ["/app/kibana", "/app/dashboards", "/app/home"],
        "body_patterns": ["Kibana", "kbn-", "elastic.co"],
        "severity": "HIGH",
    },
    "grafana": {
        "paths": ["/grafana", "/grafana/login"],
        "body_patterns": ["Grafana", "grafana_session"],
        "severity": "HIGH",
    },
    "jupyter": {
        "paths": ["/tree", "/api/kernels", "/login"],
        "body_patterns": ["Jupyter", "jupyter-notebook", "ipython"],
        "severity": "CRITICAL",
    },
    "wordpress_login": {
        "paths": ["/wp-login.php", "/wp-admin/"],
        "body_patterns": ["wp-login", "WordPress", "wp-admin"],
        "severity": "MEDIUM",
    },
    "phpmyadmin": {
        "paths": ["/phpmyadmin/", "/pma/", "/adminer.php"],
        "body_patterns": ["phpMyAdmin", "Adminer", "pmahome"],
        "severity": "HIGH",
    },
    "cpanel": {
        "paths": ["/cpanel", "/whm"],
        "body_patterns": ["cPanel", "WHM"],
        "severity": "HIGH",
    },
    "kubernetes_dashboard": {
        "paths": ["/api/v1/namespaces", "/api/v1/pods"],
        "body_patterns": ["Kubernetes", "apiVersion", "kubectl"],
        "severity": "CRITICAL",
    },
    "spring_boot": {
        "paths": ["/actuator", "/actuator/health", "/health", "/info"],
        "body_patterns": ["Spring Boot", "\"status\":\"UP\"", "actuator"],
        "severity": "MEDIUM",
    },
    "solarwinds": {
        "paths": ["/Orion/Login.aspx"],
        "body_patterns": ["SolarWinds", "Orion"],
        "severity": "HIGH",
    },
}

MISSING_HEADER_FINDINGS = {
    "strict-transport-security": ("HSTS Missing", "MEDIUM",
        "HSTS header missing. Browsers may downgrade to HTTP."),
    "content-security-policy": ("CSP Missing", "MEDIUM",
        "Content-Security-Policy missing. XSS and injection risks elevated."),
    "x-frame-options": ("Clickjacking Protection Missing", "MEDIUM",
        "X-Frame-Options missing. Site can be embedded in iframes for clickjacking."),
    "x-content-type-options": ("MIME Sniffing Protection Missing", "LOW",
        "X-Content-Type-Options: nosniff missing. Browser MIME-sniffing attacks possible."),
    "referrer-policy": ("Referrer-Policy Missing", "LOW",
        "No Referrer-Policy set. Sensitive URL parameters may leak in Referer headers."),
    "permissions-policy": ("Permissions-Policy Missing", "LOW",
        "Permissions-Policy missing. Browser features (camera, geolocation) unconstrained."),
}


class TechDetection(BaseModule):
    id = "tech_detection"
    name = "Technology Detection"
    stage = 3
    detectability = "low"
    depends_on = ["seed_discovery"]

    async def run(self) -> str:
        self.log(f"Detecting tech stack for {self.domain}")
        base_url = f"https://{self.domain}"

        tech = {
            "server": "",
            "cms": "",
            "framework": "",
            "php_version": "",
            "theme": "",
            "plugins": [],
            "security_headers": {},
            "vendor_products": [],
        }

        # 1. Fetch headers + body in full mode
        result = await curl(base_url, output="full")
        headers_text = result.get("headers", "")
        body = result.get("body", "")

        tech["raw_headers"] = headers_text[:3000]

        # Parse response headers
        headers_lower = headers_text.lower()
        for line in headers_text.split("\n"):
            l = line.lower()
            if "server:" in l:
                tech["server"] = line.split(":", 1)[1].strip()
            elif "x-powered-by:" in l:
                tech["php_version"] = line.split(":", 1)[1].strip()
            elif "x-generator:" in l or "generator:" in l:
                tech["cms"] = line.split(":", 1)[1].strip()
            elif "x-aspnet-version:" in l:
                tech["framework"] = "ASP.NET " + line.split(":", 1)[1].strip()
            elif "x-runtime:" in l:
                tech["framework"] = "Ruby on Rails"

        # 2. Security headers audit
        security = {
            "strict-transport-security": False,
            "content-security-policy": False,
            "x-frame-options": False,
            "x-content-type-options": False,
            "referrer-policy": False,
            "permissions-policy": False,
        }
        for h in security:
            if f"\n{h}:" in headers_lower or headers_lower.startswith(f"{h}:"):
                for line in headers_text.split("\n"):
                    if line.lower().startswith(h + ":"):
                        security[h] = line.split(":", 1)[1].strip()
                        break

        tech["security_headers"] = security

        # 3. CMS detection from body
        if body:
            if "wp-content" in body or "/wp-includes/" in body:
                tech["cms"] = "WordPress"
            elif "joomla" in body.lower():
                tech["cms"] = "Joomla"
            elif "drupal" in body.lower() or "/sites/default/files" in body:
                tech["cms"] = "Drupal"
            elif "typo3" in body.lower():
                tech["cms"] = "TYPO3"
            elif "wix.com" in body.lower():
                tech["cms"] = "Wix"
            elif "shopify" in body.lower():
                tech["cms"] = "Shopify"
            elif "react" in body.lower() and "__next" in body.lower():
                tech["framework"] = "Next.js"
            elif "ng-version" in body.lower():
                tech["framework"] = "Angular"
            elif "vue" in body.lower():
                tech["framework"] = "Vue.js"
            elif "laravel" in body.lower() or "csrf-token" in body.lower():
                tech["framework"] = "Laravel"

        # 4. WordPress version from readme.html
        if "WordPress" in tech.get("cms", ""):
            readme = await curl(f"{base_url}/readme.html", output="body")
            wp_match = re.search(r'WordPress\s+(\d+\.\d+[.\d]*)', readme.get("body", ""))
            if wp_match:
                tech["wordpress_version"] = wp_match.group(1)
                tech["cms"] = f"WordPress {wp_match.group(1)}"

            # Check plugins
            plugins = self.config.get("wordlists", {}).get("wp_plugins", [])
            for plugin in plugins[:30]:
                r = await curl(f"{base_url}/wp-content/plugins/{plugin}/readme.txt")
                if r.get("status") == 200:
                    tech["plugins"].append(plugin)

            # Theme detection from body
            theme_match = re.search(r'/wp-content/themes/([^/"\']+)', body)
            if theme_match:
                tech["theme"] = theme_match.group(1)

        # 5. whatweb scan (if available)
        ww = await whatweb_scan(base_url)
        if ww.get("available") and ww.get("results"):
            tech["whatweb"] = ww["results"]

        # 6. httpx tech-detect (if available)
        httpx_results = await httpx_probe([base_url])
        if httpx_results:
            hr = httpx_results[0]
            tech["httpx_tech"] = hr.get("tech", [])
            if hr.get("web-server") and not tech["server"]:
                tech["server"] = hr.get("web-server", "")

        # 7. TLS certificate
        cert = await cert_info(self.domain)
        tech["tls"] = cert
        # SANs reveal additional subdomains
        for san in cert.get("san", []):
            san = san.strip().lower()
            if san and san.endswith(f".{self.domain}") and san != self.domain:
                self.state.add_asset(
                    "subdomain", f"sub:{san}", san,
                    confidence="CONFIRMED",
                    sources=["TLS SAN"],
                )

        # 8. Vendor fingerprint checks
        await self._check_vendor_fingerprints(base_url, tech, body)

        # Store main webapp asset
        self.state.add_asset(
            "webapp",
            f"webapp:{base_url}",
            base_url,
            confidence="CONFIRMED",
            sources=["http probe", "tls handshake"],
            attrs=tech,
        )

        # Findings: missing security headers
        missing = [h for h, v in security.items() if v is False]
        if missing:
            self.state.add_finding(
                title="Missing Security Headers",
                severity="MEDIUM",
                confidence="CONFIRMED",
                category="Hardening Deficiency",
                description=f"The webapp is missing {len(missing)} security headers: "
                            f"{', '.join(missing)}.",
                evidence=[f"Missing: {h}" for h in missing],
                remediation="Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options, "
                            "Referrer-Policy, and Permissions-Policy headers.",
                asset_keys=[f"webapp:{base_url}"],
            )

        # Check for version disclosure
        if tech.get("server") and any(
            re.search(r"\d+\.\d+", tech["server"]) for _ in [1]
        ):
            self.state.add_finding(
                title="Server Version Disclosure",
                severity="LOW",
                confidence="CONFIRMED",
                category="Information Disclosure",
                description=f"Server header discloses version: {tech['server']}",
                evidence=[f"Server: {tech['server']}"],
                remediation="Remove version information from Server header.",
                asset_keys=[f"webapp:{base_url}"],
            )

        self.state.complete_module(self.id)
        self.log(f"Tech: {tech.get('cms') or tech.get('framework') or 'unknown'} | "
                 f"Server: {tech.get('server', 'unknown')} | "
                 f"Vendor products: {len(tech['vendor_products'])}")
        return "done"

    async def _check_vendor_fingerprints(self, base_url: str, tech: dict, main_body: str):
        """Check for vendor-specific products on common paths."""
        for product_name, fp in VENDOR_FINGERPRINTS.items():
            detected = False
            evidence = []

            # Check body patterns on main page first (cheap)
            for pattern in fp["body_patterns"]:
                if pattern.lower() in main_body.lower():
                    detected = True
                    evidence.append(f"Body pattern: '{pattern}' on {base_url}")
                    break

            # Check specific paths if not already detected
            if not detected:
                for path in fp["paths"][:2]:
                    r = await curl_with_status(f"{base_url}{path}")
                    status = r.get("status", 0)
                    body = r.get("body", "")
                    if status in (200, 302, 301):
                        for pattern in fp["body_patterns"]:
                            if pattern.lower() in body.lower():
                                detected = True
                                evidence.append(f"Path: {base_url}{path} ({status})")
                                break
                    if detected:
                        break

            if detected:
                tech["vendor_products"].append(product_name)
                self.state.add_asset(
                    "webapp",
                    f"vendor:{base_url}:{product_name}",
                    f"{base_url} [{product_name}]",
                    confidence="FIRM",
                    sources=["vendor fingerprint"],
                    attrs={"product": product_name},
                )
                if fp["severity"] in ("HIGH", "CRITICAL", "MEDIUM"):
                    self.state.add_finding(
                        title=f"Vendor Product Detected: {product_name.replace('_', ' ').title()}",
                        severity=fp["severity"],
                        confidence="FIRM",
                        category="Attack Surface",
                        description=f"Detected {product_name.replace('_', ' ').title()} at "
                                    f"{base_url}. Verify version and check for known CVEs.",
                        evidence=evidence,
                        remediation="Ensure latest version is deployed and access is restricted.",
                        asset_keys=[f"webapp:{base_url}"],
                    )
