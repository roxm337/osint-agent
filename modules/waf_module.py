"""Stage 4: WAF Mapping — detect, classify, and find gaps."""

from modules.base import BaseModule
from tools.wrappers import curl


class WAFMapping(BaseModule):
    id = "waf_mapping"
    name = "WAF Mapping"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]

    PROBE_PATHS = {
        "sensitive": [
            "/wp-config.php", "/.env", "/.git/config",
            "/wp-admin/", "/xmlrpc.php", "/wp-config.bak",
        ],
        "normal": [
            "/", "/wp-json/", "/wp-login.php",
            "/sitemap.xml", "/robots.txt",
        ],
        "scan_signals": [
            "/wp-content/plugins/", "/wp-content/themes/",
            "/wp-content/uploads/", "/wp-includes/",
        ],
        "file_exists": [
            "/.htpasswd", "/.htaccess",
        ],
    }

    BYPASS_TECHNIQUES = [
        {"name": "http1.0", "desc": "HTTP/1.0", "kwargs": {"http1_0": True}},
        {"name": "post_method", "desc": "POST method", "kwargs": {"method": "POST"}},
        {"name": "put_method", "desc": "PUT method", "kwargs": {"method": "PUT"}},
        {"name": "case_upper", "desc": "Upper case", "kwargs": {}},
        {"name": "x_forwarded", "desc": "X-Forwarded-For: 127.0.0.1",
         "kwargs": {"headers": {"X-Forwarded-For": "127.0.0.1"}}},
        {"name": "localhost_host", "desc": "Host: localhost",
         "kwargs": {"headers": {"Host": "localhost"}}},
    ]

    async def run(self) -> str:
        base_url = f"https://{self.domain}"
        self.log("Mapping WAF behavior...")

        waf_blocks = []
        waf_allows = []
        waf_vendor = None
        rate_limit = None

        # Phase 1: Probe all paths to understand WAF
        self.log("Phase 1: Path classification...")
        for category, paths in self.PROBE_PATHS.items():
            for path in paths:
                result = await self.http_get(f"{base_url}{path}")
                status = result.get("status", 0)

                # Check for WAF headers
                if status == 503:
                    waf_blocks.append({"path": path, "code": 503, "category": category})
                    self.state.record_waf_block(path, 503)
                elif status == 500:
                    waf_blocks.append({"path": path, "code": 500, "category": category})
                    self.state.record_waf_block(path, 500)
                elif status == 200:
                    waf_allows.append({"path": path, "code": 200, "category": category})
                    self.state.record_waf_allow(path, 200)
                elif status == 403:
                    # Apache block (file exists but protected)
                    waf_allows.append({"path": path, "code": 403, "category": category,
                                       "note": "Apache protected (file exists)"})

        # Phase 2: Try bypass on blocked paths (max 3)
        self.log("Phase 2: Bypass attempts...")
        blocked_sensitive = [b for b in waf_blocks if b["category"] == "sensitive"]
        bypass_results = []

        for block in blocked_sensitive[:2]:  # Max 2 blocked paths
            for tech in self.BYPASS_TECHNIQUES[:3]:  # Max 3 bypass techniques
                kwargs = tech["kwargs"].copy()
                path_arg = block["path"]

                if tech["name"] == "case_upper":
                    path_arg = block["path"].upper()

                result = await curl(f"{base_url}{path_arg}", **kwargs)
                status = result.get("status", 0)

                bypass_results.append({
                    "path": block["path"],
                    "technique": tech["name"],
                    "result": status,
                    "success": status not in (503, 500, 429),
                })

                if status == 200:
                    self.log(f"  BYPASS: {tech['desc']} on {block['path']} → {status}")

        # Phase 3: Detect WAF vendor
        self.log("Phase 3: WAF vendor identification...")
        vendor_headers = ["x-ws-origin", "x-sucuri-id", "cf-ray",
                          "x-powered-by", "server"]
        for path in ["/", "/wp-login.php"]:
            result = await curl(f"{base_url}{path}", output="headers")
            headers_text = result.get("body", "").lower()
            if "x-ws-origin" in headers_text:
                waf_vendor = "IONOS WebServer"
            elif "cf-ray" in headers_text or "cloudflare" in headers_text:
                waf_vendor = "Cloudflare"
            elif "x-sucuri" in headers_text:
                waf_vendor = "Sucuri WAF"
            elif "x-aws-waf" in headers_text:
                waf_vendor = "AWS WAF"

            # Rate limit detection
            if "x-ws-ratelimit" in headers_text:
                for line in headers_text.split("\n"):
                    if "x-ws-ratelimit-limit" in line:
                        rate_limit = line.split(":")[-1].strip()

        # Store WAF info
        waf_info = {
            "detected": len(waf_blocks) > 0,
            "vendor": waf_vendor,
            "rate_limit": rate_limit,
            "blocks": waf_blocks,
            "allows": waf_allows,
            "bypass_attempts": bypass_results,
        }

        self.state.add_asset(
            "waf",
            f"waf:{base_url}",
            base_url,
            confidence="CONFIRMED" if waf_vendor else ("FIRM" if waf_blocks else "TENTATIVE"),
            sources=["WAF mapping"],
            attrs=waf_info,
        )

        # Findings
        if waf_vendor:
            self.state.add_finding(
                title=f"WAF Detected: {waf_vendor}",
                severity="INFO",
                confidence="CONFIRMED",
                category="Defense Mechanism",
                description=f"{waf_vendor} WAF identified with rate limit "
                            f"{rate_limit or 'unknown'}.",
                evidence=[f"Vendor: {waf_vendor}",
                          f"Blocks: {len(waf_blocks)} paths",
                          f"Allows: {len(waf_allows)} paths"],
                remediation="Map allowed paths to find WAF gaps.",
            )

        # WAF gap finding (what's allowed that shouldn't be)
        sensitive_allowed = [a for a in waf_allows if a["category"] == "sensitive"]
        if sensitive_allowed:
            self.state.add_finding(
                title="WAF Gap: Sensitive Paths Allowed",
                severity="MEDIUM",
                confidence="CONFIRMED",
                category="Defense Gap",
                description=f"WAF allows {len(sensitive_allowed)} sensitive paths: "
                            f"{[a['path'] for a in sensitive_allowed]}.",
                evidence=[f"Allowed sensitive paths: {sensitive_allowed}"],
                remediation="Add WAF rules to protect sensitive paths.",
            )

        self.state.complete_module(self.id)
        self.log(f"WAF: {waf_vendor or 'unknown'} | {len(waf_blocks)} blocked, "
                 f"{len(waf_allows)} allowed")
        return "done"
