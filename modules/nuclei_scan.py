"""Stage 4: Nuclei vulnerability scan with technology-targeted templates."""

from modules.base import BaseModule
from tools.external import nuclei_scan, nuclei_multi, tool_available


SEVERITY_MAP = {
    "INFO": "INFO",
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}

# Tags to always run (passive/low-noise)
BASE_TAGS = ["osint", "exposure", "misconfiguration", "token-spray", "default-login"]

# Tags to run when specific tech is detected
TECH_TAG_MAP = {
    "WordPress": ["wordpress", "wp-plugin", "wp-theme"],
    "Joomla": ["joomla"],
    "Drupal": ["drupal"],
    "Spring Boot": ["springboot", "actuator"],
    "Jenkins": ["jenkins"],
    "GitLab": ["gitlab"],
    "Kibana": ["kibana", "elastic"],
    "Grafana": ["grafana"],
    "Jupyter": ["jupyter"],
    "Exchange": ["exchange"],
    "Citrix": ["citrix"],
    "Fortinet": ["fortinet"],
    "VMware": ["vmware"],
    "Kubernetes": ["kubernetes", "k8s"],
    "Docker": ["docker"],
    "Apache": ["apache"],
    "Nginx": ["nginx"],
    "IIS": ["iis"],
    "PHP": ["php"],
    "Laravel": ["laravel"],
}


class NucleiScan(BaseModule):
    id = "nuclei_scan"
    name = "Nuclei Vulnerability Scan"
    stage = 5
    detectability = "high"
    depends_on = ["tech_detection"]
    requires_auth = True

    async def run(self) -> str:
        self.log("Running authorized nuclei scan...")
        if not tool_available("nuclei"):
            self.state.skip_module(self.id, "nuclei not installed")
            return "skipped"

        target_url = f"https://{self.domain}"
        if not self.scope.check(target_url).allowed:
            self.state.block_module(self.id, "target outside scope")
            return "blocked"

        rate_limit = self.config.get("rate_limits", {}).get("scan", {}).get("per_minute", 10)

        # Determine technology-specific tags from detected tech
        webapp_assets = self.state.get_assets_by_type("webapp")
        detected_tech = set()
        for asset in webapp_assets:
            attrs = asset.get("attrs", {})
            cms = attrs.get("cms", "")
            server = attrs.get("server", "")
            vendor_products = attrs.get("vendor_products", [])
            framework = attrs.get("framework", "")
            for tech_name in [cms, server, framework] + vendor_products:
                if tech_name:
                    detected_tech.add(str(tech_name).split(" ")[0])

        # Build tag list. Do not add the broad "cve" tag to first-pass scans;
        # it creates a very large template run. Use detected tech tags first.
        tags = list(BASE_TAGS)
        for tech, tech_tags in TECH_TAG_MAP.items():
            if any(tech.lower() in dt.lower() for dt in detected_tech):
                tags.extend(tech_tags)
                self.log(f"  Adding tags for {tech}: {tech_tags}")

        first_pass_tags = sorted(set(tags))

        # Phase 1: General scan with all tags
        self.log(f"  Phase 1: Scanning with tags: {', '.join(first_pass_tags[:12])}...")
        result = await nuclei_scan(
            target_url,
            rate_limit=rate_limit,
            timeout=600,
            tags=first_pass_tags,
            severity=["low", "medium", "high", "critical"],
        )
        all_matches = result.get("results", [])

        cve_tags_used = []
        if self._allow_full_cve_pass(target_url, webapp_assets):
            cve_tags_used = ["cve"]
            self.log("  Phase 2: Confirmed apex CVE scan enabled")
            result2 = await nuclei_scan(
                target_url,
                rate_limit=rate_limit,
                timeout=900,
                tags=cve_tags_used,
                severity=["medium", "high", "critical"],
            )
            all_matches.extend(result2.get("results", []))

        # Deduplicate by template_id + matched_at
        seen = set()
        unique_matches = []
        for m in all_matches:
            key = (m.get("template_id", ""), m.get("matched_at", ""))
            if key not in seen:
                seen.add(key)
                unique_matches.append(m)

        evidence_id = self.state.add_evidence(
            self.id,
            "nuclei",
            target_url,
            {
                "target": target_url,
                "tags_used": first_pass_tags + cve_tags_used,
                "detected_tech": sorted(detected_tech),
                "total_matches": len(unique_matches),
                "exit_code": result.get("exit_code"),
            },
        )

        finding_counts = {}
        for match in unique_matches:
            severity = SEVERITY_MAP.get(match.get("severity", "INFO"), "INFO")
            finding_counts[severity] = finding_counts.get(severity, 0) + 1

            # Create individual findings for HIGH/CRITICAL
            if severity in ("HIGH", "CRITICAL"):
                self.state.add_finding(
                    title=f"Nuclei [{severity}]: {match.get('name') or match.get('template_id')}",
                    severity=severity,
                    confidence="FIRM",
                    category="Vulnerability Scan",
                    description=(
                        f"Nuclei template {match.get('template_id')} matched at "
                        f"{match.get('matched_at')}."
                    ),
                    evidence=[
                        f"Template: {match.get('template_id')}",
                        f"Matched: {match.get('matched_at')}",
                        f"Type: {match.get('type', 'http')}",
                    ] + ([f"Curl: {match['curl_command'][:200]}"]
                         if match.get("curl_command") else []),
                    evidence_refs=[evidence_id],
                    remediation="Review matched template, validate exploitability, apply vendor fix.",
                    asset_keys=[f"webapp:{target_url}"],
                )
            elif severity == "MEDIUM":
                self.state.add_finding(
                    title=f"Nuclei [MEDIUM]: {match.get('name') or match.get('template_id')}",
                    severity="MEDIUM",
                    confidence="FIRM",
                    category="Vulnerability Scan",
                    description=f"Template {match.get('template_id')} matched {match.get('matched_at')}.",
                    evidence=[
                        f"Template: {match.get('template_id')}",
                        f"Matched: {match.get('matched_at')}",
                    ],
                    evidence_refs=[evidence_id],
                    remediation="Review and remediate according to template description.",
                    asset_keys=[f"webapp:{target_url}"],
                )

        # Batch LOW/INFO findings
        low_info = [m for m in unique_matches
                    if SEVERITY_MAP.get(m.get("severity", "INFO")) in ("LOW", "INFO")]
        if low_info:
            self.state.add_finding(
                title=f"Nuclei: {len(low_info)} Low/Info Matches",
                severity="LOW",
                confidence="FIRM",
                category="Vulnerability Scan",
                description=f"Nuclei found {len(low_info)} low/informational matches.",
                evidence=[
                    f"{m.get('template_id')}: {m.get('matched_at')}"
                    for m in low_info[:20]
                ],
                evidence_refs=[evidence_id],
                remediation="Review low/info findings for false positive triage.",
                asset_keys=[f"webapp:{target_url}"],
            )

        self.state.add_asset(
            "nuclei_scan",
            f"nuclei:{self.domain}",
            self.domain,
            confidence="CONFIRMED",
            sources=["nuclei"],
            attrs={
                "total_matches": len(unique_matches),
                "by_severity": finding_counts,
                "tags_used": first_pass_tags + cve_tags_used,
                "detected_tech": sorted(detected_tech),
            },
        )
        self.state.complete_module(self.id)
        self.log(
            f"nuclei: {len(unique_matches)} matches — "
            + " | ".join(f"{sev}:{cnt}" for sev, cnt in sorted(finding_counts.items()))
        )
        return "done"

    def _allow_full_cve_pass(self, target_url: str, webapp_assets: list[dict]) -> bool:
        nuclei_cfg = self.config.get("nuclei", {})
        if nuclei_cfg.get("full_cve") is False:
            return False
        if nuclei_cfg.get("full_cve_on_confirmed_apex", True) is False:
            return False
        for asset in webapp_assets:
            if asset.get("value") == target_url and asset.get("confidence") == "CONFIRMED":
                return True
        return False
