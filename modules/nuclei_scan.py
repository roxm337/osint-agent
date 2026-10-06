"""Stage 4: Nuclei vulnerability scan with technology-targeted templates."""

import time

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

# Highest-signal, fastest tags first. A run that is cut short by the module
# deadline keeps the credential/exposure batches instead of dying inside one
# giant invocation with zero findings to show for it.
TAG_BATCHES = [
    ["token-spray", "default-login"],
    ["osint"],
    ["exposure"],
    ["misconfiguration"],
]

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
    active = True

    async def run(self) -> str:
        self.log("Running authorized nuclei scan...")
        if not tool_available("nuclei"):
            self.state.skip_module(self.id, "nuclei not installed")
            return "skipped"

        target_url = self.base_url
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
        tech_tags = []
        for tech, tags in TECH_TAG_MAP.items():
            if any(tech.lower() in dt.lower() for dt in detected_tech):
                self.log(f"  Adding tags for {tech}: {tags}")
                tech_tags.extend(tags)
        tech_tags = sorted(set(tech_tags))

        groups = [list(batch) for batch in TAG_BATCHES]
        if tech_tags:
            groups.append(tech_tags)

        # Time-box: the orchestrator kills the module at its deadline and
        # anything buffered in memory dies with it, so findings land per
        # batch and the run stops while there is still time to write them.
        try:
            deadline = float(self.config.get("module_timeout", 300) or 300)
        except (TypeError, ValueError):
            deadline = 300.0
        nuclei_cfg = self.config.get("nuclei", {})
        max_seconds = nuclei_cfg.get("max_seconds")
        try:
            max_seconds = float(max_seconds) if max_seconds else deadline - 60.0
        except (TypeError, ValueError):
            max_seconds = deadline - 60.0
        batch_cap = nuclei_cfg.get("batch_seconds", 150)
        try:
            batch_cap = float(batch_cap or 150)
        except (TypeError, ValueError):
            batch_cap = 150.0
        started = time.monotonic()
        stop_at = started + max(60.0, max_seconds)

        seen = set()
        all_matches = []
        low_info_all = []
        finding_counts = {}
        tags_used = []
        for position, group in enumerate(groups):
            remaining = stop_at - time.monotonic()
            batches_left = len(groups) - position
            if remaining < 40:
                self.log(f"  Time-box hit with {batches_left} tag group(s) "
                         f"unrun ({remaining:.0f}s left) — keeping what landed")
                break
            batch_timeout = max(40.0, min(batch_cap, (remaining - 20.0) / batches_left))
            self.log(f"  Batch {position + 1}/{len(groups)} tags "
                     f"{','.join(group)} (timeout {batch_timeout:.0f}s)...")
            try:
                result = await nuclei_scan(
                    target_url,
                    rate_limit=rate_limit,
                    timeout=int(batch_timeout),
                    tags=group,
                    severity=["low", "medium", "high", "critical"],
                )
            except Exception as exc:
                self.log(f"  Batch {','.join(group)} raised: {exc} — continuing")
                continue
            batch_matches = result.get("results", []) or []
            if result.get("error") == "timeout" and not batch_matches:
                self.log(f"  Batch {','.join(group)} timed out with no "
                         "matches — continuing with the next batch")
                continue
            fresh = []
            for match in batch_matches:
                key = (match.get("template_id", ""), match.get("matched_at", ""))
                if key not in seen:
                    seen.add(key)
                    fresh.append(match)
            if not fresh:
                continue
            tags_used.extend(group)
            all_matches.extend(fresh)
            low_info_all.extend(
                await self._record_matches(fresh, finding_counts, target_url,
                                           group, detected_tech, rate_limit))

        if self._allow_full_cve_pass(target_url, webapp_assets):
            remaining = stop_at - time.monotonic()
            if remaining > 150:
                cve_timeout = int(min(600, remaining - 45))
                self.log(f"  Confirmed apex CVE scan enabled "
                         f"(timeout {cve_timeout}s)")
                try:
                    result = await nuclei_scan(
                        target_url,
                        rate_limit=rate_limit,
                        timeout=cve_timeout,
                        tags=["cve"],
                        severity=["medium", "high", "critical"],
                    )
                except Exception as exc:
                    self.log(f"  CVE batch raised: {exc}")
                    result = {"results": []}
                cve_matches = result.get("results", []) or []
                fresh = []
                for match in cve_matches:
                    key = (match.get("template_id", ""), match.get("matched_at", ""))
                    if key not in seen:
                        seen.add(key)
                        fresh.append(match)
                if fresh:
                    tags_used.append("cve")
                    all_matches.extend(fresh)
                    low_info_all.extend(
                        await self._record_matches(fresh, finding_counts,
                                                   target_url, ["cve"],
                                                   detected_tech, rate_limit))
            else:
                self.log(f"  Skipping CVE pass: only {remaining:.0f}s left in "
                         "the time-box")

        # One consolidated LOW/INFO appendix, not one per batch: per-batch
        # summaries share a title and would otherwise merge with a stale
        # count while the evidence kept growing underneath it.
        if low_info_all:
            summary_evidence = self.state.add_evidence(
                self.id, "nuclei", target_url,
                {"target": target_url, "tags_used": sorted(set(tags_used)),
                 "low_info_matches": len(low_info_all)},
            )
            self.state.add_finding(
                title=f"Nuclei: {len(low_info_all)} Low/Info Matches",
                severity="LOW",
                confidence="FIRM",
                category="Vulnerability Scan",
                description=(f"Nuclei found {len(low_info_all)} "
                             "low/informational matches."),
                evidence=[
                    f"{m.get('template_id')}: {m.get('matched_at')}"
                    for m in low_info_all[:30]
                ],
                evidence_refs=[summary_evidence],
                remediation="Review low/info findings for false positive triage.",
                asset_keys=[f"webapp:{target_url}"],
            )
            finding_counts["LOW"] = finding_counts.get("LOW", 0) + 1

        self.state.add_asset(
            "nuclei_scan",
            f"nuclei:{self.domain}",
            self.domain,
            confidence="CONFIRMED",
            sources=["nuclei"],
            attrs={
                "total_matches": len(all_matches),
                "by_severity": finding_counts,
                "tags_used": sorted(set(tags_used)),
                "detected_tech": sorted(detected_tech),
            },
        )
        self.state.complete_module(self.id)
        self.log(
            f"nuclei: {len(all_matches)} matches — "
            + " | ".join(f"{sev}:{cnt}" for sev, cnt in sorted(finding_counts.items()))
        )
        return "done"

    async def _record_matches(self, matches: list, finding_counts: dict,
                                target_url: str, tags: list, detected_tech: set,
                                rate_limit: int) -> list:
        """Persist one batch of matches as evidence + findings immediately.

        Findings land per batch rather than at the end of the run, so a
        module deadline kills at most the in-flight batch instead of the
        whole scan. Returns the batch's LOW/INFO matches: those accumulate
        into a single appendix at the end of the run.
        """
        evidence_id = self.state.add_evidence(
            self.id,
            "nuclei",
            target_url,
            {
                "target": target_url,
                "tags_used": list(tags),
                "detected_tech": sorted(detected_tech),
                "total_matches": len(matches),
            },
        )

        validated = 0
        for match in matches:
            severity = SEVERITY_MAP.get(str(match.get("severity", "INFO")).upper(), "INFO")
            finding_counts[severity] = finding_counts.get(severity, 0) + 1

            # Create individual findings for HIGH/CRITICAL
            if severity in ("HIGH", "CRITICAL"):
                confirmed, validation_note = (False, "")
                if validated < 5:
                    validated += 1
                    confirmed, validation_note = await self._revalidate_match(
                        match, rate_limit)
                self.state.add_finding(
                    title=f"Nuclei [{severity}]: {match.get('name') or match.get('template_id')}",
                    severity=severity,
                    confidence="CONFIRMED" if confirmed else "FIRM",
                    category="Vulnerability Scan",
                    description=(
                        f"Nuclei template {match.get('template_id')} matched at "
                        f"{match.get('matched_at')}"
                        f"{' twice independently' if confirmed else ''}."
                    ),
                    evidence=[
                        f"Template: {match.get('template_id')}",
                        f"Matched: {match.get('matched_at')}",
                        f"Type: {match.get('type', 'http')}",
                        f"Revalidation: {validation_note}",
                    ] + ([f"Curl: {match['curl_command'][:200]}"]
                         if match.get("curl_command") else []),
                    evidence_refs=[evidence_id],
                    remediation="Review matched template, validate exploitability, apply vendor fix.",
                    asset_keys=[f"webapp:{target_url}"],
                    verified=confirmed,
                    verification={"method": "nuclei_template_rerun",
                                  "template": match.get("template_id", ""),
                                  "url": match.get("matched_at", "")}
                    if confirmed else {},
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

        # LOW/INFO matches accumulate for one end-of-run appendix.
        return [m for m in matches
                if SEVERITY_MAP.get(str(m.get("severity", "INFO")).upper())
                in ("LOW", "INFO")]

    async def _revalidate_match(self, match: dict, rate_limit: int
                                ) -> tuple:
        """Re-run one template against one URL: same template-id firing
        twice independently is confirmation; anything else stays FIRM
        with the reason recorded. Capped by the caller (5 per batch)."""
        template_id = str(match.get("template_id", "") or "")
        target = str(match.get("matched_at", "") or "")
        if not template_id or not target:
            return False, "missing template or target, skipped"
        try:
            result = await nuclei_scan(
                target,
                rate_limit=rate_limit,
                timeout=120,
                templates=template_id,
                severity=[str(match.get("severity", "high")).lower()],
            )
        except Exception as exc:
            return False, f"re-run raised: {exc}"
        for rerun in result.get("results", []) or []:
            if str(rerun.get("template_id", "")) == template_id:
                return True, (f"template {template_id} matched again at "
                               f"{rerun.get('matched_at', target)}")
        return False, (f"template {template_id} did not re-fire "
                       f"({result.get('error') or 'no match'})")

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
