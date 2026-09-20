"""Stage 5: Authorized CMS-specific scanner orchestration."""

from modules.base import BaseModule
from tools.external import (
    cmseek_scan,
    droopescan_scan,
    joomscan_scan,
    tool_available,
    wpscan,
)


class CMSDeepScan(BaseModule):
    id = "cms_deep_scan"
    name = "CMS Deep Scan"
    stage = 5
    detectability = "high"
    depends_on = ["tech_detection"]
    requires_auth = True

    async def run(self) -> str:
        targets = self._targets()
        if not targets:
            targets = [(f"https://{self.domain}", "")]

        if not any(tool_available(name) for name in ("wpscan", "joomscan", "droopescan", "cmseek")):
            self.state.skip_module(self.id, "CMS scanners not installed")
            return "skipped"

        evidence_refs = []
        findings = []
        for target, cms in targets[:5]:
            if not self.scope.check(target).allowed:
                continue
            cms_lower = cms.lower()
            if "wordpress" in cms_lower and tool_available("wpscan"):
                result = await wpscan(target, timeout=300)
                findings.extend(_wpscan_findings(result))
                evidence_refs.append(self.state.add_evidence(self.id, "wpscan", target, result))
            if "joomla" in cms_lower and tool_available("joomscan"):
                result = await joomscan_scan(target, timeout=300)
                findings.extend(result.get("results", []))
                evidence_refs.append(self.state.add_evidence(self.id, "joomscan", target, result))
            if any(name in cms_lower for name in ("drupal", "joomla", "wordpress")) and tool_available("droopescan"):
                cms_name = "drupal" if "drupal" in cms_lower else "joomla" if "joomla" in cms_lower else "wordpress"
                result = await droopescan_scan(target, cms=cms_name, timeout=300)
                evidence_refs.append(self.state.add_evidence(self.id, "droopescan", target, result))
            if tool_available("cmseek"):
                result = await cmseek_scan(target, timeout=300)
                findings.extend(result.get("results", []))
                evidence_refs.append(self.state.add_evidence(self.id, "cmseek", target, result))

        if findings:
            self.state.add_finding(
                title=f"CMS Deep Scan Findings: {len(findings)}",
                severity="HIGH",
                confidence="FIRM",
                category="CMS Vulnerability",
                description="CMS-specific scanners reported version or vulnerability signals.",
                evidence=[str(item.get("evidence", item)) for item in findings[:15]],
                evidence_refs=evidence_refs,
                remediation="Validate scanner output, update vulnerable CMS core/plugins/themes, and remove unused components.",
            )

        self.state.complete_module(self.id)
        self.log(f"CMS deep scan findings: {len(findings)}")
        return "done"

    def _targets(self) -> list[tuple[str, str]]:
        targets = []
        for asset in self.state.get_assets_by_type("webapp"):
            value = str(asset.get("value", "")).strip()
            attrs = asset.get("attrs", {})
            cms = str(attrs.get("cms", ""))
            if value.startswith(("http://", "https://")):
                targets.append((value, cms))
        return targets


def _wpscan_findings(result: dict) -> list[dict]:
    data = result.get("results", {}) if isinstance(result, dict) else {}
    findings = []
    for section in ("version", "main_theme"):
        item = data.get(section, {})
        if isinstance(item, dict):
            for vuln in item.get("vulnerabilities", []) or []:
                findings.append({"evidence": vuln.get("title", str(vuln))})
    for plugin, item in (data.get("plugins", {}) or {}).items():
        for vuln in item.get("vulnerabilities", []) or []:
            findings.append({"evidence": f"{plugin}: {vuln.get('title', str(vuln))}"})
    return findings
