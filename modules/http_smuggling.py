"""Stage 5: Authorized HTTP request smuggling checks."""

from modules.base import BaseModule
from tools.external import smuggler_scan, tool_available


class HTTPSmuggling(BaseModule):
    id = "http_smuggling"
    name = "HTTP Smuggling Scan"
    stage = 5
    detectability = "high"
    depends_on = ["tech_detection"]
    requires_auth = True

    async def run(self) -> str:
        if not tool_available("smuggler"):
            self.state.skip_module(self.id, "smuggler not installed")
            return "skipped"

        targets = self._targets()
        if not targets:
            targets = [f"https://{self.domain}"]

        findings = []
        evidence_refs = []
        for target in targets[:10]:
            if not self.scope.check(target).allowed:
                continue
            result = await smuggler_scan(target, timeout=300)
            findings.extend(result.get("results", []))
            evidence_refs.append(
                self.state.add_evidence(
                    self.id,
                    "smuggler",
                    target,
                    {
                        "results": result.get("results", []),
                        "exit_code": result.get("exit_code"),
                        "stderr": result.get("stderr", ""),
                    },
                )
            )

        if findings:
            self.state.add_finding(
                title=f"HTTP Smuggling Candidates: {len(findings)}",
                severity="HIGH",
                confidence="FIRM",
                category="HTTP Request Smuggling",
                description="smuggler reported potential request smuggling behavior.",
                evidence=findings[:15],
                evidence_refs=evidence_refs,
                remediation="Validate with controlled tests and normalize front-end/back-end HTTP parsing.",
            )

        self.state.complete_module(self.id)
        self.log(f"HTTP smuggling candidates: {len(findings)}")
        return "done"

    def _targets(self) -> list[str]:
        targets = []
        for asset_type in ("webapp", "url"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "")).strip()
                if value.startswith(("http://", "https://")) and value not in targets:
                    targets.append(value)
        return targets
