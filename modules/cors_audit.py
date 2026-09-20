"""Stage 5: Authorized CORS misconfiguration checks."""

from modules.base import BaseModule
from tools.external import corsy_scan, tool_available


class CORSAudit(BaseModule):
    id = "cors_audit"
    name = "CORS Audit"
    stage = 5
    detectability = "medium"
    depends_on = ["tech_detection"]
    requires_auth = True

    async def run(self) -> str:
        if not tool_available("corsy"):
            self.state.skip_module(self.id, "corsy not installed")
            return "skipped"

        targets = self._targets()
        if not targets:
            targets = [f"https://{self.domain}"]

        findings = []
        evidence_refs = []
        for target in targets[:20]:
            if not self.scope.check(target).allowed:
                continue
            result = await corsy_scan(target, timeout=180)
            results = result.get("results", [])
            findings.extend(results)
            evidence_refs.append(
                self.state.add_evidence(
                    self.id,
                    "corsy",
                    target,
                    {
                        "results": results,
                        "exit_code": result.get("exit_code"),
                        "stderr": result.get("stderr", ""),
                    },
                )
            )

        if findings:
            self.state.add_finding(
                title=f"CORS Misconfiguration Candidates: {len(findings)}",
                severity="MEDIUM",
                confidence="FIRM",
                category="CORS",
                description="Corsy reported permissive or risky CORS behavior.",
                evidence=[str(item) for item in findings[:10]],
                evidence_refs=evidence_refs,
                remediation="Restrict allowed origins and avoid credentialed wildcard trust.",
            )

        self.state.complete_module(self.id)
        self.log(f"CORS candidates: {len(findings)}")
        return "done"

    def _targets(self) -> list[str]:
        targets = []
        for asset_type in ("webapp", "url"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "")).strip()
                if value.startswith(("http://", "https://")) and value not in targets:
                    targets.append(value)
        return targets
