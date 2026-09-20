"""Stage 5: Authorized open redirect checks."""

from modules.base import BaseModule
from tools.external import openredirex_scan, tool_available

REDIRECT_NAMES = ("redirect", "redir", "url", "next", "return", "continue", "dest", "destination")


class OpenRedirectScan(BaseModule):
    id = "open_redirect"
    name = "Open Redirect Scan"
    stage = 5
    detectability = "medium"
    depends_on = ["parameter_discovery"]
    requires_auth = True

    async def run(self) -> str:
        if not tool_available("openredirex"):
            self.state.skip_module(self.id, "openredirex not installed")
            return "skipped"

        urls = self._candidate_urls()
        if not urls:
            self.state.skip_module(self.id, "no redirect-like parameters")
            return "skipped"

        in_scope = [url for url in urls if self.scope.check(url).allowed]
        result = await openredirex_scan(in_scope[:50], timeout=300)
        findings = result.get("results", [])
        evidence_id = self.state.add_evidence(
            self.id,
            "openredirex",
            self.domain,
            {
                "targets": in_scope[:50],
                "results": findings,
                "exit_code": result.get("exit_code"),
                "stderr": result.get("stderr", ""),
            },
        )

        if findings:
            self.state.add_finding(
                title=f"Open Redirect Candidates: {len(findings)}",
                severity="MEDIUM",
                confidence="FIRM",
                category="Open Redirect",
                description="openredirex reported possible open redirect behavior.",
                evidence=findings[:15],
                evidence_refs=[evidence_id],
                remediation="Validate redirect destinations against a strict allowlist.",
            )

        self.state.complete_module(self.id)
        self.log(f"Open redirect candidates: {len(findings)}")
        return "done"

    def _candidate_urls(self) -> list[str]:
        urls = []
        for asset in self.state.get_assets_by_type("parameter"):
            name = str(asset.get("value", "")).lower()
            if not any(token in name for token in REDIRECT_NAMES):
                continue
            url = str(asset.get("attrs", {}).get("url", "")).strip()
            if url and url not in urls:
                urls.append(url)
        return urls
