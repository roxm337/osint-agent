"""Stage 5: Authorized SQL injection scanning with sqlmap."""

from modules.base import BaseModule
from tools.external import sqlmap_scan, tool_available


class SQLiScan(BaseModule):
    id = "sqli_scan"
    name = "SQL Injection Scan"
    stage = 5
    detectability = "high"
    depends_on = ["parameter_discovery"]
    requires_auth = True

    async def run(self) -> str:
        if not tool_available("sqlmap"):
            self.state.skip_module(self.id, "sqlmap not installed")
            return "skipped"

        urls = self._candidate_urls()
        if not urls:
            self.state.skip_module(self.id, "no parameterized URLs")
            return "skipped"

        evidence_refs = []
        total = []
        for url in urls[:10]:
            if not self.scope.check(url).allowed:
                continue
            result = await sqlmap_scan(url, timeout=900)
            total.extend(result.get("results", []))
            evidence_refs.append(
                self.state.add_evidence(
                    self.id,
                    "sqlmap",
                    url,
                    {
                        "target": url,
                        "results": result.get("results", []),
                        "exit_code": result.get("exit_code"),
                        "stderr": result.get("stderr", ""),
                    },
                )
            )

        for item in total:
            self.state.add_finding(
                title="SQLMap SQL Injection Candidate",
                severity="CRITICAL",
                confidence="FIRM",
                category="SQL Injection",
                description="sqlmap reported SQL injection evidence with conservative risk/level settings.",
                evidence=[str(item.get("evidence", ""))],
                evidence_refs=evidence_refs,
                asset_keys=[f"url:{item.get('url', '')}"],
                remediation="Validate manually and parameterize database queries.",
            )

        self.state.complete_module(self.id)
        self.log(f"SQL injection candidates: {len(total)}")
        return "done"

    def _candidate_urls(self) -> list[str]:
        urls = []
        for asset in self.state.get_assets_by_type("parameter"):
            url = str(asset.get("attrs", {}).get("url", "")).strip()
            param = str(asset.get("value", "")).strip()
            if url and param:
                separator = "&" if "?" in url else "?"
                candidate = f"{url}{separator}{param}=1"
                if candidate not in urls:
                    urls.append(candidate)
        return urls
