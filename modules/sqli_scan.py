"""Stage 5: Authorized SQL injection scanning with sqlmap."""

from modules.base import BaseModule
from tools.external import sqlmap_scan, tool_available


class SQLiScan(BaseModule):
    id = "sqli_scan"
    name = "SQL Injection Scan"
    stage = 5
    detectability = "high"
    depends_on = ["parameter_discovery"]
    active = True

    async def run(self) -> str:
        if not tool_available("sqlmap"):
            self.state.skip_module(self.id, "sqlmap not installed")
            return "skipped"

        urls = self._candidate_urls()
        if not urls:
            self.state.skip_module(self.id, "no parameterized URLs")
            return "skipped"

        # sqlmap can only prove a blind injection out of band, and it needs a
        # full interactsh-compatible server (not just a callback domain) to do
        # it. Without one it stays in-band and every hit below is FIRM.
        interactsh_url = self._interactsh_url()

        evidence_refs = []
        total = []
        oast_urls = set()
        for url in urls[:10]:
            result = await sqlmap_scan(url, timeout=900,
                                       interactsh_url=interactsh_url)
            total.extend(result.get("results", []))
            if result.get("oast"):
                oast_urls.add(url)
            evidence_refs.append(
                self.state.add_evidence(
                    self.id,
                    "sqlmap",
                    url,
                    {
                        "target": url,
                        "results": result.get("results", []),
                        "exit_code": result.get("exit_code"),
                        "oast": bool(result.get("oast")),
                        "interactsh_url": interactsh_url,
                        "stderr": result.get("stderr", ""),
                    },
                )
            )

        for item in total:
            # A callback proves the injection that triggered it and nothing
            # else, so a per-request OAST flag must not promote the findings
            # from the URLs that stayed in-band.
            confirmed = bool(item.get("url")) and item["url"] in oast_urls
            self.state.add_finding(
                title="SQLMap SQL Injection Candidate",
                severity="CRITICAL",
                confidence="CONFIRMED" if confirmed else "FIRM",
                category="SQL Injection",
                description=(
                    "sqlmap confirmed the injection out of band: the database "
                    "server issued a callback, which only happens if the "
                    "injected query executed."
                    if confirmed else
                    "sqlmap reported SQL injection evidence with conservative "
                    "risk/level settings. The response was identical with and "
                    "without the payload, so this is not proof of execution."
                ),
                evidence=[str(item.get("evidence", ""))],
                evidence_refs=evidence_refs,
                asset_keys=[f"url:{item.get('url', '')}"],
                remediation="Validate manually and parameterize database queries.",
            )

        self.state.complete_module(self.id)
        self.log(
            f"SQL injection candidates: {len(total)}"
            f" ({len(oast_urls)} out-of-band confirmed)"
        )
        return "done"

    def _interactsh_url(self) -> str:
        """The interactsh server for sqlmap, or "" to stay in-band.

        An empty `server_url` is already the answer we want when only a callback
        domain is configured: sqlmap needs a full interactsh server to poll,
        not just a hostname to point at.
        """
        if not self._cfg().get("oast", True):
            return ""
        client = self.oob()
        return client.server_url if client else ""

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}

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
