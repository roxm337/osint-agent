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
        cookie, extra_headers = self._auth_args()
        cfg = self._cfg()
        escalate = cfg.get("escalate", True) is not False
        max_escalations = int(cfg.get("max_escalations", 3) or 3)

        evidence_refs = []
        total = []
        oast_urls = set()
        escalated = 0
        for url in urls[:10]:
            result = await sqlmap_scan(url, timeout=600,
                                       interactsh_url=interactsh_url,
                                       risk=1, level=1,
                                       cookie=cookie, headers=extra_headers)
            batch = result.get("results", []) or []
            # Escalation ladder, second rung only: risk/level 3 on points
            # where level 1 already found candidate evidence. Level 5 and
            # risk 4+ stay parked — their payload volume is a DoS-shaped
            # hammer for a marginal coverage gain.
            if batch and not result.get("oast") and escalate \
                    and escalated < max_escalations:
                escalated += 1
                self.log(f"  Escalating {url} to risk/level 3 "
                         f"({escalated}/{max_escalations})...")
                result = await sqlmap_scan(url, timeout=600,
                                           interactsh_url=interactsh_url,
                                           risk=3, level=3,
                                           cookie=cookie, headers=extra_headers)
                batch = result.get("results", []) or batch
            total.extend(batch)
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
            # from the URLs that stayed in-band. Unconfirmed stays HIGH:
            # CRITICAL is reserved for executed queries.
            confirmed = bool(item.get("url")) and item["url"] in oast_urls
            self.state.add_finding(
                title="SQLMap SQL Injection Candidate",
                severity="CRITICAL" if confirmed else "HIGH",
                confidence="CONFIRMED" if confirmed else "FIRM",
                category="SQL Injection",
                description=(
                    "sqlmap confirmed the injection out of band: the database "
                    "server issued a callback, which only happens if the "
                    "injected query executed."
                    if confirmed else
                    "sqlmap reported SQL injection evidence. The response was identical with and "
                    "without the payload, so this is not proof of execution."
                ),
                evidence=[str(item.get("evidence", ""))],
                evidence_refs=evidence_refs,
                asset_keys=[f"url:{item.get('url', '')}"],
                remediation="Validate manually and parameterize database queries.",
                verified=confirmed,
                verification={"method": "sqlmap_oast_callback",
                              "url": item.get("url", "")} if confirmed else {},
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

    def _auth_args(self) -> tuple:
        """Authorized session for sqlmap, same shape as the XSS browser pass."""
        auth = self.config.get("auth", {}) or {}
        headers = {
            str(k): str(v)
            for k, v in (auth.get("headers") or {}).items()
            if k and v is not None and str(v) != "" and str(k).lower() != "cookie"
        }
        bearer = auth.get("bearer_token") or auth.get("token")
        if bearer and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {bearer}"
        cookie = ""
        raw_headers = auth.get("headers") if isinstance(auth.get("headers"), dict) else {}
        if raw_headers.get("Cookie"):
            cookie = str(raw_headers["Cookie"])
        elif auth.get("cookie"):
            cookie = str(auth.get("cookie"))
        extra = "\n".join(f"{k}: {v}" for k, v in headers.items()
                          if k.lower() != "authorization")
        if bearer:
            extra = (extra + "\n" if extra else "") + f"Authorization: Bearer {bearer}"
        return cookie, extra

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
