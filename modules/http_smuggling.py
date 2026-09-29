"""Stage 5: HTTP request smuggling, graded as what it actually is.

This module does not claim to confirm anything, and that is the point of the
rewrite. Smuggling is a disagreement between a front-end proxy and a back-end
server about where one request ends and the next begins. Reproducing that
needs a real two-hop chain, so there is no local fixture that would honestly
stand in for it — unlike CORS or open redirect, which are decidable from a
single response. Anything this module emits therefore stays TENTATIVE until a
person has seen the desync.

That is also the reason the previous version was wrong in a way that mattered:
it forwarded smuggler's stdout to a HIGH/FIRM finding. smuggler prints
"potential" and "vulnerable" on the same kind of line, and a fuzzer that
desynchronises a proxy by accident has still told you nothing about whether a
request can be smuggled. HIGH/FIRM on that basis is a claim nobody can
defend, and it is the kind of finding that costs a triager an afternoon.

The tool output is still recorded in full as evidence, so the work is not
thrown away — it is just labelled honestly.
"""

from modules.base import BaseModule
from tools.external import smuggler_scan, tool_available


class HTTPSmuggling(BaseModule):
    id = "http_smuggling"
    name = "HTTP Smuggling Scan"
    stage = 5
    detectability = "high"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        cfg = self._cfg()
        if cfg.get("enabled", True) is False:
            self.state.skip_module(self.id, "disabled in config")
            return "skipped"

        targets = self._targets()
        if not targets:
            targets = [f"https://{self.domain}"]

        if not tool_available("smuggler"):
            self.state.skip_module(self.id, "smuggler not installed")
            return "skipped"

        limit = int(cfg.get("max_targets", 10) or 10)
        reported = 0
        for target in targets[:limit]:
            result = await smuggler_scan(target, timeout=300)
            hits = result.get("results", [])
            evidence_id = self.state.add_evidence(
                self.id, "smuggler", target,
                {"results": hits, "stdout": result.get("stdout", ""),
                 "exit_code": result.get("exit_code"),
                 "stderr": result.get("stderr", "")},
            )
            if hits:
                reported += len(hits)
                self.state.add_finding(
                    title=f"HTTP smuggling candidate: {target}",
                    # Unconfirmed. The impact if real is severe, but the tool
                    # has not shown a desync that survives scrutiny.
                    severity="MEDIUM",
                    confidence="TENTATIVE",
                    category="HTTP Request Smuggling",
                    description=(
                        f"smuggler returned {len(hits)} candidate line(s) for "
                        f"{target}. This is a fuzzer's output, not a confirmed "
                        "desync: a request-smuggling bug needs a front-end and "
                        "a back-end server that disagree on request boundaries, "
                        "and that has not been shown here. Reproduce it with a "
                        "controlled two-request sequence before treating it as "
                        "a finding — the impact if genuine is high, so it is "
                        "worth the hour."
                    ),
                    evidence=[str(hit) for hit in hits[:15]],
                    evidence_refs=[evidence_id],
                    remediation=(
                        "Normalise HTTP parsing between front end and back end: "
                        "reject ambiguous Content-Length/Transfer-Encoding "
                        "combinations, and use a single parser with identical "
                        "rules on both hops."
                    ),
                    verified=False,
                )

        self.state.complete_module(self.id)
        self.log(f"HTTP smuggling candidates (unconfirmed): {reported}")
        return "done"

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}

    def _targets(self) -> list[str]:
        targets = []
        for asset_type in ("webapp", "url"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "")).strip()
                if value.startswith(("http://", "https://")) and value not in targets:
                    targets.append(value)
        return targets
