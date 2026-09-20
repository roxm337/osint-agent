"""Stage 4: Authorized content discovery via ffuf."""

import json
from pathlib import Path

from modules.base import BaseModule
from tools.external import ffuf, parse_ffuf_json, tool_available


INTERESTING_STATUSES = {200, 204, 301, 302, 307, 308, 401, 403}


def classify_content_hit(hit: dict) -> str:
    status = int(hit.get("status") or 0)
    url = str(hit.get("url", ""))
    if status in (401, 403):
        return "protected"
    if any(token in url.lower() for token in ["admin", "backup", "debug", "config"]):
        return "interesting"
    return "discovered"


class ContentDiscovery(BaseModule):
    id = "content_discovery"
    name = "Content Discovery"
    stage = 5
    detectability = "high"
    depends_on = ["tech_detection"]
    requires_auth = True

    async def run(self) -> str:
        self.log("Running authorized ffuf content discovery...")
        if not tool_available("ffuf"):
            self.state.skip_module(self.id, "ffuf not installed")
            return "skipped"

        base_url = f"https://{self.domain}"
        if not self.scope.check(base_url).allowed:
            self.state.block_module(self.id, "target outside scope")
            return "blocked"

        words = self.config.get("wordlists", {}).get("content_discovery", [])
        if not words:
            self.state.skip_module(self.id, "no content discovery wordlist")
            return "skipped"

        run_dir = self.state.state_dir / "tool-output"
        run_dir.mkdir(exist_ok=True)
        wordlist_path = run_dir / "ffuf-content.txt"
        output_path = run_dir / "ffuf-content.json"
        wordlist_path.write_text("\n".join(w.strip("/") for w in words if w) + "\n")

        result = await ffuf(
            f"{base_url}/FUZZ",
            str(wordlist_path),
            str(output_path),
            rate=self.config.get("rate_limits", {}).get("scan", {}).get("per_minute", 10),
            timeout=240,
        )
        if not result.get("available", True):
            self.state.skip_module(self.id, "ffuf not installed")
            return "skipped"

        output_text = output_path.read_text() if output_path.exists() else "{}"
        hits = [
            hit for hit in parse_ffuf_json(output_text)
            if int(hit.get("status") or 0) in INTERESTING_STATUSES
        ]
        evidence_id = self.state.add_evidence(
            self.id,
            "ffuf",
            base_url,
            {
                "command": "ffuf",
                "url_template": f"{base_url}/FUZZ",
                "word_count": len(words),
                "exit_code": result.get("exit_code"),
                "stderr": result.get("stderr", ""),
                "results": hits,
            },
        )

        for hit in hits:
            category = classify_content_hit(hit)
            self.state.add_asset(
                "web_path",
                f"web_path:{hit['url']}",
                hit["url"],
                confidence="CONFIRMED",
                sources=["ffuf"],
                attrs={**hit, "category": category},
            )

        interesting = [hit for hit in hits if classify_content_hit(hit) != "discovered"]
        if interesting:
            self.state.add_finding(
                title=f"Interesting Web Paths Discovered",
                severity="MEDIUM",
                confidence="CONFIRMED",
                category="Content Discovery",
                description=(
                    f"ffuf discovered {len(interesting)} protected or sensitive-looking "
                    f"paths on {self.domain}."
                ),
                evidence=[
                    f"{hit['status']} {hit['url']}"
                    for hit in interesting[:15]
                ],
                evidence_refs=[evidence_id],
                remediation=(
                    "Review discovered paths for intended exposure, authentication, "
                    "and sensitive content leakage."
                ),
            )

        self.state.add_asset(
            "content_discovery",
            f"content_discovery:{self.domain}",
            self.domain,
            confidence="CONFIRMED",
            sources=["ffuf"],
            attrs={"hits": len(hits), "output": str(output_path)},
        )
        self.state.complete_module(self.id)
        self.log(f"ffuf hits: {len(hits)}")
        return "done"
