"""Stage 4: Structural validation of discovered secret candidates."""

import json

from core.validators import extract_secrets
from modules.base import BaseModule


class SecretValidation(BaseModule):
    id = "secret_validation"
    name = "Secret Validation"
    stage = 4
    detectability = "low"
    depends_on = ["js_analysis"]

    async def run(self) -> str:
        candidates = []

        for finding in self.state.findings.get("findings", []):
            text = " ".join([
                str(finding.get("title", "")),
                str(finding.get("description", "")),
                " ".join(map(str, finding.get("evidence", []))),
            ])
            for secret in extract_secrets(text):
                secret["source"] = finding.get("id", "")
                candidates.append(secret)

        for item in self.state.evidence.get("items", []):
            path = self.state.output_dir / item.get("path", "")
            if not path.exists():
                continue
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            for secret in extract_secrets(text[:200000]):
                secret["source"] = item.get("id", "")
                candidates.append(secret)

        unique = _dedupe(candidates)
        if not unique:
            self.state.skip_module(self.id, "no structurally valid secrets")
            return "skipped"

        evidence_id = self.state.add_evidence(
            self.id,
            "secret_validation",
            self.domain,
            {"secrets": unique, "live_checks": "not_performed"},
        )

        for item in unique:
            self.state.add_asset(
                "secret_candidate",
                f"secret:{item['type']}:{item['redacted']}",
                item["redacted"],
                confidence="FIRM",
                sources=[self.id],
                attrs=item,
            )

        self.state.add_finding(
            title=f"Structurally Valid Secret Candidates: {len(unique)}",
            severity="HIGH",
            confidence="FIRM",
            category="Credential Exposure",
            description=(
                "Discovered secret candidates passed structural validation. "
                "No live credential use was performed."
            ),
            evidence=[f"{item['type']}: {item['redacted']} ({item['source']})" for item in unique[:10]],
            evidence_refs=[evidence_id],
            remediation="Rotate matching credentials and remove them from public client-side or repository history.",
        )

        self.state.complete_module(self.id)
        self.log(f"Secret candidates validated structurally: {len(unique)}")
        return "done"


def _dedupe(items: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for item in items:
        key = json.dumps([item.get("type"), item.get("redacted")])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique
