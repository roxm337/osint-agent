"""Stage 4: Structural validation of discovered secret candidates."""

import json

from core.validators import (
    analyze_jwt,
    extract_secrets,
    grade_secret_candidate,
    SECRET_EXAMPLE_MARKERS as _EXAMPLE_MARKERS,
)
from modules.base import BaseModule


def _jwt_payload(value: str) -> dict:
    """Payload claims without verifying (kept for backward compatibility)."""
    return analyze_jwt(value).get("claims", {})


def _grade(secret_type: str, value: str, validation: dict) -> tuple[str, str]:
    """Tier a candidate (kept for backward compatibility; see core)."""
    return grade_secret_candidate(secret_type, value, validation)


class SecretValidation(BaseModule):
    id = "secret_validation"
    name = "Secret Validation"
    stage = 4
    detectability = "low"
    depends_on = ["js_analysis"]

    async def run(self) -> str:
        candidates = []

        for finding in self.state.findings.get("findings", []):
            # Never re-scan our own output: the last run's finding text
            # contains the same redacted candidates, which would re-grade
            # forever and inflate the count every run.
            if finding.get("module_id") == self.id:
                continue
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
        for item in unique:
            full_value = item.pop("value", "")
            tier, reason = _grade(item["type"], full_value,
                                  item.get("validation", {}))
            item["tier"] = tier
            item["tier_reason"] = reason
        if not unique:
            self.state.skip_module(self.id, "no structurally valid secrets")
            return "skipped"

        plausible = [item for item in unique if item["tier"] == "plausible"]
        # Nothing here was used, so nothing is HIGH: a real-shaped token
        # is MEDIUM (rotate it), docs/test shapes are LOW (triage tail).
        severity = "MEDIUM" if plausible else "LOW"

        evidence_id = self.state.add_evidence(
            self.id,
            "secret_validation",
            self.domain,
            {"secrets": unique, "live_checks": "not_performed",
             "plausible": len(plausible), "weak": len(unique) - len(plausible)},
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
            severity=severity,
            confidence="FIRM",
            category="Credential Exposure",
            description=(
                f"{len(plausible)} plausible and {len(unique) - len(plausible)} "
                "weak (docs/test/expired) candidates passed structural "
                "validation. No live credential use was performed: plausible "
                "means real-shaped, not proven-working."
            ),
            evidence=[f"{item['type']}: {item['redacted']} "
                      f"[{item['tier']}: {item['tier_reason']}] "
                      f"({item['source']})" for item in unique[:15]],
            evidence_refs=[evidence_id],
            remediation="Rotate plausible credentials and remove them from public client-side or repository history.",
        )

        self.state.complete_module(self.id)
        self.log(f"Secret candidates: {len(plausible)} plausible, "
                 f"{len(unique) - len(plausible)} weak")
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
