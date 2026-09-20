"""Stage 6: Generate submittable per-finding bounty reports."""

from pathlib import Path

from core.scoring import score_label
from modules.base import BaseModule


class BountySubmission(BaseModule):
    id = "bounty_submission"
    name = "Bounty Submission Export"
    stage = 6
    detectability = "low"
    depends_on = ["risk_prioritization"]

    async def run(self) -> str:
        findings = [
            finding for finding in self.state.findings.get("findings", [])
            if str(finding.get("severity", "")).upper() not in {"INFO"}
        ]
        if not findings:
            self.state.skip_module(self.id, "no submittable findings")
            return "skipped"

        output_dir = self.state.output_dir / "submissions"
        output_dir.mkdir(parents=True, exist_ok=True)
        written = []
        for finding in findings:
            path = output_dir / f"{finding.get('id', 'finding')}_{_slug(finding.get('title', 'finding'))}.md"
            path.write_text(_render_submission(finding, self.state.evidence.get("items", [])))
            written.append(str(path.relative_to(self.state.output_dir)))

        index_path = output_dir / "INDEX.md"
        index_path.write_text(_render_index(findings, written))
        evidence_id = self.state.add_evidence(
            self.id,
            "bounty_submissions",
            self.domain,
            {"count": len(written), "files": written, "index": str(index_path.relative_to(self.state.output_dir))},
        )
        self.state.add_asset(
            "bounty_submission",
            f"submission:{self.domain}",
            self.domain,
            confidence="CONFIRMED",
            sources=[self.id],
            attrs={"files": written, "evidence_ref": evidence_id},
        )
        self.state.complete_module(self.id)
        self.log(f"Bounty submissions: {len(written)}")
        return "done"


def _render_submission(finding: dict, evidence_items: list[dict]) -> str:
    evidence_by_id = {item.get("id"): item for item in evidence_items}
    score = int(finding.get("risk_score") or 0)
    lines = [
        f"# {finding.get('title', 'Untitled Finding')}",
        "",
        "## Summary",
        "",
        finding.get("description", ""),
        "",
        "## Severity",
        "",
        f"- Severity: {finding.get('severity', 'INFO')}",
        f"- Priority: {finding.get('priority', 'P4')}",
        f"- Risk Score: {score}/100 ({score_label(score)})",
        f"- Confidence: {finding.get('confidence', '')}",
        f"- Category: {finding.get('category', '')}",
        "",
        "## Affected Assets",
        "",
    ]
    for asset in finding.get("asset_keys", []) or ["Not specified"]:
        lines.append(f"- `{asset}`")
    lines.extend(["", "## Evidence", ""])
    if finding.get("evidence"):
        for item in finding["evidence"]:
            lines.append(f"- {item}")
    else:
        lines.append("- See evidence files below.")
    if finding.get("evidence_refs"):
        lines.extend(["", "## Evidence Files", ""])
        for ref in finding["evidence_refs"]:
            item = evidence_by_id.get(ref, {})
            lines.append(f"- `{item.get('path', ref)}`")
    lines.extend([
        "",
        "## Impact",
        "",
        _impact_text(finding),
        "",
        "## Recommended Remediation",
        "",
        finding.get("remediation", "Remediate the affected component and retest."),
        "",
        "## Validation Notes",
        "",
        "All reproduction steps should be performed only within authorized program scope.",
        "",
    ])
    return "\n".join(lines)


def _render_index(findings: list[dict], files: list[str]) -> str:
    lines = ["# Bounty Submission Index", "", "| Finding | Severity | Score | File |", "|---|---|---:|---|"]
    for finding, path in zip(findings, files):
        lines.append(
            f"| {finding.get('id', '')}: {finding.get('title', '')} | "
            f"{finding.get('severity', '')} | {finding.get('risk_score', 0)} | `{path}` |"
        )
    lines.append("")
    return "\n".join(lines)


def _impact_text(finding: dict) -> str:
    category = str(finding.get("category", "")).lower()
    if "credential" in category:
        return "An attacker may gain access to credentials or tokens and pivot into related systems."
    if "xss" in category:
        return "An attacker may execute JavaScript in a victim browser and perform actions as that user."
    if "sql" in category:
        return "An attacker may access, modify, or delete database-backed application data."
    if "source" in category:
        return "An attacker may reconstruct source code and discover implementation flaws or credentials."
    if "takeover" in category:
        return "An attacker may claim an abandoned resource and serve attacker-controlled content."
    return "The issue increases attack surface or weakens the target's security posture."


def _slug(value: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value))
    return "-".join(part for part in slug.split("-") if part)[:80] or "finding"
