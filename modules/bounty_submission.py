"""Stage 6: Generate submittable per-finding bounty reports."""

from pathlib import Path

from core.scoring import score_label
from modules.base import BaseModule


def _is_ready(finding: dict) -> bool:
    """Submittable means proven, not just scored.

    CONFIRMED confidence or an explicit verified flag. Everything else
    above INFO goes to the validation queue instead of a bounty draft —
    submitting FIRM-only scanner output is how programs get noise.
    """
    if str(finding.get("severity", "")).upper() == "INFO":
        return False
    if finding.get("verified"):
        return True
    return str(finding.get("confidence", "")).upper() == "CONFIRMED"


class BountySubmission(BaseModule):
    id = "bounty_submission"
    name = "Bounty Submission Export"
    stage = 6
    detectability = "low"
    depends_on = ["risk_prioritization"]

    async def run(self) -> str:
        candidates = [
            finding for finding in self.state.findings.get("findings", [])
            if str(finding.get("severity", "")).upper() not in {"INFO"}
        ]
        if not candidates:
            self.state.skip_module(self.id, "no submittable findings")
            return "skipped"

        ready = [f for f in candidates if _is_ready(f)]
        queued = [f for f in candidates if not _is_ready(f)]

        output_dir = self.state.output_dir / "submissions"
        output_dir.mkdir(parents=True, exist_ok=True)
        queue_dir = output_dir / "needs-validation"
        if queued:
            queue_dir.mkdir(parents=True, exist_ok=True)
        written = []
        for finding in ready:
            path = output_dir / f"{finding.get('id', 'finding')}_{_slug(finding.get('title', 'finding'))}.md"
            path.write_text(_render_submission(finding, self.state.evidence.get("items", [])))
            written.append(str(path.relative_to(self.state.output_dir)))
        queued_files = []
        for finding in queued:
            path = queue_dir / f"{finding.get('id', 'finding')}_{_slug(finding.get('title', 'finding'))}.md"
            path.write_text(_render_submission(finding, self.state.evidence.get("items", [])))
            queued_files.append(str(path.relative_to(self.state.output_dir)))

        index_path = output_dir / "INDEX.md"
        index_path.write_text(_render_index(ready, written, queued, queued_files))
        evidence_id = self.state.add_evidence(
            self.id,
            "bounty_submissions",
            self.domain,
            {"ready": len(written), "files": written,
             "queued_for_validation": len(queued_files),
             "queued_files": queued_files,
             "index": str(index_path.relative_to(self.state.output_dir))},
        )
        self.state.add_asset(
            "bounty_submission",
            f"submission:{self.domain}",
            self.domain,
            confidence="CONFIRMED",
            sources=[self.id],
            attrs={"files": written, "queued": queued_files,
                   "evidence_ref": evidence_id},
        )
        self.state.complete_module(self.id)
        self.log(f"Bounty submissions: {len(written)} ready, "
                 f"{len(queued_files)} queued for validation")
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
        *(_reproduce_block(finding)),
        "## Validation Notes",
        "",
        "All reproduction steps should be performed only within authorized program scope.",
        "",
    ])
    return "\n".join(lines)


def _reproduce_block(finding: dict) -> list[str]:
    """Exact commands that re-demonstrate the finding, not prose about it.

    Read-only by construction: plain GETs, sqlmap/dalfox in safe modes,
    and the reserved .invalid probe host for redirects. A finding whose
    proof cannot be re-run from this block is not really proven.
    """
    verification = finding.get("verification") or {}
    category = str(finding.get("category", "")).lower()
    lines = ["## Reproduce", ""]
    url = (verification.get("url") or "").strip()
    if not url:
        for key in finding.get("asset_keys", []) or []:
            if str(key).startswith(("url:", "webapp:")):
                candidate = str(key).split(":", 1)[1]
                if candidate.startswith(("http://", "https://")):
                    url = candidate
                    break
    action_id = str(verification.get("action_id") or "")
    if action_id:
        params = verification.get("params") or {}
        lines.append(f"- Proving action: `{action_id}`"
                     + (f" ({verification.get('selected_because', '')})"
                        if verification.get("selected_because") else ""))
        if params:
            shown = ", ".join(f"{k}={v}" for k, v in params.items())
            lines.append(f"- Action params: `{shown}`")
    if url:
        lines.append("")
        lines.append("```bash")
        lines.append(f"curl -i -sS --max-time 25 '{url}'")
        lines.append("```")
    if "sql" in category:
        lines.append("")
        lines.append("```bash")
        target = url or "<target URL with parameter>"
        lines.append(f"sqlmap -u '{target}' --batch --level 1 --risk 1 --smart")
        lines.append("```")
        lines.append("- Escalate to `--level 3 --risk 3` only on a FIRM candidate; "
                     "CONFIRMED requires out-of-band proof or stacked evidence.")
    elif "xss" in category or "cross-site" in category:
        lines.append("")
        lines.append("```bash")
        target = url or "<target URL with parameter>"
        lines.append(f"dalfox scan -i url '{target}' --only-poc v")
        lines.append("```")
        lines.append("- Browser-executed marker reflection is the bar; "
                     "reflected text alone is a candidate, not proof.")
    elif "redirect" in category:
        param = verification.get("param") or "<param>"
        lines.append("")
        lines.append("```bash")
        base = (url or "<target URL>").split("?")[0]
        lines.append(f"curl -sSI --max-time 25 '{base}?{param}=https://redirect-probe.invalid/' | grep -i '^location'")
        lines.append("```")
        lines.append("- Confirmed only if `Location` names the probe host; "
                     "never follow the redirect.")
    if len(lines) == 2:
        lines.append("No machine-readable proof recorded — re-run the module "
                     "that produced this finding with verification enabled.")
    lines.append("")
    return lines


def _render_index(ready: list[dict], files: list[str],
                  queued: list[dict], queued_files: list[str]) -> str:
    lines = ["# Bounty Submission Index", "",
             "Only CONFIRMED or verified findings are submittable. "
             "The rest wait in `needs-validation/`.", "",
             "## Ready to submit", "",
             "| Finding | Severity | Confidence | Verified | Score | File |",
             "|---|---|---|---|---:|---|"]
    for finding, path in zip(ready, files):
        lines.append(_index_row(finding, path))
    lines.extend(["", "## Needs validation", "",
                  "| Finding | Severity | Confidence | Verified | Score | File |",
                  "|---|---|---|---|---:|---|"])
    for finding, path in zip(queued, queued_files):
        lines.append(_index_row(finding, path))
    lines.append("")
    return "\n".join(lines)


def _index_row(finding: dict, path: str) -> str:
    return (
        f"| {finding.get('id', '')}: {finding.get('title', '')} | "
        f"{finding.get('severity', '')} | {finding.get('confidence', '')} | "
        f"{'yes' if finding.get('verified') else 'no'} | "
        f"{finding.get('risk_score', 0)} | `{path}` |"
    )


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
