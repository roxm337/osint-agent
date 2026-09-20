"""Report bundle builders and renderers for OSINT Agent."""

from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from core.scoring import score_label

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITIES)}


def build_report_bundle(state: Any, target: str) -> dict:
    """Build a structured report bundle from persisted investigation state."""
    summary = state.summary()
    findings = list(state.findings.get("findings", []))
    assets = list(state.assets.get("nodes", []))
    edges = list(state.assets.get("edges", []))
    evidence = list(state.evidence.get("items", []))
    runs = list(state.module.get("runs", []))

    findings_sorted = sorted(
        findings,
        key=lambda item: (
            int(item.get("risk_score") or 0),
            _severity_sort_value(item.get("severity")),
            str(item.get("created_at", "")),
        ),
        reverse=True,
    )

    severity_counts = {
        severity: summary["findings_by_severity"].get(severity, 0)
        for severity in SEVERITIES
    }
    risk_scores = [int(item.get("risk_score") or 0) for item in findings]
    asset_counts = Counter(str(item.get("type", "unknown")) for item in assets)
    module_status_counts = Counter(str(run.get("status", "unknown")) for run in runs)

    bundle = {
        "metadata": {
            "target": target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_version": "2.0",
            "output_dir": str(state.output_dir),
        },
        "summary": {
            "assets": len(assets),
            "relations": len(edges),
            "findings": len(findings),
            "evidence": len(evidence),
            "requests": summary["total_requests"],
            "waf_detected": summary["waf_detected"],
            "started_at": summary["started_at"],
            "last_action": summary["last_action"],
        },
        "risk": {
            "severity_counts": severity_counts,
            "max_score": max(risk_scores) if risk_scores else 0,
            "average_score": round(sum(risk_scores) / len(risk_scores), 1)
            if risk_scores
            else 0,
            "critical_high": severity_counts["CRITICAL"] + severity_counts["HIGH"],
            "top_findings": [_finding_digest(item) for item in findings_sorted[:10]],
        },
        "assets": {
            "counts_by_type": dict(sorted(asset_counts.items())),
            "high_value": _high_value_assets(assets),
            "samples_by_type": _asset_samples_by_type(assets),
        },
        "patterns": _derive_patterns(assets, edges, findings, summary),
        "recommendations": _derive_recommendations(findings_sorted, assets, summary),
        "modules": {
            "completed": list(summary["modules_completed"]),
            "skipped": list(summary["modules_skipped"]),
            "blocked": list(summary["modules_blocked"]),
            "status_counts": dict(sorted(module_status_counts.items())),
            "runs": [_run_digest(run) for run in runs],
        },
        "evidence": {
            "count": len(evidence),
            "items": [_evidence_digest(item) for item in evidence],
        },
        "findings": findings_sorted,
    }
    return bundle


def write_report_bundle(state: Any, target: str) -> dict:
    """Write markdown and JSON report artifacts into the state's output dir."""
    bundle = build_report_bundle(state, target)
    output_dir = Path(state.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "report": output_dir / f"{target}_report.md",
        "executive_summary": output_dir / f"{target}_executive_summary.md",
        "summary": output_dir / f"{target}_summary.json",
        "findings": output_dir / f"{target}_findings.json",
    }
    paths["report"].write_text(render_markdown(bundle))
    paths["executive_summary"].write_text(render_executive_summary(bundle))
    paths["summary"].write_text(json.dumps(bundle, indent=2, default=str))
    paths["findings"].write_text(json.dumps(state.findings, indent=2, default=str))
    return {key: str(path) for key, path in paths.items()}


def render_markdown(bundle: dict) -> str:
    metadata = bundle["metadata"]
    summary = bundle["summary"]
    risk = bundle["risk"]
    lines = [
        f"# OSINT Investigation Report: {metadata['target']}",
        "",
        f"**Generated:** {_format_iso(metadata['generated_at'])}",
        f"**Report Version:** {metadata['report_version']}",
        f"**Output Directory:** `{metadata['output_dir']}`",
        "",
        "## Executive Summary",
        "",
        _executive_narrative(bundle),
        "",
        "## Risk Overview",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Assets | {summary['assets']} |",
        f"| Relations | {summary['relations']} |",
        f"| Findings | {summary['findings']} |",
        f"| Evidence Items | {summary['evidence']} |",
        f"| Requests Made | {summary['requests']} |",
        f"| WAF Detected | {_yes_no(summary['waf_detected'])} |",
        f"| Max Risk Score | {risk['max_score']}/100 ({score_label(risk['max_score'])}) |",
        f"| Average Risk Score | {risk['average_score']}/100 |",
        f"| Critical/High Findings | {risk['critical_high']} |",
        "",
        "### Severity Distribution",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for severity in SEVERITIES:
        lines.append(f"| {severity} | {risk['severity_counts'].get(severity, 0)} |")

    lines.extend([
        "",
        "## Top Findings",
        "",
    ])
    if risk["top_findings"]:
        lines.extend([
            "| ID | Severity | Score | Title | Category |",
            "|---|---|---:|---|---|",
        ])
        for item in risk["top_findings"]:
            lines.append(
                f"| {_cell(item['id'])} | {_cell(item['severity'])} | "
                f"{item['risk_score']} | {_cell(item['title'])} | "
                f"{_cell(item['category'])} |"
            )
    else:
        lines.append("No findings were recorded.")

    lines.extend([
        "",
        "## Prioritized Recommendations",
        "",
    ])
    for recommendation in bundle["recommendations"]:
        lines.append(f"- {recommendation}")

    lines.extend([
        "",
        "## Attack Surface Patterns",
        "",
    ])
    if bundle["patterns"]:
        for pattern in bundle["patterns"]:
            lines.append(f"- **{_escape_text(pattern['title'])}:** {_escape_text(pattern['detail'])}")
    else:
        lines.append("- No notable cross-asset patterns were identified.")

    lines.extend([
        "",
        "## Detailed Findings",
        "",
    ])
    if bundle["findings"]:
        for severity in SEVERITIES:
            findings = [
                item for item in bundle["findings"]
                if str(item.get("severity", "")).upper() == severity
            ]
            if not findings:
                continue
            lines.extend([f"### {severity}", ""])
            for finding in findings:
                lines.extend(_render_finding(finding, bundle["evidence"]["items"]))
    else:
        lines.append("No detailed findings were recorded.")

    lines.extend(_render_evidence_index(bundle["evidence"]["items"]))
    lines.extend(_render_module_ledger(bundle["modules"]))
    lines.extend(_render_visual_evidence(bundle["assets"]))
    lines.extend(_render_asset_inventory(bundle["assets"]))
    lines.extend([
        "",
        "---",
        "",
        f"*Generated by OSINT Agent at {_format_iso(metadata['generated_at'])}*",
        "",
    ])
    return "\n".join(lines)


def render_executive_summary(bundle: dict) -> str:
    metadata = bundle["metadata"]
    risk = bundle["risk"]
    lines = [
        f"# Executive Summary: {metadata['target']}",
        "",
        _executive_narrative(bundle),
        "",
        "## Immediate Priorities",
        "",
    ]
    for recommendation in bundle["recommendations"][:5]:
        lines.append(f"- {recommendation}")
    lines.extend([
        "",
        "## Highest-Risk Findings",
        "",
    ])
    if risk["top_findings"]:
        for item in risk["top_findings"][:5]:
            lines.append(
                f"- {item['id']} [{item['severity']} {item['risk_score']}/100]: "
                f"{_escape_text(item['title'])}"
            )
    else:
        lines.append("- No findings were recorded.")
    lines.append("")
    return "\n".join(lines)


def _render_finding(finding: dict, evidence_items: list[dict]) -> list[str]:
    evidence_by_id = {item.get("id"): item for item in evidence_items}
    risk_score = int(finding.get("risk_score") or 0)
    lines = [
        f"#### {_escape_text(finding.get('id', 'FINDING'))}: "
        f"{_escape_text(finding.get('title', 'Untitled Finding'))}",
        "",
        f"- **Risk Score:** {risk_score}/100 ({score_label(risk_score)})",
        f"- **Confidence:** {_escape_text(finding.get('confidence', ''))}",
        f"- **Category:** {_escape_text(finding.get('category', ''))}",
        f"- **Description:** {_escape_text(finding.get('description', ''))}",
    ]
    if finding.get("asset_keys"):
        lines.append("- **Affected Assets:**")
        for asset_key in finding["asset_keys"]:
            lines.append(f"  - `{_escape_text(asset_key)}`")
    if finding.get("evidence"):
        lines.append("- **Evidence:**")
        for evidence in finding["evidence"]:
            lines.append(f"  - {_escape_text(evidence)}")
    if finding.get("evidence_refs"):
        lines.append("- **Evidence Files:**")
        for evidence_ref in finding["evidence_refs"]:
            item = evidence_by_id.get(evidence_ref, {})
            path = item.get("path", evidence_ref)
            lines.append(f"  - `{_escape_text(path)}`")
    if finding.get("remediation"):
        lines.append(f"- **Remediation:** {_escape_text(finding['remediation'])}")
    lines.append("")
    return lines


def _render_evidence_index(items: list[dict]) -> list[str]:
    lines = ["", "## Evidence Index", ""]
    if not items:
        lines.append("No evidence files were recorded.")
        return lines
    lines.extend([
        "| ID | Module | Type | Subject | Path |",
        "|---|---|---|---|---|",
    ])
    for item in items:
        lines.append(
            f"| {_cell(item.get('id', ''))} | {_cell(item.get('module_id', ''))} | "
            f"{_cell(item.get('type', ''))} | {_cell(item.get('subject', ''))} | "
            f"`{_cell(item.get('path', ''))}` |"
        )
    return lines


def _render_module_ledger(modules: dict) -> list[str]:
    lines = [
        "",
        "## Module Run Ledger",
        "",
        f"**Completed:** {_join_or_dash(modules['completed'])}",
        f"**Skipped:** {_join_or_dash(modules['skipped'])}",
        f"**Blocked:** {_join_or_dash(modules['blocked'])}",
        "",
    ]
    runs = modules["runs"]
    if not runs:
        lines.append("No module run ledger entries were recorded.")
        return lines
    lines.extend([
        "| Run | Stage | Module | Status | Requests | Assets Added | Findings Added | Duration |",
        "|---|---:|---|---|---:|---:|---:|---:|",
    ])
    for run in runs:
        lines.append(
            f"| {_cell(run.get('id', ''))} | {run.get('stage', 0)} | "
            f"{_cell(run.get('module_id', ''))} | {_cell(run.get('status', ''))} | "
            f"{run.get('requests', 0)} | {run.get('assets_added', 0)} | "
            f"{run.get('findings_added', 0)} | {_cell(run.get('duration', ''))} |"
        )
    return lines


def _render_asset_inventory(assets: dict) -> list[str]:
    lines = ["", "## Asset Inventory", ""]
    if not assets["counts_by_type"]:
        lines.append("No assets were recorded.")
        return lines
    lines.extend([
        "### Counts by Type",
        "",
        "| Type | Count |",
        "|---|---:|",
    ])
    for asset_type, count in assets["counts_by_type"].items():
        lines.append(f"| {_cell(asset_type)} | {count} |")
    lines.extend(["", "### Representative Assets", ""])
    for asset_type, samples in assets["samples_by_type"].items():
        lines.append(f"**{_escape_text(asset_type)}**")
        for sample in samples:
            lines.append(f"- `{_escape_text(sample)}`")
        lines.append("")
    return lines


def _render_visual_evidence(assets: dict) -> list[str]:
    screenshots = assets["samples_by_type"].get("screenshot_target", [])
    if not screenshots:
        return []
    lines = ["", "## Visual Evidence", ""]
    for target in screenshots[:20]:
        lines.append(f"- `{_escape_text(target)}`")
    return lines


def _derive_recommendations(findings: list[dict], assets: list[dict], summary: dict) -> list[str]:
    recommendations = []
    high_risk = [
        item for item in findings
        if int(item.get("risk_score") or 0) >= 70
        or str(item.get("severity", "")).upper() in {"CRITICAL", "HIGH"}
    ]
    if high_risk:
        recommendations.append(
            "Prioritize validation and remediation of critical/high findings before "
            "expanding active testing."
        )
    if summary["waf_detected"]:
        recommendations.append(
            "Review WAF/rate-limit behavior before active modules to avoid noisy or blocked scans."
        )
    if any(str(item.get("type")) in {"webapp", "url"} for item in assets):
        recommendations.append(
            "Run crawl and parameter discovery against live web applications to convert paths into test cases."
        )
    if any(str(item.get("type")) in {"bucket", "cloud"} for item in assets):
        recommendations.append(
            "Validate cloud storage exposure and ownership before creating a bounty submission."
        )
    if any("takeover" in str(item.get("category", "")).lower() for item in findings):
        recommendations.append(
            "Confirm dangling DNS or takeover candidates with non-destructive proof before escalation."
        )
    if not recommendations:
        recommendations.append(
            "Continue enrichment with passive APIs and evidence collection before intrusive testing."
        )
    return recommendations


def _derive_patterns(
    assets: list[dict], edges: list[dict], findings: list[dict], summary: dict
) -> list[dict]:
    asset_counts = Counter(str(item.get("type", "unknown")) for item in assets)
    edge_counts = Counter(str(item.get("type", "unknown")) for item in edges)
    categories = Counter(str(item.get("category", "Unknown")) for item in findings)
    patterns = []

    if asset_counts.get("subdomain", 0) >= 20:
        patterns.append({
            "title": "Large subdomain surface",
            "detail": f"{asset_counts['subdomain']} subdomains discovered; prioritize live services and ownership validation.",
        })
    if asset_counts.get("webapp", 0) or asset_counts.get("url", 0):
        patterns.append({
            "title": "Web application concentration",
            "detail": "Live web assets are present; crawl, parameter discovery, and screenshot triage should be next.",
        })
    if edge_counts:
        strongest = edge_counts.most_common(1)[0]
        patterns.append({
            "title": "Dominant relationship type",
            "detail": f"`{strongest[0]}` relationships account for {strongest[1]} graph edges.",
        })
    for category, count in categories.most_common(3):
        if count:
            patterns.append({
                "title": f"{category} finding cluster",
                "detail": f"{count} finding(s) share this category.",
            })
    if summary["modules_blocked"]:
        patterns.append({
            "title": "Blocked coverage",
            "detail": f"{len(summary['modules_blocked'])} module(s) were blocked and may hide untested surface.",
        })
    return patterns


def _asset_samples_by_type(assets: list[dict]) -> dict:
    grouped = defaultdict(list)
    for asset in assets:
        asset_type = str(asset.get("type", "unknown"))
        if len(grouped[asset_type]) < 10:
            grouped[asset_type].append(str(asset.get("value", asset.get("key", ""))))
    return dict(sorted(grouped.items()))


def _high_value_assets(assets: list[dict]) -> list[dict]:
    high_value_types = {"webapp", "url", "ip", "bucket", "cloud", "dns_takeover"}
    selected = []
    for asset in assets:
        if str(asset.get("type")) in high_value_types:
            selected.append({
                "type": asset.get("type", ""),
                "key": asset.get("key", ""),
                "value": asset.get("value", ""),
                "confidence": asset.get("confidence", ""),
            })
        if len(selected) >= 25:
            break
    return selected


def _finding_digest(finding: dict) -> dict:
    return {
        "id": finding.get("id", ""),
        "title": finding.get("title", ""),
        "severity": finding.get("severity", ""),
        "confidence": finding.get("confidence", ""),
        "risk_score": int(finding.get("risk_score") or 0),
        "category": finding.get("category", ""),
        "asset_keys": list(finding.get("asset_keys", [])),
        "evidence_refs": list(finding.get("evidence_refs", [])),
    }


def _run_digest(run: dict) -> dict:
    started_at = run.get("started_at")
    finished_at = run.get("finished_at")
    return {
        "id": run.get("id", ""),
        "module_id": run.get("module_id", ""),
        "stage": run.get("stage", 0),
        "detectability": run.get("detectability", ""),
        "status": run.get("status", ""),
        "requests": run.get("requests", 0),
        "assets_added": run.get("assets_added", 0),
        "findings_added": run.get("findings_added", 0),
        "started_at": started_at,
        "finished_at": finished_at,
        "duration": _duration(started_at, finished_at),
        "error": run.get("error", ""),
    }


def _evidence_digest(item: dict) -> dict:
    return {
        "id": item.get("id", ""),
        "module_id": item.get("module_id", ""),
        "type": item.get("type", ""),
        "subject": item.get("subject", ""),
        "path": item.get("path", ""),
        "created_at": item.get("created_at", ""),
    }


def _executive_narrative(bundle: dict) -> str:
    summary = bundle["summary"]
    risk = bundle["risk"]
    target = bundle["metadata"]["target"]
    return (
        f"The investigation for `{_escape_text(target)}` identified "
        f"{summary['assets']} assets, {summary['relations']} relations, "
        f"{summary['findings']} findings, and {summary['evidence']} evidence items. "
        f"The highest current risk score is {risk['max_score']}/100 "
        f"({score_label(risk['max_score'])}), with {risk['critical_high']} "
        "critical/high finding(s) requiring priority review."
    )


def _duration(started_at: str | None, finished_at: str | None) -> str:
    if not started_at or not finished_at:
        return ""
    try:
        started = datetime.fromisoformat(started_at)
        finished = datetime.fromisoformat(finished_at)
    except ValueError:
        return ""
    seconds = int((finished - started).total_seconds())
    if seconds < 0:
        return ""
    return f"{seconds}s"


def _severity_sort_value(severity: str | None) -> int:
    value = str(severity or "INFO").upper()
    return len(SEVERITIES) - SEVERITY_RANK.get(value, len(SEVERITIES) - 1)


def _format_iso(value: str) -> str:
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return value
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _join_or_dash(values: list[str]) -> str:
    return ", ".join(values) if values else "-"


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _cell(value: Any) -> str:
    return _escape_text(value).replace("|", "\\|").replace("\n", " ")


def _escape_text(value: Any) -> str:
    return str(value).replace("\r", " ").strip()
