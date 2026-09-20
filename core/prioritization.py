"""Finding prioritization helpers."""

from core.scoring import score_finding, score_vulnerability

SEVERITY_FROM_SCORE = (
    (90, "CRITICAL"),
    (70, "HIGH"),
    (40, "MEDIUM"),
    (15, "LOW"),
    (0, "INFO"),
)


def prioritize_findings(findings: list[dict], scoring_config: dict | None = None) -> list[dict]:
    """Update findings in place with normalized priority metadata."""
    weights = (scoring_config or {}).get("weights", {})
    prioritized = []

    for finding in findings:
        intelligence = finding.get("intelligence", {}) or {}
        cvss = _first_number(
            intelligence.get("cvss"),
            finding.get("cvss_score"),
            finding.get("cvss"),
        )
        epss = _first_number(
            intelligence.get("epss"),
            finding.get("epss_score"),
            finding.get("epss"),
        )
        kev = bool(
            intelligence.get("kev")
            or finding.get("kev")
            or "known exploited" in str(finding.get("category", "")).lower()
        )
        exposure = _exposure_score(finding)

        if cvss or epss or kev:
            score = score_vulnerability(
                cvss=cvss,
                epss=epss,
                kev=kev,
                exposure=exposure,
                weights=weights,
            )
        else:
            score = score_finding(
                finding.get("severity", "INFO"),
                finding.get("confidence", "TENTATIVE"),
                finding.get("asset_keys", []),
                finding.get("category", ""),
            )

        existing_score = int(finding.get("risk_score") or 0)
        score = max(existing_score, score)
        finding["risk_score"] = score
        finding["priority"] = _priority_from_score(score)
        finding["priority_factors"] = {
            "cvss": cvss,
            "epss": epss,
            "kev": kev,
            "exposure": exposure,
        }
        finding["severity"] = _max_severity(
            finding.get("severity", "INFO"),
            _severity_from_score(score),
        )
        prioritized.append(finding)

    prioritized.sort(
        key=lambda item: (
            int(item.get("risk_score") or 0),
            str(item.get("severity", "")),
            str(item.get("created_at", "")),
        ),
        reverse=True,
    )
    return prioritized


def _exposure_score(finding: dict) -> float:
    asset_keys = finding.get("asset_keys", []) or []
    category = str(finding.get("category", "")).lower()
    score = 0.0
    if asset_keys:
        score += 0.35
    if any(str(key).startswith(("webapp:", "url:", "ip:", "bucket:", "cloud:")) for key in asset_keys):
        score += 0.35
    if any(term in category for term in ("exposure", "takeover", "credential", "cloud")):
        score += 0.3
    return min(score, 1.0)


def _priority_from_score(score: int) -> str:
    if score >= 90:
        return "P0"
    if score >= 70:
        return "P1"
    if score >= 40:
        return "P2"
    if score >= 15:
        return "P3"
    return "P4"


def _severity_from_score(score: int) -> str:
    for threshold, severity in SEVERITY_FROM_SCORE:
        if score >= threshold:
            return severity
    return "INFO"


def _max_severity(current: str, candidate: str) -> str:
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    current_upper = str(current or "INFO").upper()
    candidate_upper = str(candidate or "INFO").upper()
    if order.get(candidate_upper, 0) > order.get(current_upper, 0):
        return candidate_upper
    return current_upper


def _first_number(*values) -> float:
    for value in values:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            continue
        if parsed > 0:
            return parsed
    return 0.0
