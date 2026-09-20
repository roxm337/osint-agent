"""Finding risk scoring helpers."""

from typing import List, Optional

SEVERITY_BASE = {
    "INFO": 5,
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 95,
}

CONFIDENCE_MULTIPLIER = {
    "TENTATIVE": 0.65,
    "FIRM": 0.85,
    "CONFIRMED": 1.0,
}


def score_finding(severity: str, confidence: str, asset_keys: Optional[List[str]] = None,
                  category: str = "") -> int:
    """Return a stable 0-100 risk score from severity, confidence, and context."""
    sev = str(severity or "INFO").upper()
    conf = str(confidence or "TENTATIVE").upper()
    score = SEVERITY_BASE.get(sev, 5) * CONFIDENCE_MULTIPLIER.get(conf, 0.65)

    assets = asset_keys or []
    if assets:
        score += 3
    if any(k.startswith(("port:", "webapp:", "cloud:", "bucket:")) for k in assets):
        score += 7

    category_l = (category or "").lower()
    if any(term in category_l for term in ("credential", "exposure", "network")):
        score += 5

    return max(0, min(100, round(score)))


def score_label(score: int) -> str:
    if score >= 95:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 15:
        return "Low"
    return "Informational"


def score_vulnerability(cvss: float = 0.0, epss: float = 0.0,
                        kev: bool = False, exposure: float = 0.0,
                        weights: Optional[dict] = None) -> int:
    """Score vulnerability intelligence using CVSS, EPSS, KEV, and exposure."""
    active_weights = {
        "cvss": 0.4,
        "epss": 0.3,
        "kev": 0.2,
        "exposure": 0.1,
    }
    if weights:
        active_weights.update(weights)

    cvss_component = max(0.0, min(float(cvss or 0.0), 10.0)) / 10.0
    epss_component = max(0.0, min(float(epss or 0.0), 1.0))
    kev_component = 1.0 if kev else 0.0
    exposure_component = max(0.0, min(float(exposure or 0.0), 1.0))

    weighted = (
        cvss_component * active_weights["cvss"]
        + epss_component * active_weights["epss"]
        + kev_component * active_weights["kev"]
        + exposure_component * active_weights["exposure"]
    )
    return max(0, min(100, round(weighted * 100)))
