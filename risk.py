"""Risk weighting.

Compliance as a raw pass/fail ratio treats a failed critical control the same
as a failed low one. These weights let the platform compute a *risk-weighted*
score and prioritize remediation by impact (severity x asset criticality).
"""

from __future__ import annotations

from app.models import Severity

# how much an unmet control of each severity contributes to risk exposure
SEVERITY_WEIGHT = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 5.0,
    Severity.MEDIUM: 3.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.0,
}

# multiplier from the asset's business criticality (from inventory)
CRITICALITY_WEIGHT = {
    "critical": 3.0,
    "high": 2.0,
    "medium": 1.0,
    "low": 0.5,
}


def severity_weight(sev) -> float:
    if isinstance(sev, Severity):
        return SEVERITY_WEIGHT.get(sev, 3.0)
    try:
        return SEVERITY_WEIGHT.get(Severity(str(sev)), 3.0)
    except ValueError:
        return 3.0


def criticality_weight(crit: str | None) -> float:
    return CRITICALITY_WEIGHT.get((crit or "medium").lower(), 1.0)
