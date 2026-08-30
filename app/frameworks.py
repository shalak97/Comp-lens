"""Multi-framework crosswalk.

Each internal control maps to the equivalent clause/control in several
frameworks, so a single assessment can satisfy multiple audits at once.
References are illustrative mappings — confirm against the official framework
texts for a formal audit.
"""

from __future__ import annotations

# control_id -> { framework: [external control references] }
CROSSWALK: dict[str, dict[str, list[str]]] = {
    "AC-2-7": {"NIST": ["AC-2(7)"], "ISO27001": ["A.5.15", "A.8.5"], "SOC2": ["CC6.1"], "CIS": ["6.5"]},
    "AC-2-3": {"NIST": ["AC-2(3)"], "ISO27001": ["A.5.16"], "SOC2": ["CC6.1"], "CIS": ["5.3"]},
    "CM-3":   {"NIST": ["CM-3"], "ISO27001": ["A.8.32"], "SOC2": ["CC8.1"], "CIS": ["4.2"]},
    "SC-28":  {"NIST": ["SC-28"], "ISO27001": ["A.8.24"], "SOC2": ["CC6.1"], "CIS": ["3.11"]},
    "SC-7":   {"NIST": ["SC-7"], "ISO27001": ["A.8.20", "A.8.22"], "SOC2": ["CC6.6"], "CIS": ["12.2"]},
    "AU-2":   {"NIST": ["AU-2"], "ISO27001": ["A.8.15"], "SOC2": ["CC7.2"], "CIS": ["8.2"]},
    "RA-5":   {"NIST": ["RA-5"], "ISO27001": ["A.8.8"], "SOC2": ["CC7.1"], "CIS": ["7.1"]},
    "SA-15-BRANCH":  {"NIST": ["SA-15"], "ISO27001": ["A.8.25"], "SOC2": ["CC8.1"], "CIS": ["16.12"]},
    "SA-15-SECRETS": {"NIST": ["SA-15", "SA-11"], "ISO27001": ["A.8.25"], "SOC2": ["CC8.1"], "CIS": ["16.11"]},
    "SC-28-HOST":    {"NIST": ["SC-28"], "ISO27001": ["A.8.24"], "SOC2": ["CC6.1"], "CIS": ["3.11"]},
    # AI governance controls (ISO 42001 Annex A / NIST AI RMF functions / EU AI Act articles)
    "AI-INV":       {"ISO42001": ["A.6.2.1"], "NIST_AI_RMF": ["MAP-1"], "EU_AI_ACT": ["Art.11"]},
    "AI-RISK":      {"ISO42001": ["A.5.2"], "NIST_AI_RMF": ["MAP-1", "MEASURE-2"], "EU_AI_ACT": ["Art.9"]},
    "AI-DATA":      {"ISO42001": ["A.7.4"], "NIST_AI_RMF": ["MAP-2"], "EU_AI_ACT": ["Art.10"]},
    "AI-OVERSIGHT": {"ISO42001": ["A.9.2"], "NIST_AI_RMF": ["MANAGE-1"], "EU_AI_ACT": ["Art.14"]},
    "AI-TRANSP":    {"ISO42001": ["A.8.2"], "NIST_AI_RMF": ["GOVERN-4"], "EU_AI_ACT": ["Art.13"]},
    "AI-EVAL":      {"ISO42001": ["A.6.2.4"], "NIST_AI_RMF": ["MEASURE-2"], "EU_AI_ACT": ["Art.15"]},
    "AI-LOG":       {"ISO42001": ["A.6.2.8"], "NIST_AI_RMF": ["MANAGE-4"], "EU_AI_ACT": ["Art.12"]},
    "AI-ROBUST":    {"ISO42001": ["A.6.2.4"], "NIST_AI_RMF": ["MEASURE-2"], "EU_AI_ACT": ["Art.15"]},
}

FRAMEWORKS = ["NIST", "ISO27001", "SOC2", "CIS", "ISO42001", "NIST_AI_RMF", "EU_AI_ACT"]


_MERGED = False


def _merge_declarative_crosswalk() -> None:
    """Fold the declarative check pack's crosswalk into CROSSWALK.

    Each check in app/data/control_checks.json carries its own framework
    references, so adding a control is one edit in one file rather than a
    connector change plus an evaluator plus a crosswalk entry here. Merged
    lazily and once, on first use, to avoid an import cycle at module load.

    Hand-written entries above always win — the pack extends the crosswalk, it
    never redefines a mapping something already depends on.
    """
    global _MERGED
    if _MERGED:
        return
    _MERGED = True
    try:
        from app.services.control_checks import all_checks
    except Exception:  # noqa: BLE001  — never let content break the core mapping
        return
    for cid, check in all_checks().items():
        if cid not in CROSSWALK and check.crosswalk:
            CROSSWALK[cid] = {k: list(v) for k, v in check.crosswalk.items()}


def frameworks() -> list[str]:
    return list(FRAMEWORKS)


def controls_for_framework(framework: str) -> list[str]:
    """Internal control_ids that map to a given framework."""
    _merge_declarative_crosswalk()
    fw = framework.upper()
    if fw == "ALL":
        return list(CROSSWALK.keys())
    return [cid for cid, m in CROSSWALK.items() if any(k.upper() == fw for k in m)]


def crosswalk_for(control_id: str) -> dict[str, list[str]]:
    _merge_declarative_crosswalk()
    return CROSSWALK.get(control_id, {})
