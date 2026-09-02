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
    # AI governance controls (ISO 42001 Annex A / NIST AI RMF functions / EU AI Act articles).
    #
    # These also carry NIST 800-53 and ISO 27001 Annex A references wherever a
    # genuine equivalent exists. That is not decoration: without a reference on
    # both of those catalogues an AI control cannot appear in a NIST or ISO
    # report, and the SCF cross-check (app/services/scf_crosswalk.py) has no
    # pair to corroborate, so it sits outside the verified set by construction.
    #
    # Only defensible equivalents are listed. AI-OVERSIGHT gets none: "a human
    # can intervene in an automated decision" has no counterpart in either
    # catalogue, and inventing one to raise a coverage figure is the failure
    # this codebase spends most of its effort avoiding. It keeps its AI-specific
    # mappings and stays outside the SCF denominator, honestly.
    "AI-INV":       {"ISO42001": ["A.6.2.1"], "NIST_AI_RMF": ["MAP-1"], "EU_AI_ACT": ["Art.11"],
                     "NIST": ["CM-8", "PM-5"], "ISO27001": ["A.5.9"]},
    "AI-RISK":      {"ISO42001": ["A.5.2"], "NIST_AI_RMF": ["MAP-1", "MEASURE-2"], "EU_AI_ACT": ["Art.9"],
                     "NIST": ["RA-3", "PM-9"]},
    "AI-DATA":      {"ISO42001": ["A.7.4"], "NIST_AI_RMF": ["MAP-2"], "EU_AI_ACT": ["Art.10"],
                     "NIST": ["RA-2", "SI-12"], "ISO27001": ["A.5.12", "A.5.13"]},
    "AI-OVERSIGHT": {"ISO42001": ["A.9.2"], "NIST_AI_RMF": ["MANAGE-1"], "EU_AI_ACT": ["Art.14"]},
    "AI-TRANSP":    {"ISO42001": ["A.8.2"], "NIST_AI_RMF": ["GOVERN-4"], "EU_AI_ACT": ["Art.13"],
                     "NIST": ["PT-5"], "ISO27001": ["A.5.34"]},
    "AI-EVAL":      {"ISO42001": ["A.6.2.4"], "NIST_AI_RMF": ["MEASURE-2"], "EU_AI_ACT": ["Art.15"],
                     "NIST": ["SA-11"], "ISO27001": ["A.8.29"]},
    "AI-LOG":       {"ISO42001": ["A.6.2.8"], "NIST_AI_RMF": ["MANAGE-4"], "EU_AI_ACT": ["Art.12"],
                     "NIST": ["AU-2", "AU-12"], "ISO27001": ["A.8.15"]},
    "AI-ROBUST":    {"ISO42001": ["A.6.2.4"], "NIST_AI_RMF": ["MEASURE-2"], "EU_AI_ACT": ["Art.15"],
                     "NIST": ["SA-11", "SI-10"], "ISO27001": ["A.8.29"]},
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
