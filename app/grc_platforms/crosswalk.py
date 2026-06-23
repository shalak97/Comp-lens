"""Standards-based control crosswalk — the shared translation layer.

Before this, every platform profile carried its own hardcoded dict mapping its
control refs to Comp-Lens control ids. That doesn't scale to a unified portal:
N platforms x M frameworks = bespoke dicts everywhere, and no honesty about how
good each mapping is.

This centralizes the crosswalk into a single, framework-keyed registry. A platform
profile no longer says "my CC6.1 means AC-2"; it says "I speak SOC2" and the shared
crosswalk does the translation. New platforms inherit every mapping for free, and
mapping quality is tracked per entry (exact vs partial vs heuristic) so the portal
can be honest about translation confidence across sources.

Maps are grounded in the public framework crosswalks (NIST 800-53 <-> SOC2 TSC <->
ISO 27001 Annex A) that NIST and the Secure Controls Framework publish. They are
starting points — validate against your own control set on first connection.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass
class Mapping:
    control_id: str          # Comp-Lens / NIST 800-53 control id
    quality: str             # exact | partial | heuristic
    note: str = ""


# quality -> base confidence contribution (combined with freshness downstream)
QUALITY_CONFIDENCE = {"exact": 0.95, "partial": 0.7, "heuristic": 0.5}

# ── framework crosswalks: their control ref -> Comp-Lens control id ──
# SOC 2 Trust Services Criteria -> NIST 800-53 (per NIST/SCF public crosswalks)
_SOC2 = {
    "CC6.1": Mapping("AC-2", "exact", "logical access provisioning"),
    "CC6.2": Mapping("AC-2", "partial", "registration/credentialing"),
    "CC6.3": Mapping("AC-3", "exact", "access enforcement"),
    "CC6.6": Mapping("SC-7", "exact", "boundary protection"),
    "CC6.7": Mapping("SC-28", "exact", "data at rest protection"),
    "CC6.8": Mapping("SI-3", "partial", "malicious code protection"),
    "CC7.1": Mapping("RA-5", "exact", "vulnerability monitoring"),
    "CC7.2": Mapping("SI-4", "exact", "system monitoring"),
    "CC7.3": Mapping("IR-4", "partial", "incident handling"),
    "CC8.1": Mapping("CM-3", "exact", "change control"),
    "A1.2": Mapping("CP-9", "partial", "availability / backup"),
}
# ISO 27001:2022 Annex A -> NIST 800-53
_ISO27001 = {
    "A.5.15": Mapping("AC-3", "exact", "access control"),
    "A.5.16": Mapping("IA-4", "partial", "identity management"),
    "A.5.18": Mapping("AC-2", "exact", "access rights"),
    "A.8.5": Mapping("IA-2", "exact", "secure authentication"),
    "A.8.8": Mapping("RA-5", "exact", "technical vulnerabilities"),
    "A.8.11": Mapping("SC-28", "partial", "data masking / at rest"),
    "A.8.16": Mapping("SI-4", "exact", "monitoring activities"),
    "A.8.24": Mapping("SC-28", "exact", "use of cryptography"),
    "A.8.32": Mapping("CM-3", "exact", "change management"),
}
# CIS Controls v8 -> NIST 800-53 (heuristic — CIS safeguards are coarser)
_CIS = {
    "5.1": Mapping("AC-2", "partial", "account management"),
    "6.1": Mapping("AC-3", "partial", "access control management"),
    "3.11": Mapping("SC-28", "partial", "encrypt data at rest"),
    "7.1": Mapping("RA-5", "partial", "vulnerability management"),
    "8.1": Mapping("AU-2", "heuristic", "audit log management"),
}

CROSSWALKS: Dict[str, Dict[str, Mapping]] = {
    "SOC2": _SOC2, "ISO27001": _ISO27001, "CIS": _CIS,
}


def resolve(framework: str, control_ref: str) -> Optional[Mapping]:
    """Translate a platform's (framework, control_ref) to a Comp-Lens mapping."""
    fw = CROSSWALKS.get((framework or "").upper())
    if not fw:
        return None
    return fw.get((control_ref or "").strip())


def resolve_best(control_ref: str, frameworks=None) -> Tuple[Optional[Mapping], Optional[str]]:
    """Resolve a control ref across one or more candidate frameworks.

    Returns (mapping, framework_used). Tries the declared frameworks first, then
    falls back to scanning all crosswalks (so a profile that mislabels its framework
    still maps, at reduced confidence). Honest about which framework produced the hit.
    """
    candidates = []
    if isinstance(frameworks, str):
        candidates = [frameworks]
    elif frameworks:
        candidates = list(frameworks)
    # declared frameworks first
    for fw in candidates:
        m = resolve(fw, control_ref)
        if m:
            return m, fw.upper()
    # fallback scan
    for fw, table in CROSSWALKS.items():
        m = table.get((control_ref or "").strip())
        if m:
            # downgrade quality one notch since framework wasn't declared
            downgraded = Mapping(m.control_id,
                                 "heuristic" if m.quality != "heuristic" else "heuristic",
                                 m.note + " (framework inferred)")
            return downgraded, fw
    return None, None


def register_crosswalk(framework: str, mapping: Dict[str, Mapping]) -> None:
    """Allow a YAML profile or extension to contribute a new framework crosswalk."""
    CROSSWALKS[framework.upper()] = mapping
