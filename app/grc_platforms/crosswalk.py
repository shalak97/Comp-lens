"""Standards-based control crosswalk — the shared translation layer.

Before this, every platform profile carried its own hardcoded dict mapping its
control refs to Comp-Lens control ids. That doesn't scale to a unified portal:
N platforms x M frameworks = bespoke dicts everywhere, and no honesty about how
good each mapping is.

This centralizes the crosswalk into a single, framework-keyed registry. A platform
profile no longer says "my CC6.1 means AC-2"; it says "I speak SOC2" and the shared
crosswalk does the translation. New platforms inherit every mapping for free.

Mapping quality is a *first-class, typed* property, not a footnote:

  * ``quality``       — the legacy tier (exact | partial | heuristic), retained so
                        every existing consumer keeps working unchanged.
  * ``relationship``  — a NIST IR 8477 set-theory relationship *type* with a
                        direction (source ref → canonical control): EQUIVALENT,
                        SUBSET (source is narrower), SUPERSET (source is broader),
                        INTERSECTS (partial overlap), or NOT_RELATED. A quality
                        bucket alone can't say *which way* a partial map leans;
                        this can. Defaults are derived from ``quality`` so nothing
                        has to be re-authored.
  * ``confidence``    — ONE number in [0, 1] that should propagate downstream
                        (evidence → control → framework → compliance claim). It is a
                        strict generalisation of the old ``QUALITY_CONFIDENCE`` table:
                        for a mapping that keeps the default relationship for its
                        quality, ``confidence`` equals the legacy value exactly, so
                        no existing trust score moves. Only an explicitly *narrower*
                        relationship or ``strength`` override lowers it.

Maps are grounded in the public framework crosswalks (NIST 800-53 <-> SOC2 TSC <->
ISO 27001 Annex A <-> CIS v8) that NIST and the Secure Controls Framework publish.
They are starting points — validate against your own control set on first connection.
Because there is no authoritative gold-standard crosswalk to score against, the
honest signal is *relationship type + confidence*, carried per edge, never an
aggregate "accuracy" against a fabricated ground truth.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

# Schema version for the crosswalk registry. Stored assertions that embed a
# mapping should pin this so a later revision can be told apart from the edge it
# was made under (guards against silent framework/schema drift).
SCHEMA_VERSION = "2.0"

# The canonical namespace every mapping resolves *into*.
CANONICAL_FRAMEWORK = "NIST_800_53"


class RelationshipType(StrEnum):
    """NIST IR 8477 set-theory relationship of a source control ref TO the
    canonical Comp-Lens (NIST 800-53) control.

    Direction is always ``source_ref → canonical_control``:
      EQUIVALENT  the two cover the same scope in both directions
      SUBSET      the source ref is *narrower* than the canonical control
      SUPERSET    the source ref is *broader* than the canonical control
      INTERSECTS  they overlap, but neither contains the other
      NOT_RELATED no meaningful overlap
    """

    EQUIVALENT = "equivalent"
    SUBSET = "subset"
    SUPERSET = "superset"
    INTERSECTS = "intersects"
    NOT_RELATED = "not_related"


# quality -> base confidence contribution (retained verbatim for backward
# compatibility; existing callers read this table directly).
QUALITY_CONFIDENCE = {"exact": 0.95, "partial": 0.7, "heuristic": 0.5}

# The relationship a legacy quality bucket implies when none is stated.
_QUALITY_DEFAULT_REL = {
    "exact": RelationshipType.EQUIVALENT,
    "partial": RelationshipType.INTERSECTS,
    "heuristic": RelationshipType.INTERSECTS,
}

# How much trust a relationship *type* can carry on its own (a ceiling on
# confidence). Ceilings are set at or above the quality base of the type's
# default bucket, so a default-relationship mapping never scores below its legacy
# ``QUALITY_CONFIDENCE`` value — confidence is a strict generalisation, not a
# silent downgrade. An explicitly narrower type (or a ``strength`` override) is
# the only thing that pulls it down.
_REL_STRENGTH = {
    RelationshipType.EQUIVALENT: 1.0,
    RelationshipType.SUBSET: 0.90,
    RelationshipType.SUPERSET: 0.75,
    RelationshipType.INTERSECTS: 0.75,
    RelationshipType.NOT_RELATED: 0.0,
}


def _coerce_rel(value: Any, quality: str) -> RelationshipType:
    if value is None:
        return _QUALITY_DEFAULT_REL.get(quality, RelationshipType.INTERSECTS)
    if isinstance(value, RelationshipType):
        return value
    return RelationshipType(str(value).lower())


@dataclass
class Mapping:
    control_id: str          # Comp-Lens / NIST 800-53 control id
    quality: str             # exact | partial | heuristic  (legacy tier, retained)
    note: str = ""
    relationship: Any = None       # RelationshipType | str | None (derived if None)
    strength: float | None = None  # explicit 0..1 confidence override; derived if None

    def __post_init__(self) -> None:
        self.relationship = _coerce_rel(self.relationship, self.quality)

    @property
    def confidence(self) -> float:
        """The single first-class confidence for this edge, in [0, 1].

        This is the number to propagate downstream. It equals the legacy
        ``QUALITY_CONFIDENCE[quality]`` whenever the relationship is the default
        for that quality (so no existing score changes), and is capped by the
        relationship-type ceiling when a narrower type is stated. A ``strength``
        override, when given, wins outright.
        """
        if self.strength is not None:
            return round(max(0.0, min(1.0, float(self.strength))), 4)
        base = QUALITY_CONFIDENCE.get(self.quality, 0.5)
        ceiling = _REL_STRENGTH.get(self.relationship, 0.75)
        return round(max(0.0, min(base, ceiling)), 4)

    def to_dict(self) -> dict[str, Any]:
        """Serialisable edge — relationship type and confidence are first-class,
        not dropped on the floor at import time."""
        return {
            "control_id": self.control_id,
            "quality": self.quality,
            "relationship": self.relationship.value,
            "confidence": self.confidence,
            "note": self.note,
            "schema_version": SCHEMA_VERSION,
        }


def compose(a: float, b: float) -> float:
    """Compose two edge confidences along a chain (A→X, X→Y ⇒ A→Y).

    Multiplicative composition is a *pragmatic proxy*, not a proven calculus:
    if A intersects X at 0.7 and X intersects Y at 0.6, the transitive strength
    is treated as 0.42. There is no defensible general answer for chaining
    partial set-theory relationships, so downstream code must treat a composed
    confidence as strictly weaker evidence and never as an exact join. Kept here,
    and documented as a proxy, so every caller composes the same honest way.
    """
    return round(max(0.0, min(1.0, float(a) * float(b))), 4)


# ── framework crosswalks: their control ref -> Comp-Lens control id ──
# SOC 2 Trust Services Criteria -> NIST 800-53 (per NIST/SCF public crosswalks)
_SOC2 = {
    "CC6.1": Mapping("AC-2", "exact", "logical access provisioning"),
    "CC6.2": Mapping("AC-2", "partial", "registration/credentialing",
                     relationship=RelationshipType.INTERSECTS),
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
# CIS Controls v8 -> NIST 800-53. CIS safeguards are coarser, so a safeguard is
# typically *broader* than the NIST control it maps to: relationship = SUPERSET.
_CIS = {
    "5.1": Mapping("AC-2", "partial", "account management", relationship=RelationshipType.SUPERSET),
    "6.1": Mapping("AC-3", "partial", "access control management", relationship=RelationshipType.SUPERSET),
    "3.11": Mapping("SC-28", "partial", "encrypt data at rest", relationship=RelationshipType.SUPERSET),
    "7.1": Mapping("RA-5", "partial", "vulnerability management", relationship=RelationshipType.SUPERSET),
    "8.1": Mapping("AU-2", "heuristic", "audit log management", relationship=RelationshipType.SUPERSET),
}

CROSSWALKS: dict[str, dict[str, Mapping]] = {
    "SOC2": _SOC2, "ISO27001": _ISO27001, "CIS": _CIS,
}

# Provenance + version per framework crosswalk, so a stored mapping can pin the
# exact source revision it was drawn from (drift-proofing, IR 8477 discipline).
CROSSWALK_META: dict[str, dict[str, str]] = {
    "SOC2": {"source": "AICPA TSC 2017 ↔ NIST 800-53r5 (NIST/SCF crosswalk)", "revision": "2017"},
    "ISO27001": {"source": "ISO/IEC 27001:2022 Annex A ↔ NIST 800-53r5", "revision": "2022"},
    "CIS": {"source": "CIS Controls v8 ↔ NIST 800-53r5", "revision": "v8"},
}


def resolve(framework: str, control_ref: str) -> Mapping | None:
    """Translate a platform's (framework, control_ref) to a Comp-Lens mapping."""
    fw = CROSSWALKS.get((framework or "").upper())
    if not fw:
        return None
    return fw.get((control_ref or "").strip())


def resolve_best(control_ref: str, frameworks=None) -> tuple[Mapping | None, str | None]:
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
    # fallback scan — framework was not declared, so downgrade: the relationship
    # becomes INTERSECTS and the quality drops to heuristic, which together pull
    # ``confidence`` down honestly rather than asserting a match we can't place.
    for fw, table in CROSSWALKS.items():
        m = table.get((control_ref or "").strip())
        if m:
            downgraded = Mapping(
                m.control_id, "heuristic", m.note + " (framework inferred)",
                relationship=RelationshipType.INTERSECTS,
            )
            return downgraded, fw
    return None, None


def register_crosswalk(framework: str, mapping: dict[str, Mapping],
                       meta: dict[str, str] | None = None) -> None:
    """Allow a YAML profile or extension to contribute a new framework crosswalk."""
    CROSSWALKS[framework.upper()] = mapping
    if meta:
        CROSSWALK_META[framework.upper()] = meta


__all__ = [
    "SCHEMA_VERSION", "CANONICAL_FRAMEWORK", "RelationshipType", "Mapping",
    "QUALITY_CONFIDENCE", "CROSSWALKS", "CROSSWALK_META",
    "resolve", "resolve_best", "register_crosswalk", "compose",
]
