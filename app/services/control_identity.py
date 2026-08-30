"""The internal-id <-> framework-id pivot.

Comp-Lens names controls twice. Internally a control is a thing the platform
can *evaluate* — `AC-2-7`, `SC-28-OBJSTORE-KMS`, `IA-2-ROOT-MFA` — chosen so one
check can satisfy several frameworks at once. Externally a control is a clause
in a published catalogue — `AC-2(7)`, `A.8.24`, `CC6.1`. The crosswalk in
app/frameworks.py (extended by the declarative check pack) is what maps between
them, and the architecture calls that mapping the pivot the whole product turns
on.

Until this module existed, nothing applied it at the join points. Two subsystems
compared internal ids directly against catalogue ids:

  * framework_catalog.controls() marked a catalogue row "automated" only when a
    CONTROL_CATALOG key was spelled identically to the catalogue id, so 5 of the
    45 genuinely-covered NIST controls lit up and ISO 27001 showed 0 of 93.
  * AttestationService.coverage() matched Finding.control_id (internal) against
    those same catalogue ids, so findings for 51 of 56 automated controls never
    counted toward the audit-readiness number the product leads with.

The frameworks were also named twice — `NIST` in the crosswalk and on /summary,
`NIST_800_53` in the catalogue — with no translation, so `/coverage?framework=NIST`
silently returned an empty report rather than failing.

This module owns both translations so callers never do string matching again.
"""

from __future__ import annotations

import re
from functools import lru_cache

#: Catalogue keys (app/data/frameworks/*.json via framework_catalog.FRAMEWORKS).
NIST = "NIST_800_53"
ISO = "ISO_27001_2022"

#: Every spelling a caller might reasonably pass -> catalogue key.
_FRAMEWORK_ALIASES = {
    "nist": NIST, "nist_800_53": NIST, "nist-800-53": NIST, "nist80053": NIST,
    "800-53": NIST, "sp800-53": NIST, "nist_sp_800_53": NIST,
    "iso27001": ISO, "iso_27001_2022": ISO, "iso-27001": ISO, "iso 27001": ISO,
    "iso27001_2022": ISO, "iso_27001": ISO, "27001": ISO,
}

#: Catalogue key -> the key the crosswalk uses for that framework.
_CATALOG_TO_CROSSWALK = {NIST: "NIST", ISO: "ISO27001"}

#: "AC-2(7)" -> "AC-2"
_ENHANCEMENT = re.compile(r"^(?P<base>[^(]+)\(.+\)$")


def normalize_framework(name: str | None) -> str | None:
    """Resolve any accepted framework spelling to its catalogue key.

    Returns None for a framework with no published catalogue (SOC2, CIS and the
    AI frameworks are crosswalk targets only), so callers can distinguish
    "not a catalogue framework" from "unknown name".
    """
    if not name:
        return None
    return _FRAMEWORK_ALIASES.get(name.strip().lower().replace(" ", "_").replace("/", "_"))


def crosswalk_key(catalog_key: str) -> str | None:
    """The crosswalk's name for a catalogue framework."""
    return _CATALOG_TO_CROSSWALK.get(catalog_key)


def _resolve_ref(ref: str, catalog_ids: frozenset[str]) -> str | None:
    """Map one crosswalk reference onto a real catalogue id.

    Exact match wins. Failing that, an enhancement reference falls back to its
    base control, so a crosswalk pointing at `AC-2(7)` still resolves against a
    catalogue that only carries `AC-2`.
    """
    if ref in catalog_ids:
        return ref
    m = _ENHANCEMENT.match(ref)
    if m:
        base = m.group("base").strip()
        if base in catalog_ids:
            return base
    return None


@lru_cache(maxsize=8)
def _catalog_ids(catalog_key: str) -> frozenset[str]:
    from app.services import framework_catalog as catalog
    return frozenset(c["id"] for c in catalog.controls(catalog_key, _raw=True))


@lru_cache(maxsize=8)
def internal_to_canonical(catalog_key: str) -> dict[str, frozenset[str]]:
    """internal control id -> the catalogue ids it covers, for one framework."""
    from app.frameworks import crosswalk_for
    from app.policy.engine import CONTROL_CATALOG

    xw = crosswalk_key(catalog_key)
    if xw is None:
        return {}
    ids = _catalog_ids(catalog_key)
    out: dict[str, frozenset[str]] = {}
    for internal in CONTROL_CATALOG:
        resolved = {
            r for r in (_resolve_ref(ref, ids) for ref in crosswalk_for(internal).get(xw, []))
            if r is not None
        }
        if resolved:
            out[internal] = frozenset(resolved)
    return out


@lru_cache(maxsize=8)
def canonical_to_internal(catalog_key: str) -> dict[str, frozenset[str]]:
    """catalogue id -> the internal control ids that evaluate it."""
    rev: dict[str, set[str]] = {}
    for internal, canon in internal_to_canonical(catalog_key).items():
        for c in canon:
            rev.setdefault(c, set()).add(internal)
    return {k: frozenset(v) for k, v in rev.items()}


@lru_cache(maxsize=8)
def automated_canonical_ids(catalog_key: str) -> frozenset[str]:
    """Catalogue ids that at least one internal control can actually evaluate."""
    return frozenset(canonical_to_internal(catalog_key))


def canonical_ids_for(internal_id: str, catalog_key: str) -> frozenset[str]:
    return internal_to_canonical(catalog_key).get(internal_id, frozenset())


def reset_caches() -> None:
    """Drop memoised maps — for tests that mutate the catalogue or crosswalk."""
    for fn in (_catalog_ids, internal_to_canonical, canonical_to_internal,
               automated_canonical_ids):
        fn.cache_clear()


__all__ = [
    "NIST", "ISO", "normalize_framework", "crosswalk_key",
    "internal_to_canonical", "canonical_to_internal", "automated_canonical_ids",
    "canonical_ids_for", "reset_caches",
]
