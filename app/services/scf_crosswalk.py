"""SCF-grounded framework-to-framework crosswalk.

Every check in app/data/control_checks.json carries a hand-authored crosswalk,
explicitly flagged as "illustrative — confirm against official framework texts
before a formal audit." This module is that confirmation: it loads the Secure
Controls Framework's published mapping (app/data/scf_crosswalk.json, extracted
from github.com/securecontrolsframework/securecontrolsframework, a
professionally-maintained meta-framework covering 250+ standards) and uses it
two ways.

1. As a standalone NIST<->ISO 27001 Annex A crosswalk, independent of Comp-Lens's
   own internal control ids — usable for any NIST or ISO control a customer
   asks about, not just the ~56 this platform can currently automate.
2. As ground truth to VERIFY the hand-authored crosswalk: for each internal
   control that declares both a NIST and an ISO reference, check whether SCF
   ever links that NIST control to that ISO control through a shared SCF
   control. A verified entry has independent, professionally-maintained
   corroboration; an unverified one is not necessarily wrong — SCF's own
   coverage is not exhaustive — but it has not been confirmed and should be
   read as illustrative until it is.

SCF pivots through its OWN control ids (e.g. GOV-01), not through Comp-Lens's
internal ones — SCF has no idea Comp-Lens's internal control ids exist. The
crosswalk here is NIST<->ISO, reached by two controls sharing at least one SCF
control in common; the SCF ids themselves are exposed as provenance
(which SCF control(s) support a given link) but are not a lookup key an API
caller is expected to use directly.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_PATH = Path(__file__).resolve().parent.parent / "data" / "scf_crosswalk.json"


@lru_cache(maxsize=1)
def _load() -> dict[str, Any]:
    if not _PATH.exists():
        return {"version": None, "controls": []}
    return json.loads(_PATH.read_text())


def version() -> str | None:
    return _load().get("version")


@lru_cache(maxsize=1)
def _indices() -> tuple[dict[str, set[str]], dict[str, set[str]], dict[tuple[str, str], set[str]]]:
    """Build once: nist_id -> iso_ids, iso_id -> nist_ids, (nist,iso) -> scf_ids.

    The pair index is what powers verification — it names which SCF control(s)
    justify a given NIST/ISO link, so a verified result is traceable rather
    than a bare yes/no.
    """
    nist_to_iso: dict[str, set[str]] = {}
    iso_to_nist: dict[str, set[str]] = {}
    pair_to_scf: dict[tuple[str, str], set[str]] = {}

    for c in _load().get("controls", []):
        nist_refs = c.get("nist_800_53_r5", [])
        iso_refs = c.get("iso_27001_annex_a", [])
        for n in nist_refs:
            nist_to_iso.setdefault(n, set()).update(iso_refs)
        for i in iso_refs:
            iso_to_nist.setdefault(i, set()).update(nist_refs)
        for n in nist_refs:
            for i in iso_refs:
                pair_to_scf.setdefault((n, i), set()).add(c["scf_id"])

    return nist_to_iso, iso_to_nist, pair_to_scf


def iso_for_nist(nist_id: str) -> list[str]:
    """ISO 27001 Annex A controls SCF links to this NIST 800-53 control."""
    return sorted(_indices()[0].get(nist_id, ()))


def nist_for_iso(iso_id: str) -> list[str]:
    """NIST 800-53 controls SCF links to this ISO 27001 Annex A control."""
    return sorted(_indices()[1].get(iso_id, ()))


def scf_controls_linking(nist_id: str, iso_id: str) -> list[str]:
    """Which SCF control(s) are the reason SCF links this NIST/ISO pair."""
    return sorted(_indices()[2].get((nist_id, iso_id), ()))


def _base(control_id: str) -> str:
    """Strip an enhancement suffix: "AC-2(7)" -> "AC-2". SCF's crosswalk is at
    base-control granularity for most entries; a hand-authored reference to a
    specific enhancement should still be checkable against its base control's
    SCF-verified links rather than reporting a spurious mismatch."""
    return control_id.split("(")[0]


def verify_link(nist_id: str, iso_id: str) -> dict[str, Any]:
    """Does SCF corroborate that this NIST control and this ISO control cover
    the same requirement? Checked at both exact and base-control granularity.
    """
    exact = scf_controls_linking(nist_id, iso_id)
    if exact:
        return {"nist_id": nist_id, "iso_id": iso_id, "verified": True,
                "granularity": "exact", "scf_controls": exact}
    base_hits = scf_controls_linking(_base(nist_id), _base(iso_id))
    if base_hits:
        return {"nist_id": nist_id, "iso_id": iso_id, "verified": True,
                "granularity": "base_control", "scf_controls": base_hits}
    return {"nist_id": nist_id, "iso_id": iso_id, "verified": False,
            "granularity": None, "scf_controls": []}


def verify_internal_crosswalk() -> dict[str, Any]:
    """Cross-check every hand-authored internal control's NIST+ISO references
    against SCF. Returns per-control results plus a summary, so the platform
    can show — not just claim — how much of its own crosswalk is independently
    corroborated versus still illustrative.
    """
    from app.frameworks import CROSSWALK, crosswalk_for

    # CROSSWALK starts with only the hand-written entries; the 38 declarative
    # controls' crosswalk data is merged into it lazily, on first call to
    # crosswalk_for()/controls_for_framework(). Reading CROSSWALK directly
    # without triggering that merge would silently verify only the legacy
    # controls and skip every one added this session.
    crosswalk_for("__trigger_merge__")

    results = []
    for internal_id, mapping in sorted(CROSSWALK.items()):
        nist_refs = mapping.get("NIST", [])
        iso_refs = mapping.get("ISO27001", [])
        if not nist_refs or not iso_refs:
            continue  # nothing to cross-check without both sides
        pairs = []
        for n in nist_refs:
            for i in iso_refs:
                pairs.append(verify_link(n, i))
        results.append({
            "control_id": internal_id,
            "nist_refs": nist_refs, "iso_refs": iso_refs,
            "any_verified": any(p["verified"] for p in pairs),
            "pairs": pairs,
        })

    checked = len(results)
    verified = sum(1 for r in results if r["any_verified"])
    return {
        "scf_version": version(),
        "controls_checked": checked,
        "controls_verified": verified,
        "controls_unverified": checked - verified,
        "verified_pct": round(verified / checked * 100, 1) if checked else 0.0,
        "results": results,
    }


__all__ = [
    "version", "iso_for_nist", "nist_for_iso", "scf_controls_linking",
    "verify_link", "verify_internal_crosswalk",
]
