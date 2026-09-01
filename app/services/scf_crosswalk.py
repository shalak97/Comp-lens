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


def _in_catalog(framework: str, control_id: str) -> bool | None:
    """Is this a real control in our own catalog? None if we couldn't tell.

    Deliberately tri-state. Answering False when the catalog itself failed to
    load would assert "no such control" on no evidence — the same kind of
    unfounded claim this module exists to avoid.
    """
    try:
        from app.services import framework_catalog
        return framework_catalog.get(framework, control_id) is not None
    except Exception:  # noqa: BLE001 — an unavailable catalog is "unknown", not "absent"
        return None


def lookup(nist_id: str | None = None, iso_id: str | None = None) -> dict[str, Any]:
    """Ad-hoc NIST <-> ISO lookup, with enough context to read the answer.

    An empty list is ambiguous on its own: SCF genuinely not mapping a real
    control looks identical to a typo'd id that no catalog contains, and both
    look identical to the SCF data file having failed to load. A caller who
    can't tell those apart will read "[]" as "there is no ISO equivalent for
    this control", which is a claim we have not made. So each requested id is
    reported with whether our catalog actually contains it, alongside the
    reference-data status.
    """
    out: dict[str, Any] = {
        "scf_version": version(),
        "reference_data": _reference_data_status(),
    }
    if nist_id:
        out["nist_id"] = nist_id
        out["nist_id_in_catalog"] = _in_catalog("NIST_800_53", nist_id)
        out["iso_27001_annex_a"] = iso_for_nist(nist_id)
    if iso_id:
        out["iso_id"] = iso_id
        out["iso_id_in_catalog"] = _in_catalog("ISO_27001_2022", iso_id)
        out["nist_800_53_r5"] = nist_for_iso(iso_id)
    return out


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


def _reference_data_status() -> dict[str, Any]:
    """Is the SCF reference data actually loaded?

    Without this, a missing or empty app/data/scf_crosswalk.json makes every
    link fail to verify and the report reads "0% verified" — which accuses the
    crosswalk of being wrong when the truth is that there was nothing to check
    it against. Those two states must never look alike.
    """
    doc = _load()
    controls = doc.get("controls", [])
    return {
        "loaded": bool(controls),
        "version": doc.get("version"),
        "scf_controls": len(controls),
    }


def _declarative_pack_status() -> dict[str, Any]:
    """Did the declarative check pack load?

    app.frameworks._merge_declarative_crosswalk() folds the check pack's
    controls into CROSSWALK inside a bare ``except Exception: return`` — by
    design, so malformed content can never break the core mapping. The cost is
    that a failure is *invisible*: CROSSWALK silently shrinks to just the
    hand-written entries and this report then verifies a fraction of the
    catalog while reporting a higher percentage than the full run would. A
    compliance report that quietly narrows its own denominator and comes back
    with a better number is worse than no report, so probe the pack directly
    and say so.
    """
    try:
        from app.services.control_checks import all_checks
    except Exception as exc:  # noqa: BLE001 — the failure is the finding
        return {"loaded": False, "error": f"{type(exc).__name__}: {exc}",
                "checks_with_crosswalk": 0}
    try:
        checks = all_checks()
    except Exception as exc:  # noqa: BLE001
        return {"loaded": False, "error": f"{type(exc).__name__}: {exc}",
                "checks_with_crosswalk": 0}
    return {"loaded": True, "error": None,
            "checks_with_crosswalk": sum(1 for c in checks.values() if c.crosswalk)}


def verify_internal_crosswalk() -> dict[str, Any]:
    """Cross-check every internal control's NIST+ISO references against SCF.

    Returns per-control results plus a summary that states its own scope: how
    many controls are in the crosswalk at all, how many could be checked, and
    which were skipped and why. ``verified_pct`` is a percentage *of the
    controls that could be checked*, so it is only meaningful alongside
    ``scope_complete`` — read on its own it silently flatters a degraded run.
    """
    from app.frameworks import CROSSWALK, controls_for_framework

    # controls_for_framework() is the public entry point that folds the
    # declarative check pack into CROSSWALK, so calling it both triggers that
    # merge and yields the authoritative id list. Reading CROSSWALK directly
    # would verify only the hand-written entries and skip every declarative
    # control, without any sign that it had done so.
    control_ids = controls_for_framework("ALL")

    results: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []

    for internal_id in sorted(control_ids):
        mapping = CROSSWALK.get(internal_id, {})
        nist_refs = mapping.get("NIST", [])
        iso_refs = mapping.get("ISO27001", [])
        if not nist_refs or not iso_refs:
            # Not a failure — an SCF cross-check needs both sides to pivot
            # through. But these controls must stay visible in the report
            # rather than dropping out of the denominator unannounced.
            missing = []
            if not nist_refs:
                missing.append("NIST")
            if not iso_refs:
                missing.append("ISO 27001")
            skipped.append({"control_id": internal_id,
                            "reason": f"no {' or '.join(missing)} reference"})
            continue
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
    reference = _reference_data_status()
    pack = _declarative_pack_status()
    return {
        "scf_version": version(),
        "controls_in_crosswalk": len(control_ids),
        "controls_checked": checked,
        "controls_verified": verified,
        "controls_unverified": checked - verified,
        "controls_skipped": len(skipped),
        "verified_pct": round(verified / checked * 100, 1) if checked else 0.0,
        # False means this run examined less than the whole crosswalk, or had
        # no reference data to check it against — the percentage above is not
        # comparable to a complete run and must not be reported as coverage.
        "scope_complete": reference["loaded"] and pack["loaded"],
        "reference_data": reference,
        "declarative_pack": pack,
        "skipped": skipped,
        "results": results,
    }


__all__ = [
    "version", "iso_for_nist", "nist_for_iso", "scf_controls_linking",
    "lookup", "verify_link", "verify_internal_crosswalk",
]
