"""Framework control catalogs (NIST SP 800-53 Rev5, ISO/IEC 27001:2022 Annex A).

Catalogs are reference data loaded from app/data/frameworks/*.json. The bundled
auto-evaluated controls (app/policy/engine.py) are surfaced here too so the UI
can show which catalog controls are automatically assessed vs attestation-based.
"""
from __future__ import annotations

import json
import os
from functools import cache, lru_cache
from typing import Any

_DATA = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "frameworks")

FRAMEWORKS = {
    "NIST_800_53": {"label": "NIST SP 800-53 Rev 5", "file": "nist_800_53.json",
                    "authority": "NIST", "kind": "security"},
    "ISO_27001_2022": {"label": "ISO/IEC 27001:2022 Annex A", "file": "iso_27001_2022.json",
                       "authority": "ISO/IEC", "kind": "security"},
}


def _key(framework: str) -> str | None:
    """Accept either the catalogue key or the name the rest of the API uses.

    /summary and /crosswalk speak "NIST"/"ISO27001"; this catalogue is keyed by
    "NIST_800_53"/"ISO_27001_2022". Passing the former used to yield an empty
    catalogue and a silently empty coverage report.
    """
    if framework in FRAMEWORKS:
        return framework
    from app.services.control_identity import normalize_framework
    return normalize_framework(framework)


@cache
def _load(framework: str) -> list[dict[str, Any]]:
    meta = FRAMEWORKS.get(_key(framework))
    if not meta:
        return []
    path = os.path.join(_DATA, meta["file"])
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _automated_ids(framework: str) -> set:
    """Catalogue ids that a live evaluator can actually assess.

    Resolved through the crosswalk rather than by matching internal control ids
    against catalogue ids directly: the two are different vocabularies, so the
    old identity comparison marked 5 of the 45 genuinely-covered NIST controls
    and 0 of 93 ISO controls as automated.
    """
    try:
        from app.services.control_identity import automated_canonical_ids
        return set(automated_canonical_ids(framework))
    except Exception:  # noqa: BLE001 — never let annotation break the catalogue
        return set()


def frameworks() -> list[dict[str, Any]]:
    out = []
    for key, meta in FRAMEWORKS.items():
        ctrls = _load(key)
        out.append({"framework": key, "label": meta["label"], "authority": meta["authority"],
                    "control_count": len(ctrls),
                    "families": sorted({c["family"] for c in ctrls})})
    return out


def controls(framework: str, family: str | None = None,
             _raw: bool = False) -> list[dict[str, Any]]:
    rows = _load(framework)
    if family:
        rows = [c for c in rows if c.get("family") == family or c.get("family_id") == family]
    if _raw:
        # Used by control_identity to read catalogue ids without recursing back
        # into the automation lookup it is itself computing.
        return list(rows)
    auto = _automated_ids(_key(framework) or framework)
    return [{**c, "automated": c["id"] in auto} for c in rows]


def families(framework: str) -> list[dict[str, Any]]:
    rows = _load(framework)
    fams: dict[str, dict[str, Any]] = {}
    for c in rows:
        f = fams.setdefault(c["family"], {"family": c["family"], "family_id": c.get("family_id"), "count": 0})
        f["count"] += 1
    return sorted(fams.values(), key=lambda x: x["family_id"] or x["family"])


def get(framework: str, control_id: str) -> dict[str, Any] | None:
    for c in _load(framework):
        if c["id"] == control_id:
            auto = _automated_ids(_key(framework) or framework)
            return {**c, "automated": control_id in auto}
    return None
