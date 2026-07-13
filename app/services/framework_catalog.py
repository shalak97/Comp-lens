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


@cache
def _load(framework: str) -> list[dict[str, Any]]:
    meta = FRAMEWORKS.get(framework)
    if not meta:
        return []
    path = os.path.join(_DATA, meta["file"])
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def _automated_ids() -> set:
    """control_ids that have a live evaluator (auto-assessed)."""
    try:
        from app.policy.engine import CONTROL_CATALOG
        return set(CONTROL_CATALOG.keys())
    except Exception:
        return set()


def frameworks() -> list[dict[str, Any]]:
    out = []
    for key, meta in FRAMEWORKS.items():
        ctrls = _load(key)
        out.append({"framework": key, "label": meta["label"], "authority": meta["authority"],
                    "control_count": len(ctrls),
                    "families": sorted({c["family"] for c in ctrls})})
    return out


def controls(framework: str, family: str | None = None) -> list[dict[str, Any]]:
    auto = _automated_ids()
    rows = _load(framework)
    if family:
        rows = [c for c in rows if c.get("family") == family or c.get("family_id") == family]
    # annotate automation flag
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
            return {**c, "automated": control_id in _automated_ids()}
    return None
