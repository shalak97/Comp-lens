"""Cross-framework control crosswalk, derived from the shared concept lexicon.

Two controls are considered equivalent if they are mapped to one or more of the
same concepts in the evidence lexicon. That makes evidence framework-agnostic:
proving a concept satisfies the control in every framework that concept maps to.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, List

from app.services import evidence_graph as evg


@lru_cache(maxsize=1)
def _index():
    """Build {(.framework,control): set(concepts)} and concept->controls."""
    ctrl_concepts: Dict[tuple, set] = {}
    for c in evg.lexicon():
        for m in c.get("controls", []):
            key = (m["framework"], m["control_id"])
            ctrl_concepts.setdefault(key, set()).add(c["id"])
    return ctrl_concepts


def mapped_controls(control_id: str, framework: str) -> List[Dict[str, Any]]:
    """Controls in OTHER frameworks that share >=1 concept with this control."""
    idx = _index()
    src = idx.get((framework, control_id), set())
    if not src:
        return []
    out = []
    for (fw, cid), concepts in idx.items():
        if fw == framework and cid == control_id:
            continue
        shared = src & concepts
        if shared:
            out.append({"framework": fw, "control_id": cid,
                        "shared_concepts": sorted(shared),
                        "overlap": len(shared)})
    out.sort(key=lambda x: (-x["overlap"], x["framework"], x["control_id"]))
    return out
