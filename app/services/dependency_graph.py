"""Control dependency graph — merges three edge sources with provenance & typing.

Edge semantics: source -> target means "if `source` degrades, `target` is affected".

  - curated      (HARD): hand-authored causal dependencies; the ONLY edges that
                         propagate a *failure* cascade. From control_dependencies.json.
  - shared_concept (SOFT): two controls map to the same evidence concept (lexicon).
                         Recorded as weakening influence only; does not recurse.
  - nist_related (SOFT): NIST 800-53 'related' links — associative, dense, lowest
                         weight; weakening influence only, does not recurse.

This typing is the core remediation for "related != depends-on": only curated
hard edges can cause a downstream control to be reported as failed.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any, Dict, List

from app.services import evidence_graph as evg

_DATA = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

SOFT_WEIGHT_NIST = 0.25
SOFT_WEIGHT_CONCEPT = 0.5


def _load(name: str) -> Any:
    with open(os.path.join(_DATA, name), encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def _graph() -> Dict[str, List[Dict[str, Any]]]:
    """adjacency: {source_control: [edge,...]} where edge has target/type/weight/provenance/rationale."""
    adj: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def put(src, tgt, etype, weight, prov, rationale):
        if src == tgt:
            return
        bucket = adj.setdefault(src, {})
        cur = bucket.get(tgt)
        # precedence: hard always wins; else keep the higher weight
        if cur is None or (etype == "hard" and cur["type"] != "hard") or \
           (etype == cur["type"] and weight > cur["weight"]):
            bucket[tgt] = {"target": tgt, "type": etype, "weight": round(weight, 3),
                           "provenance": prov, "rationale": rationale}

    # 1) curated hard edges
    for e in _load("control_dependencies.json").get("edges", []):
        put(e["source"], e["target"], "hard", float(e.get("weight", 0.8)),
            "curated", e.get("rationale", ""))

    # 2) shared-concept soft edges (bidirectional)
    concept_controls: Dict[str, set] = {}
    for c in evg.lexicon():
        nist = [m["control_id"] for m in c.get("controls", []) if m["framework"] == "NIST_800_53"]
        for cid in nist:
            concept_controls.setdefault(c["id"], set()).add(cid)
    for concept, ctrls in concept_controls.items():
        ctrls = sorted(ctrls)
        for i, a in enumerate(ctrls):
            for b in ctrls[i + 1:]:
                r = f"Both map to evidence concept '{concept}'."
                put(a, b, "soft", SOFT_WEIGHT_CONCEPT, "shared_concept", r)
                put(b, a, "soft", SOFT_WEIGHT_CONCEPT, "shared_concept", r)

    # 3) NIST related soft edges (bidirectional, lowest weight)
    try:
        for src, targets in _load("nist_related.json").items():
            for tgt in targets:
                put(src, tgt, "soft", SOFT_WEIGHT_NIST, "nist_related",
                    "NIST 800-53 lists these as related controls.")
    except FileNotFoundError:
        pass

    return {src: list(b.values()) for src, b in adj.items()}


def out_edges(control_id: str) -> List[Dict[str, Any]]:
    """Controls affected if `control_id` degrades (downstream dependents)."""
    return _graph().get(control_id, [])


def in_edges(control_id: str) -> List[Dict[str, Any]]:
    """Controls that `control_id` depends on (upstream prerequisites)."""
    out = []
    for src, edges in _graph().items():
        for e in edges:
            if e["target"] == control_id:
                out.append({"source": src, "target": control_id,
                            "type": e["type"], "weight": e["weight"],
                            "provenance": e["provenance"], "rationale": e["rationale"]})
    return out


def stats() -> Dict[str, int]:
    g = _graph()
    by_type: Dict[str, int] = {}
    total = 0
    for edges in g.values():
        for e in edges:
            by_type[e["provenance"]] = by_type.get(e["provenance"], 0) + 1
            total += 1
    return {"nodes": len(g), "edges": total, **by_type}
