"""Counterfactual compliance simulator — the "compliance blast radius".

Given hypothetical control failures, propagate the impact through the dependency
graph and report which controls are structurally affected, how badly, and via
which path. Remediations baked in:

  * Only HARD (curated) edges propagate a *failure* and recurse — soft edges add
    a leaf "weakened/at-risk" signal but never cascade further (prevents the
    associative-link explosion).
  * Depth-bounded BFS with a visited set (cycle-safe) and per-node dedup keeping
    the strongest impact.
  * Graded severity (failed / weakened / at_risk) instead of binary.
  * Every affected control carries its path, the edge rationale, and provenance.
  * exclude_edges + min_weight let the user prune untrusted edges.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.services import dependency_graph as dg

# severity thresholds
FAILED_AT = 0.5
WEAKENED_AT = 0.3
PRUNE_BELOW = 0.15


def _level(sev: float, edge_type: str) -> str:
    if edge_type == "hard" and sev >= FAILED_AT:
        return "failed"
    if sev >= WEAKENED_AT:
        return "weakened"
    return "at_risk"


def _resolve_seeds(framework: str, changes: List[Dict[str, Any]]):
    """Map each requested change onto controls present in the NIST-keyed graph.

    Remediations:
      * validates `state` (unknown -> degraded, with a warning)
      * bridges non-NIST controls to NIST equivalents via the shared-concept
        crosswalk so ISO/other frameworks return a real answer instead of 0
      * warns when a seed has no downstream dependencies (so an empty blast
        radius is never silently misread as "safe")
    """
    seeds: Dict[str, float] = {}
    warnings: List[str] = []
    for ch in changes:
        cid = ch.get("control_id", "").strip()
        if not cid:
            continue
        state = ch.get("state", "failed")
        if state not in ("failed", "degraded"):
            warnings.append(f"{cid}: unknown state '{state}', treated as 'degraded'.")
            state = "degraded"
        sev = 1.0 if state == "failed" else 0.6

        targets = [cid]
        if framework != "NIST_800_53":
            try:
                from app.services.crosswalk import mapped_controls
                nist = [m["control_id"] for m in mapped_controls(cid, framework)
                        if m["framework"] == "NIST_800_53"]
            except Exception:
                nist = []
            if nist:
                warnings.append(f"Bridged {framework} control {cid} to NIST "
                                f"{nist} via shared concepts; affected controls below are NIST IDs.")
                targets = nist
            else:
                warnings.append(f"{cid}: no NIST mapping found — dependency simulation "
                                "is only available for controls reachable from the NIST catalog.")
                targets = []

        for t in targets:
            seeds[t] = max(seeds.get(t, 0.0), sev)
            if not dg.out_edges(t):
                warnings.append(f"{t}: no downstream dependencies in the graph "
                                "(isolated, leaf, or unrecognized control) — empty cascade is expected.")
    return seeds, warnings


def simulate(framework: str, changes: List[Dict[str, Any]],
             max_depth: int = 3, min_weight: float = 0.0,
             exclude_edges: Optional[List[List[str]]] = None) -> Dict[str, Any]:
    """changes: [{control_id, state}] (state failed|degraded). Returns blast radius."""
    max_depth = max(0, min(int(max_depth), 10))   # clamp: safety against runaway traversal
    excl = {tuple(e) for e in (exclude_edges or []) if isinstance(e, (list, tuple)) and len(e) == 2}
    seeds, warnings = _resolve_seeds(framework, changes)

    # best impact per control: {cid: (severity, level, path, edge)}
    impact: Dict[str, Dict[str, Any]] = {}
    # BFS frontier of (control, severity, depth, path) — only hard-failed nodes expand
    frontier: List[Tuple[str, float, int, List[str]]] = [
        (cid, sev, 0, [cid]) for cid, sev in seeds.items()]

    while frontier:
        node, sev, depth, path = frontier.pop(0)
        if depth >= max_depth:
            continue
        for e in dg.out_edges(node):
            if e["weight"] < min_weight:
                continue
            if (node, e["target"]) in excl:
                continue
            prop = sev * e["weight"]
            if prop < PRUNE_BELOW:
                continue
            tgt = e["target"]
            if tgt in seeds:           # don't re-impact a directly-changed control
                continue
            lvl = _level(prop, e["type"])
            prev = impact.get(tgt)
            if prev is None or prop > prev["severity"]:
                impact[tgt] = {"control_id": tgt, "severity": round(prop, 3),
                               "impact": lvl, "via": path + [tgt],
                               "edge_type": e["type"], "provenance": e["provenance"],
                               "rationale": e["rationale"]}
            # only genuine hard failures cascade further (remediation: no soft explosion)
            if e["type"] == "hard" and lvl == "failed" and tgt not in path:
                frontier.append((tgt, prop, depth + 1, path + [tgt]))

    cascade = sorted(impact.values(), key=lambda x: (-x["severity"], x["control_id"]))

    # blast radius summary
    by_level: Dict[str, int] = {}
    for c in cascade:
        by_level[c["impact"]] = by_level.get(c["impact"], 0) + 1

    return {
        "framework": framework,
        "directly_changed": [{"control_id": c["control_id"],
                              "state": c.get("state", "failed")} for c in changes],
        "blast_radius": {"total_affected": len(cascade), "by_impact": by_level,
                         "max_depth": max_depth},
        "cascade": cascade,
        "warnings": warnings,
        "explanation": _explain(changes, cascade),
    }


def _explain(changes, cascade) -> str:
    if not cascade:
        return ("No downstream controls structurally depend on the changed control(s). "
                "Either it has no curated dependents, or you excluded the edges.")
    chg = ", ".join(c["control_id"] for c in changes)
    failed = [c["control_id"] for c in cascade if c["impact"] == "failed"]
    weak = [c["control_id"] for c in cascade if c["impact"] != "failed"]
    parts = [f"Changing {chg} structurally affects {len(cascade)} control(s)."]
    if failed:
        parts.append(f"Hard-dependent and likely INVALIDATED even if their own test stays green: "
                     f"{', '.join(failed[:8])}{'…' if len(failed) > 8 else ''}.")
    if weak:
        parts.append(f"Weakened / at-risk (related or shared-evidence): "
                     f"{', '.join(weak[:8])}{'…' if len(weak) > 8 else ''}.")
    return " ".join(parts)


def fragility(db: Session, tenant_id: str, framework: str, control_id: str) -> Dict[str, Any]:
    """Is this control green-but-structurally-at-risk? Checks its hard prerequisites'
    current compliance state via the evidence policy engine."""
    from app.services import evidence_policy
    prereqs = [e for e in dg.in_edges(control_id) if e["type"] == "hard"]
    weak = []
    for e in prereqs:
        pre = e["source"]
        try:
            d = evidence_policy.evaluate(db, tenant_id, framework, pre)
            if not d.get("satisfied"):
                weak.append({"prereq": pre, "status": d.get("status"),
                             "weight": e["weight"], "rationale": e["rationale"]})
        except Exception:
            continue
    return {
        "control_id": control_id, "framework": framework,
        "structurally_at_risk": bool(weak),
        "weak_prerequisites": sorted(weak, key=lambda x: -x["weight"]),
        "detail": (f"This control depends on {len(weak)} unsatisfied prerequisite(s); "
                   "its own evidence may not hold even if its direct test passes."
                   if weak else "All hard prerequisites are satisfied."),
    }
