"""Prescriptive remediation optimizer (dependency-leverage based).

Distinct from the existing risk-based RemediationService: this ranks failing
controls by STRUCTURAL leverage from the dependency graph, not severity x asset
criticality. The two are complementary.

  leverage  – how many controls structurally depend on this one (dependency graph)
  unblocks  – of those, how many are currently failing (direct payoff)
  effort    – heuristic band: family base effort, lowered when a live connector can
              automate the family, raised for HIGH-baseline-only specialist controls
  baseline  – LOW-baseline controls are foundational -> prioritised
  action    – concrete next step from CIS Controls v8 safeguards (+ NIST guidance)

Knowledge bases (all free, fetched at build time):
  control_guidance.json  – NIST SP 800-53 supplemental guidance text
  control_baselines.json – NIST SP 800-53B LOW/MODERATE/HIGH tiers
  cis_mappings.json      – MITRE CIS-CCI mappings: NIST control -> CIS v8 safeguards
  family_effort.json     – curated per-family effort heuristics + connector coverage

Honest limits: effort is a generic heuristic, not organisation-specific; CIS
safeguards give direction, not tool-level runbooks (paywalled CIS Benchmarks).
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.services import dependency_graph as dg

_DATA = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


@lru_cache(maxsize=1)
def _kb():
    def load(n):
        try:
            return json.load(open(os.path.join(_DATA, n), encoding="utf-8"))
        except FileNotFoundError:
            return {}
    return {"guidance": load("control_guidance.json"),
            "baselines": load("control_baselines.json"),
            "cis": load("cis_mappings.json"),
            "effort": load("family_effort.json")}


def _family(cid: str) -> str:
    return cid.split("-")[0].upper() if "-" in cid else cid[:2].upper()


def _downstream_hard(control_id: str, max_depth: int = 4) -> set:
    seen, frontier = set(), [(control_id, 0)]
    while frontier:
        node, d = frontier.pop(0)
        if d >= max_depth:
            continue
        for e in dg.out_edges(node):
            if e["type"] != "hard":
                continue
            t = e["target"]
            if t not in seen and t != control_id:
                seen.add(t)
                frontier.append((t, d + 1))
    return seen


def _effort(cid: str, available_connectors: list[str]) -> dict[str, Any]:
    kb = _kb()["effort"]
    fam = _family(cid)
    base = kb.get("family_effort", {}).get(fam, 2)
    reasons = [f"family {fam} base effort {base}"]
    automatable = kb.get("family_automatable", {}).get(fam, False)
    conn_fams = kb.get("connector_families", {})
    covered = automatable and any(fam in conn_fams.get(c.upper(), []) for c in (available_connectors or []))
    if covered:
        base = max(1, base - 1)
        reasons.append("a connected source can automate this family (-1)")
    tiers = _kb()["baselines"].get(cid, [])
    if tiers == ["HIGH"]:
        base = min(3, base + 1)
        reasons.append("HIGH-baseline-only specialist control (+1)")
    band = {1: "Low", 2: "Medium", 3: "High"}[base]
    return {"band": band, "score": base, "automatable": covered, "reasons": reasons}


def _failing_from_attestations(db: Session, tenant_id: str, framework: str) -> list[str]:
    from app.models import ControlAttestation
    rows = db.execute(select(ControlAttestation).where(
        ControlAttestation.tenant_id == tenant_id,
        ControlAttestation.framework == framework)).scalars().all()
    return [r.control_id for r in rows if r.status.value == "non_compliant"]


def plan(db: Session, tenant_id: str, framework: str,
         failing_controls: list[str] | None = None,
         available_connectors: list[str] | None = None) -> dict[str, Any]:
    kb = _kb()
    failing = [c.upper() for c in (failing_controls or [])]
    if not failing:
        failing = _failing_from_attestations(db, tenant_id, framework)
    failing_set = set(failing)
    conns = available_connectors or []

    items = []
    for cid in failing:
        downstream = _downstream_hard(cid)
        unblocks = sorted(downstream & failing_set)
        leverage = len(downstream)
        eff = _effort(cid, conns)
        tiers = kb["baselines"].get(cid, [])
        baseline_bonus = 2 if "LOW" in tiers else 1 if "MODERATE" in tiers else 0
        score = round((leverage + 3 * len(unblocks) + baseline_bonus) / eff["score"], 2)
        cis = kb["cis"].get(cid) or kb["cis"].get(_family(cid)) or []
        items.append({
            "control_id": cid, "leverage": leverage, "unblocks": unblocks,
            "unblocks_count": len(unblocks), "effort": eff["band"],
            "effort_detail": eff["reasons"], "baseline": tiers or ["\u2014"],
            "priority_score": score,
            "next_action": (cis[0]["cis_title"] if cis else None),
            "cis_safeguards": cis[:3], "guidance": kb["guidance"].get(cid, "")[:240],
        })
    items.sort(key=lambda x: (-x["priority_score"], -x["leverage"], x["control_id"]))
    for i, it in enumerate(items, 1):
        it["rank"] = i

    return {
        "framework": framework, "failing_count": len(failing),
        "connectors_considered": conns,
        "quick_wins": [i["control_id"] for i in items if i["effort"] == "Low" and i["priority_score"] >= 2][:5],
        "highest_leverage": [i["control_id"] for i in sorted(items, key=lambda x: -x["leverage"])[:5]],
        "roadmap": items,
        "method": ("priority = (leverage + 3x current-unblocks + baseline) / effort. "
                   "Leverage from dependency graph; effort from family heuristics + connector coverage; "
                   "actions from CIS Controls v8. Effort is a generic estimate, not organisation-specific."),
    }


def detail(db: Session, tenant_id: str, framework: str, control_id: str,
           available_connectors: list[str] | None = None) -> dict[str, Any]:
    kb = _kb()
    cid = control_id.upper()
    downstream = _downstream_hard(cid)
    eff = _effort(cid, available_connectors or [])
    cis = kb["cis"].get(cid) or kb["cis"].get(_family(cid)) or []
    return {
        "control_id": cid, "framework": framework,
        "leverage": len(downstream), "downstream_controls": sorted(downstream),
        "effort": eff, "baseline": kb["baselines"].get(cid, []),
        "guidance": kb["guidance"].get(cid, ""), "cis_safeguards": cis,
        "prerequisites": [e["source"] for e in dg.in_edges(cid) if e["type"] == "hard"],
    }
