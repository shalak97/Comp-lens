"""Compliance-as-code for evidence.

Treats every extracted concept hit as a fact and applies declarative rules to
decide whether evidence actually SATISFIES a control — instead of naively trusting
any hit. Mirrors the existing policy-engine pattern: a builtin Python evaluator by
default, or POST the facts to OPA (rego package `evidence_compliance`) when
settings.opa_url is configured. Policy lives in app/data/evidence_policy.json and is
expressed identically in app/policy/evidence_compliance.rego.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ControlAttestation, EvidenceConceptHit
from app.services import evidence_graph as evg

_POLICY: Optional[dict] = None


def policy() -> dict:
    global _POLICY
    if _POLICY is None:
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "evidence_policy.json")
        with open(path, encoding="utf-8") as fh:
            _POLICY = json.load(fh)
    return _POLICY


def _control_concepts(control_id: str, framework: str) -> List[str]:
    """concept ids whose lexicon mapping includes this control."""
    out = []
    for c in evg.lexicon():
        for m in c.get("controls", []):
            if m["control_id"] == control_id and m["framework"] == framework:
                out.append(c["id"])
    return out


def _effective_rules(control_id: str, framework: str, concept_id: str) -> dict:
    p = policy()
    rules = dict(p["default"])
    rules.update(p.get("by_concept", {}).get(concept_id, {}))
    rules.update(p.get("by_control", {}).get(f"{framework}:{control_id}", {}))
    return rules


def _age_days(dt) -> Optional[float]:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).total_seconds() / 86400.0


def evaluate(db: Session, tenant_id: str, framework: str, control_id: str) -> Dict[str, Any]:
    concepts = _control_concepts(control_id, framework)
    hits: List[EvidenceConceptHit] = []
    if concepts:
        hits = list(db.execute(select(EvidenceConceptHit).where(
            EvidenceConceptHit.tenant_id == tenant_id,
            EvidenceConceptHit.concept_id.in_(concepts))).scalars().all())
    att = db.execute(select(ControlAttestation).where(
        ControlAttestation.tenant_id == tenant_id,
        ControlAttestation.framework == framework,
        ControlAttestation.control_id == control_id)).scalar_one_or_none()

    # If OPA is configured, delegate (facts -> rego decision); else builtin rules.
    try:
        from app.config import settings
        opa = getattr(settings, "opa_url", None)
    except Exception:
        opa = None
    facts = _facts(control_id, framework, hits, att)
    if opa:
        d = _evaluate_opa(opa, facts)
        if d:
            return {**d, "facts": facts, "engine": "opa"}

    return {**_evaluate_builtin(control_id, framework, hits, att), "engine": "builtin"}


def _facts(control_id, framework, hits, att):
    return {
        "control_id": control_id, "framework": framework,
        "evidence_hits": [{
            "concept": h.concept_id, "confirmed": bool(h.confirmed),
            "confidence": float(h.confidence or 0), "method": h.method,
        } for h in hits],
        "attestation": ({"status": att.status.value, "owner": att.owner,
                         "age_days": _age_days(att.updated_at)} if att else None),
    }


def _evaluate_builtin(control_id, framework, hits, att) -> Dict[str, Any]:
    reasons, qualifying = [], []
    for h in hits:
        r = _effective_rules(control_id, framework, h.concept_id)
        age = _age_days(h_updated(h))
        ok = True
        if r["require_confirmation"] and not h.confirmed:
            ok = False; reasons.append(f"{h.concept_id}: hit not confirmed")
        if float(h.confidence or 0) < r["min_confidence"]:
            ok = False; reasons.append(f"{h.concept_id}: confidence {h.confidence:.2f} < {r['min_confidence']}")
        if r["max_age_days"] is not None and age is not None and age > r["max_age_days"]:
            ok = False; reasons.append(f"{h.concept_id}: evidence is {age:.0f} days old (> {r['max_age_days']})")
        if ok:
            need_owner = r["require_attestation_owner"]
            if need_owner and not (att and att.owner):
                reasons.append(f"{h.concept_id}: qualifying evidence found but an attestation owner sign-off is required")
            else:
                qualifying.append(h.concept_id)

    if qualifying:
        return {"status": "compliant", "satisfied": True,
                "reason": f"Evidence satisfies control via: {', '.join(sorted(set(qualifying)))}",
                "qualifying_concepts": sorted(set(qualifying)), "notes": reasons}
    if att and att.status.value == "compliant":
        return {"status": "compliant", "satisfied": True,
                "reason": "Met via human attestation (no qualifying automated evidence).",
                "qualifying_concepts": [], "notes": reasons}
    if hits:
        return {"status": "insufficient_evidence", "satisfied": False,
                "reason": "Evidence exists but does not meet policy thresholds.",
                "qualifying_concepts": [], "notes": reasons}
    return {"status": "not_assessed", "satisfied": False,
            "reason": "No evidence or attestation on record.",
            "qualifying_concepts": [], "notes": []}


def h_updated(h):
    # EvidenceConceptHit has no explicit timestamp; fall back to its document's.
    return getattr(h, "created_at", None)


def _evaluate_opa(opa_url: str, facts: dict) -> Optional[dict]:
    try:
        import requests
        from app.config import settings
        pkg = getattr(settings, "opa_package", "evidence_compliance")
        url = opa_url.rstrip("/") + f"/v1/data/{pkg}/decision"
        r = requests.post(url, json={"input": facts}, timeout=8)
        if r.status_code == 200:
            return r.json().get("result")
    except Exception:
        return None
    return None
