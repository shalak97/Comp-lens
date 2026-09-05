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
import logging
import os
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ControlAttestation, EvidenceConceptHit
from app.services import evidence_graph as evg

logger = logging.getLogger(__name__)

_POLICY: dict | None = None


def policy() -> dict:
    global _POLICY
    if _POLICY is None:
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "evidence_policy.json")
        with open(path, encoding="utf-8") as fh:
            _POLICY = json.load(fh)
    return _POLICY


def _control_concepts(control_id: str, framework: str) -> list[str]:
    """concept ids whose lexicon mapping includes this control.

    Canonicalised on both sides: the lexicon writes an enhancement `AC-2(1)`
    while callers may pass the dotted `AC-2.1`, and comparing them raw returned
    no concepts — reported as `not_assessed` for a control that does have
    evidence.
    """
    from app.services.control_identity import canonical_control_id

    want = canonical_control_id(control_id)
    out = []
    for c in evg.lexicon():
        for m in c.get("controls", []):
            if (canonical_control_id(m["control_id"]) == want
                    and m["framework"] == framework):
                out.append(c["id"])
    return out


def _effective_rules(control_id: str, framework: str, concept_id: str) -> dict:
    p = policy()
    rules = dict(p["default"])
    rules.update(p.get("by_concept", {}).get(concept_id, {}))
    rules.update(p.get("by_control", {}).get(f"{framework}:{control_id}", {}))
    return rules


def _age_days(dt) -> float | None:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return (datetime.now(UTC) - dt).total_seconds() / 86400.0


def evaluate(db: Session, tenant_id: str, framework: str, control_id: str) -> dict[str, Any]:
    concepts = _control_concepts(control_id, framework)
    hits: list[EvidenceConceptHit] = []
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

    result = {**_evaluate_builtin(control_id, framework, hits, att), "engine": "builtin"}
    try:
        from app.services.crosswalk import mapped_controls
        if result.get("satisfied"):
            result["propagated_to"] = mapped_controls(control_id, framework)[:10]
    except Exception:
        pass
    return result


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


def _evaluate_builtin(control_id, framework, hits, att) -> dict[str, Any]:
    reasons, qualifying = [], []
    for h in hits:
        r = _effective_rules(control_id, framework, h.concept_id)
        age = _age_days(h_updated(h))
        decay = _decay_factor(age)
        eff_conf = float(h.confidence or 0) * decay
        ok = True
        if r["require_confirmation"] and not h.confirmed:
            ok = False
            reasons.append(f"{h.concept_id}: hit not confirmed")
        if eff_conf < r["min_confidence"]:
            if decay < 1.0:
                reasons.append(f"{h.concept_id}: decayed confidence {eff_conf:.2f} (age {age:.0f}d) < {r['min_confidence']}")
            else:
                reasons.append(f"{h.concept_id}: confidence {h.confidence:.2f} < {r['min_confidence']}")
            ok = False
        if r["max_age_days"] is not None and age is not None and age > r["max_age_days"]:
            ok = False
            reasons.append(f"{h.concept_id}: evidence is {age:.0f} days old (> {r['max_age_days']})")
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
        # A sign-off ages like everything else. Automated evidence is aged twice
        # here — decay, then a hard max_age_days rejection — and this branch had
        # neither, so a five-year-old attestation satisfied the control forever.
        # Worse, it is reached only AFTER every piece of automated evidence has
        # been rejected as too old or too weak: the staler the machine evidence,
        # the more likely the answer came from the one path with no freshness
        # rule at all.
        rules = _effective_rules(control_id, framework, "")
        att_age = _age_days(att.updated_at)
        max_age = rules.get("max_age_days")
        if max_age is not None and att_age is not None and att_age > max_age:
            reasons.append(
                f"attestation is {att_age:.0f} days old (> {max_age}); a sign-off "
                f"has to be renewed to keep standing as evidence")
        else:
            age_note = f" (signed off {att_age:.0f} days ago)" if att_age is not None else ""
            return {"status": "compliant", "satisfied": True,
                    "reason": ("Met via human attestation (no qualifying automated "
                               f"evidence){age_note}."),
                    "attestation_age_days": (round(att_age, 1) if att_age is not None
                                             else None),
                    "qualifying_concepts": [], "notes": reasons}
    if hits or att:
        return {"status": "insufficient_evidence", "satisfied": False,
                "reason": ("Evidence and/or attestation exist but do not meet policy "
                           "thresholds."),
                "qualifying_concepts": [], "notes": reasons}
    return {"status": "not_assessed", "satisfied": False,
            "reason": "No evidence or attestation on record.",
            "qualifying_concepts": [], "notes": []}


def h_updated(h):
    # ingestion timestamp = the hit's created_at
    return getattr(h, "created_at", None)


def _decay_factor(age_days):
    """Temporal decay: full weight until full_until_days, linear to 0 at zero_at_days."""
    cfg = policy().get("decay", {})
    if not cfg.get("enabled") or age_days is None:
        return 1.0
    full = cfg.get("full_until_days", 180)
    zero = cfg.get("zero_at_days", 365)
    if age_days <= full:
        return 1.0
    if age_days >= zero:
        return 0.0
    return max(0.0, 1.0 - (age_days - full) / float(zero - full))


def _evaluate_opa(opa_url: str, facts: dict) -> dict | None:
    """Ask OPA for the decision, or return None so the builtin engine answers.

    The fallback is deliberate — an OPA blip must not fail an assessment — but
    it used to be silent, so an operator who configured OPA precisely to
    centralise policy could be served locally-computed decisions indefinitely
    without a single log line. The caller stamps `engine` on the result either
    way; this makes the switch visible in logs too.

    Not routed through ResilientClient: OPA is normally a sidecar on localhost,
    which that client's SSRF guard exists to refuse.
    """
    try:
        import requests

        from app.config import settings
        pkg = getattr(settings, "opa_package", "evidence_compliance")
        url = opa_url.rstrip("/") + f"/v1/data/{pkg}/decision"
        r = requests.post(url, json={"input": facts}, timeout=8)
        if r.status_code == 200:
            return r.json().get("result")
        logger.warning("OPA at %s answered %s; falling back to the builtin engine",
                       opa_url, r.status_code)
    except Exception as exc:  # noqa: BLE001 — any OPA problem falls back, loudly
        logger.warning("OPA at %s unreachable (%s: %s); falling back to the builtin engine",
                       opa_url, type(exc).__name__, exc)
    return None
