"""Export evidence + attestations as an OSCAL Assessment Results document.

OSCAL (NIST's Open Security Controls Assessment Language) is the interoperable
standard auditors and FedRAMP/CMMC tooling consume. We emit a minimal but valid
assessment-results object: each evidence concept hit becomes an `observation`
(with its verbatim quote as the relevant-evidence), and each control's policy
determination becomes a `finding`.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ControlAttestation, EvidenceConceptHit, EvidenceDocument
from app.services import evidence_policy


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _ctrl_to_oscal(control_id: str) -> str:
    # OSCAL control ids are lowercase, e.g. AC-2(7) -> ac-2.7 ; A.8.5 -> a.8.5
    return control_id.lower().replace("(", ".").replace(")", "")


def _reviewed_controls(assessed: list[str], unassessed: list[tuple[str, str]]) -> dict[str, Any]:
    """The scope this result speaks to.

    `control-selections` is required and an empty `include-controls` array is
    not a way to say "nothing" — so when no control could be assessed, the
    selection carries a description saying so instead of an empty list that a
    validator would reject and a reader would misread as "all controls".
    """
    if assessed:
        return {"control-selections": [
            {"description": "Controls for which a determination was reached.",
             "include-controls": [{"control-id": _ctrl_to_oscal(c)} for c in assessed]}]}
    return {"control-selections": [
        {"description": (
            "No control reached a determination in this assessment"
            + (f"; {len(unassessed)} had no evidence or attestation on record."
               if unassessed else "."))}]}


def export_assessment_results(db: Session, tenant_id: str, framework: str) -> dict[str, Any]:
    docs = {d.doc_id: d for d in db.execute(select(EvidenceDocument).where(
        EvidenceDocument.tenant_id == tenant_id)).scalars().all()}
    hits = list(db.execute(select(EvidenceConceptHit).where(
        EvidenceConceptHit.tenant_id == tenant_id)).scalars().all())
    atts = list(db.execute(select(ControlAttestation).where(
        ControlAttestation.tenant_id == tenant_id,
        ControlAttestation.framework == framework)).scalars().all())

    observations: list[dict[str, Any]] = []
    hit_obs: dict[str, str] = {}
    for h in hits:
        oid = str(uuid.uuid4())
        hit_obs[h.id] = oid
        d = docs.get(h.doc_id)
        observations.append({
            "uuid": oid,
            "title": f"Evidence: {h.concept_id}",
            "description": f"Concept '{h.concept_id}' detected via {h.method} "
                           f"(confidence {h.confidence:.2f}, "
                           f"{'confirmed' if h.confirmed else 'unconfirmed'}).",
            "methods": ["EXAMINE" if h.method != "llm" else "TEST"],
            "relevant-evidence": [{
                "description": (h.quote or "")[:600],
                "props": [
                    {"name": "source-document", "value": d.name if d else h.doc_id},
                    {"name": "confidence", "value": f"{h.confidence:.2f}"},
                    {"name": "confirmed", "value": str(bool(h.confirmed)).lower()},
                ] + ([{"name": "document-signature", "value": d.signature}] if d and d.signature else []),
            }],
            "collected": (h.created_at.isoformat() if h.created_at else _now()),
        })

    # findings: one per control that has evidence or an attestation
    candidate = {a.control_id for a in atts}
    # derive controls that any hit concept maps to (via the lexicon)
    from app.services import evidence_graph as evg
    concept_to_controls: dict[str, list] = {}
    for c in evg.lexicon():
        for m in c.get("controls", []):
            if m["framework"] == framework:
                concept_to_controls.setdefault(c["id"], []).append(m["control_id"])
    for h in hits:
        for cid in concept_to_controls.get(h.concept_id, []):
            candidate.add(cid)

    findings: list[dict[str, Any]] = []
    assessed: list[str] = []
    unassessed: list[tuple[str, str]] = []
    for cid in sorted(candidate):
        decision = evidence_policy.evaluate(db, tenant_id, framework, cid)

        # A control nothing was ever recorded against was not assessed, and an
        # OSCAL finding is an assertion. `state` admits only satisfied and
        # not-satisfied, so asserting anything here would say "we determined
        # this control is not met" about a control nobody looked at — in the
        # machine-readable package a regulator reads. It is left out of the
        # assessed scope below and reported as a gap instead.
        if decision["status"] == "not_assessed":
            unassessed.append((cid, decision["reason"]))
            continue

        rel_obs = [hit_obs[h.id] for h in hits
                   if cid in concept_to_controls.get(h.concept_id, [])]
        satisfied = bool(decision["satisfied"])
        assessed.append(cid)
        target_props = [{"name": "policy-status", "value": decision["status"]},
                        {"name": "engine", "value": decision.get("engine", "builtin")}]
        if not satisfied:
            # `insufficient_evidence` IS a determination — evidence was examined
            # and did not meet the policy threshold — so not-satisfied is the
            # honest state. But it is a different claim from "the control was
            # tested and the mechanism is broken", and an assessor reading this
            # is entitled to know which one they are looking at.
            target_props.append({
                "name": "determination-basis",
                "value": "evidence-examined-below-threshold",
                "remarks": ("Not satisfied on the strength of the evidence on "
                            "record, not on a direct test of the control."),
            })
        findings.append({
            "uuid": str(uuid.uuid4()),
            "title": f"{cid} — {decision['status']}",
            "description": decision["reason"],
            "target": {
                "type": "objective-id",
                "target-id": _ctrl_to_oscal(cid),
                "status": {"state": "satisfied" if satisfied else "not-satisfied"},
                "props": target_props,
            },
            "related-observations": [{"observation-uuid": o} for o in rel_obs],
        })

    return {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": f"Comp-Lens Evidence Assessment — {framework}",
                "last-modified": _now(),
                "version": "1.0",
                "oscal-version": "1.1.2",
                "props": [{"name": "tenant", "value": tenant_id},
                          {"name": "framework", "value": framework}],
            },
            "import-ap": {"href": "#comp-lens-assessment-plan"},
            "results": [{
                "uuid": str(uuid.uuid4()),
                "title": "Automated evidence + attestation assessment",
                "description": "Generated by Comp-Lens compliance-as-code evidence engine.",
                "start": _now(),
                # Required by the model, and load-bearing here: it states which
                # controls this result actually speaks to. Controls with nothing
                # on record are deliberately outside it rather than carrying a
                # fabricated not-satisfied finding.
                "reviewed-controls": _reviewed_controls(assessed, unassessed),
                "observations": observations,
                "findings": findings,
                # The gap, stated rather than implied by silence. An assessor
                # comparing this against the catalog can see exactly which
                # controls produced no determination and why.
                "props": [{"name": "unassessed-control", "value": _ctrl_to_oscal(cid),
                           "remarks": reason}
                          for cid, reason in unassessed],
            }],
        }
    }
