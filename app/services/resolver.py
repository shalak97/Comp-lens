"""Ontology-driven resolver.

Given an occasion (tenant, framework, control, asset, available connectors) this
decides WHICH code module satisfies the control, across three plane types in
preference order:

  telemetry  -> a connector produces a signal, an evaluator judges it
  document   -> the evidence pipeline has concept hits mapping to the control
  attestation-> human-recorded status (the floor; never silently skipped)

It then (optionally) EXECUTES the chosen module and records an auditable
RoutingDecision explaining what was chosen and why the alternatives were skipped.

The schema lives in app/data/telemetry_ontology.json (planes + module
capabilities) and app/data/control_bindings.json (per-control strategy chains),
so routing is declarative data, not logic buried in code.

'DEMO' acts as a wildcard *simulation* producer: if it is in the caller's
available-connectors list it can stand in for any telemetry producer, so the full
collect->evaluate path can be exercised before real connector credentials exist.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors.base import ConnectorError
from app.connectors.registry import registry
from app.models import (AssessmentRequest, ControlAttestation, EvidenceConceptHit,
                        RoutingDecision)
from app.services.assessment import AssessmentService

_DATA = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
_ontology: Optional[dict] = None
_bindings: Optional[dict] = None


def _load(name: str) -> dict:
    with open(os.path.join(_DATA, name), encoding="utf-8") as fh:
        return json.load(fh)


def ontology() -> dict:
    global _ontology
    if _ontology is None:
        _ontology = _load("telemetry_ontology.json")
    return _ontology


def bindings() -> dict:
    global _bindings
    if _bindings is None:
        _bindings = _load("control_bindings.json")
    return _bindings


def planes() -> dict:
    return ontology().get("planes", {})


def control_binding(framework: str, control_id: str) -> Optional[dict]:
    return bindings().get("frameworks", {}).get(framework, {}).get(control_id)


# ------------------------------------------------------------------ producer selection
def _connector_ok(source_system: str) -> bool:
    try:
        return registry.get(source_system).healthcheck()
    except (ConnectorError, Exception):
        return False


def _pick_producer(producers: List[str], available: List[str]):
    """Return (source_system_to_use, display_label) or (None, None)."""
    for p in producers:
        if p in available and _connector_ok(p):
            return p, p
    if "DEMO" in available and _connector_ok("DEMO"):
        return "DEMO", "DEMO (simulation)"
    return None, None


# ------------------------------------------------------------------ resolve
def resolve(db: Session, tenant_id: str, framework: str, control_id: str,
            asset: Optional[Dict[str, Any]] = None,
            available_connectors: Optional[List[str]] = None,
            dry_run: bool = False) -> Dict[str, Any]:
    asset = asset or {}
    available = available_connectors or []
    asset_type = asset.get("type", "*")
    asset_id = asset.get("id")
    binding = control_binding(framework, control_id)
    if not binding:
        raise ValueError(f"No routing binding for {control_id} in {framework}")

    skipped: List[Dict[str, Any]] = []
    chosen: Optional[Dict[str, Any]] = None
    status: Optional[str] = None
    reason: Optional[str] = None
    finding_id: Optional[str] = None
    extra: Dict[str, Any] = {}

    for s in sorted(binding["strategies"], key=lambda x: x.get("preference", 100)):
        stype = s["type"]
        ats = s.get("asset_types", ["*"])
        if "*" not in ats and asset_type != "*" and asset_type not in ats:
            skipped.append({"type": stype, "plane": s["plane"],
                            "reason": f"asset_type '{asset_type}' not in {ats}"})
            continue

        if stype == "telemetry":
            prod, label = _pick_producer(s["producers"], available)
            if not prod:
                skipped.append({"type": stype, "plane": s["plane"], "signal": s["signal"],
                                "reason": f"no available/healthy producer in {s['producers']}"})
                continue
            chosen = {"type": stype, "plane": s["plane"], "signal": s["signal"],
                      "module": label, "eval_control": s["eval_control"]}
            if not dry_run:
                req = AssessmentRequest(tenant_id=tenant_id, framework=framework,
                                        control_id=s["eval_control"], source_system=prod,
                                        asset_id=asset_id, params=asset.get("params", {}))
                f = AssessmentService(db).run_single(req)
                status = f.status.value if hasattr(f.status, "value") else str(f.status)
                reason = f.description
                finding_id = f.finding_id
            break

        if stype == "document":
            hits = db.execute(
                select(EvidenceConceptHit).where(
                    EvidenceConceptHit.tenant_id == tenant_id,
                    EvidenceConceptHit.concept_id.in_(s.get("concepts", [])))
            ).scalars().all()
            if not hits:
                skipped.append({"type": stype, "plane": s["plane"],
                                "reason": "no evidence hits for mapped concepts"})
                continue
            confirmed = [h for h in hits if h.confirmed]
            chosen = {"type": stype, "plane": s["plane"], "signal": s["signal"], "module": "EVIDENCE",
                      "concepts": sorted({h.concept_id for h in hits})}
            if not dry_run:
                status = "compliant" if confirmed else "pending_review"
                reason = f"{len(confirmed)} confirmed / {len(hits)} total evidence hit(s)"
                extra = {"evidence_hits": [{"concept": h.concept_id, "confirmed": bool(h.confirmed),
                                            "quote": (h.quote or "")[:160]} for h in hits[:8]]}
            break

        if stype == "attestation":
            att = db.execute(
                select(ControlAttestation).where(
                    ControlAttestation.tenant_id == tenant_id,
                    ControlAttestation.framework == framework,
                    ControlAttestation.control_id == control_id)
            ).scalar_one_or_none()
            chosen = {"type": stype, "plane": s["plane"], "signal": s["signal"], "module": "ATTEST"}
            if not dry_run:
                status = att.status.value if att else "not_assessed"
                reason = ("human attestation on record" if att
                          else "no telemetry or evidence available — requires attestation")
            break

    if chosen is None:  # defensive: the attestation floor should always catch
        chosen = {"type": "attestation", "plane": "attestation_document",
                  "signal": "human_attestation", "module": "ATTEST"}
        status = None if dry_run else "not_assessed"
        reason = "fell through to attestation floor"

    rec = RoutingDecision(
        tenant_id=tenant_id, framework=framework, control_id=control_id,
        asset_type=asset_type, asset_id=asset_id, plane=chosen["plane"],
        strategy_type=chosen["type"], module=chosen.get("module"), status=status,
        reason=reason, executed=(not dry_run), dry_run=dry_run, skipped=skipped,
        finding_id=finding_id)
    db.add(rec)
    db.commit()
    db.refresh(rec)

    return {"decision_id": rec.id, "tenant_id": tenant_id, "framework": framework,
            "control_id": control_id, "asset_type": asset_type, "chosen": chosen,
            "status": status, "reason": reason, "executed": (not dry_run),
            "skipped": skipped, "finding_id": finding_id, **extra}


def list_decisions(db: Session, tenant_id: str, control_id: Optional[str] = None,
                   limit: int = 100) -> List[RoutingDecision]:
    stmt = select(RoutingDecision).where(RoutingDecision.tenant_id == tenant_id)
    if control_id:
        stmt = stmt.where(RoutingDecision.control_id == control_id)
    stmt = stmt.order_by(RoutingDecision.created_at.desc()).limit(limit)
    return list(db.execute(stmt).scalars().all())
