"""Audit management service: lifecycle, checklist, PBC requests, export package."""
from __future__ import annotations

import builtins
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit_models import (
    Audit,
    AuditControl,
    AuditIn,
    AuditPatch,
    ControlReviewPatch,
    EvidenceRequest,
    EvidenceRequestIn,
    EvidenceRequestPatch,
)
from app.frameworks import crosswalk_for
from app.policy.engine import CONTROL_CATALOG


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


def _controls_for_framework(framework: str) -> list[dict[str, str]]:
    """Which controls are in scope for this framework, from the live catalog."""
    fw = framework.upper().replace(" ", "").replace("-", "")
    out = []
    for cid, meta in CONTROL_CATALOG.items():
        cross = crosswalk_for(cid)
        # NIST is the native catalog; for others, include controls that crosswalk to them
        if fw.startswith("NIST") or any(fw in k.upper().replace(" ", "").replace("-", "") for k in cross):
            out.append({"control_id": cid, "title": meta.get("title", cid)})
    return out or [{"control_id": cid, "title": meta.get("title", cid)}
                   for cid, meta in CONTROL_CATALOG.items()]


class AuditService:
    def __init__(self, db: Session):
        self.db = db

    # ── audit CRUD + lifecycle ──
    def _ser(self, a: Audit, with_progress: bool = True) -> dict[str, Any]:
        d = {"id": a.id, "name": a.name, "framework": a.framework,
             "auditor": a.auditor, "status": a.status,
             "period_start": _iso(a.period_start), "period_end": _iso(a.period_end),
             "created_at": _iso(a.created_at), "updated_at": _iso(a.updated_at)}
        if with_progress:
            d.update(self._progress(a.id, a.tenant_id))
        return d

    def _progress(self, audit_id: str, tenant_id: str) -> dict[str, Any]:
        # tenant_id was accepted here but not applied, which was safe only
        # because every current caller verifies audit ownership first. That is
        # an invariant held by convention at a distance; scoping the queries
        # makes it hold locally instead.
        ctrls = self.db.execute(select(AuditControl).where(
            AuditControl.audit_id == audit_id,
            AuditControl.tenant_id == tenant_id)).scalars().all()
        reqs = self.db.execute(select(EvidenceRequest).where(
            EvidenceRequest.audit_id == audit_id,
            EvidenceRequest.tenant_id == tenant_id)).scalars().all()
        total = len(ctrls)
        approved = sum(1 for c in ctrls if c.review_state == "approved")
        rejected = sum(1 for c in ctrls if c.review_state == "rejected")
        reviewed = sum(1 for c in ctrls if c.review_state in ("approved", "rejected", "exception"))
        open_reqs = sum(1 for r in reqs if r.state == "open")
        return {"controls_total": total, "controls_approved": approved,
                "controls_rejected": rejected,
                "readiness_pct": round(100 * reviewed / total) if total else 0,
                "approval_pct": round(100 * approved / total) if total else 0,
                "evidence_requests_total": len(reqs), "evidence_requests_open": open_reqs}

    def list(self, tenant_id: str, limit: int | None = None,
             offset: int = 0) -> builtins.list[dict[str, Any]]:
        from app import pagination

        stmt = pagination.apply(
            select(Audit).where(Audit.tenant_id == tenant_id)
            .order_by(Audit.created_at.desc(), Audit.id),
            limit, offset)
        return [self._ser(a) for a in self.db.execute(stmt).scalars().all()]

    def get(self, tenant_id: str, audit_id: str) -> dict[str, Any] | None:
        a = self.db.get(Audit, audit_id)
        if not a or a.tenant_id != tenant_id:
            return None
        return self._ser(a)

    def create(self, tenant_id: str, data: AuditIn) -> dict[str, Any]:
        a = Audit(tenant_id=tenant_id, name=data.name, framework=data.framework,
                  period_start=data.period_start, period_end=data.period_end,
                  auditor=data.auditor, status="planning")
        self.db.add(a)
        self.db.commit()
        self.db.refresh(a)
        # auto-build the control checklist for the framework
        self._seed_controls(a)
        return self._ser(a)

    def _seed_controls(self, a: Audit) -> None:
        for c in _controls_for_framework(a.framework):
            self.db.add(AuditControl(audit_id=a.id, tenant_id=a.tenant_id,
                                     control_id=c["control_id"], title=c["title"],
                                     review_state="not_started"))
        self.db.commit()
        self.refresh_posture(a.tenant_id, a.id)

    def update(self, tenant_id: str, audit_id: str, patch: AuditPatch) -> dict[str, Any] | None:
        a = self.db.get(Audit, audit_id)
        if not a or a.tenant_id != tenant_id:
            return None
        for k, v in patch.model_dump(exclude_unset=True).items():
            if v is not None and hasattr(v, "value"):
                v = v.value
            setattr(a, k, v)
        a.updated_at = _now()
        self.db.commit()
        self.db.refresh(a)
        return self._ser(a)

    def delete(self, tenant_id: str, audit_id: str) -> bool:
        a = self.db.get(Audit, audit_id)
        if not a or a.tenant_id != tenant_id:
            return False
        for model in (AuditControl, EvidenceRequest):
            for row in self.db.execute(select(model).where(model.audit_id == audit_id)).scalars().all():
                self.db.delete(row)
        self.db.delete(a)
        self.db.commit()
        return True

    # ── live posture: pull current pass/fail into each control's auto_status ──
    def refresh_posture(self, tenant_id: str, audit_id: str) -> dict[str, Any] | None:
        """Best-effort: map current findings onto the audit's controls.

        Returns None when the audit does not belong to this tenant, so the
        route can 404 the same way get()/export_package() do.

        The ownership check is load-bearing, not decorative. The caller's
        authorize_tenant() only proves the principal may act as *their own*
        tenant; it says nothing about who owns the audit named in the URL.
        Without this, an operator of tenant A could pass tenant B's audit_id
        and write A's control statuses onto B's audit rows below — a
        cross-tenant write that silently corrupts another customer's audit
        evidence.
        """
        a = self.db.get(Audit, audit_id)
        if not a or a.tenant_id != tenant_id:
            return None
        latest: dict[str, str] = {}
        try:
            from app.middleware_models import StoredEvent
            evs = self.db.execute(select(StoredEvent).where(StoredEvent.tenant_id == tenant_id)
                                  .order_by(StoredEvent.received_at.desc())).scalars().all()
            for e in evs:
                latest.setdefault(e.control_id, e.status)
        except Exception:
            pass
        # tenant_id is redundant given the ownership check above, and stays as
        # defence in depth: this statement mutates rows, so it should not be
        # one refactor away from crossing a tenant boundary again.
        ctrls = self.db.execute(select(AuditControl).where(
            AuditControl.audit_id == audit_id,
            AuditControl.tenant_id == tenant_id)).scalars().all()
        updated = 0
        for c in ctrls:
            st = latest.get(c.control_id)
            if st and st != c.auto_status:
                c.auto_status = st
                updated += 1
        self.db.commit()
        return {"controls": len(ctrls), "updated": updated}

    # ── checklist ──
    def list_controls(self, tenant_id: str, audit_id: str, limit: int | None = None,
                      offset: int = 0) -> builtins.list[dict[str, Any]]:
        from app import pagination

        rows = self.db.execute(pagination.apply(
            select(AuditControl).where(
                AuditControl.audit_id == audit_id, AuditControl.tenant_id == tenant_id)
            .order_by(AuditControl.control_id),
            limit, offset)).scalars().all()
        return [{"id": c.id, "control_id": c.control_id, "title": c.title,
                 "review_state": c.review_state, "auto_status": c.auto_status,
                 "owner": c.owner, "evidence_ref": c.evidence_ref,
                 "reviewer_note": c.reviewer_note,
                 "frameworks": crosswalk_for(c.control_id)} for c in rows]

    def review_control(self, tenant_id: str, control_row_id: str,
                       patch: ControlReviewPatch) -> dict[str, Any] | None:
        c = self.db.get(AuditControl, control_row_id)
        if not c or c.tenant_id != tenant_id:
            return None
        for k, v in patch.model_dump(exclude_unset=True).items():
            if v is not None and hasattr(v, "value"):
                v = v.value
            setattr(c, k, v)
        c.updated_at = _now()
        self.db.commit()
        self.db.refresh(c)
        return {"id": c.id, "control_id": c.control_id, "review_state": c.review_state,
                "owner": c.owner, "reviewer_note": c.reviewer_note}

    # ── evidence requests (PBC list) ──
    def list_requests(self, tenant_id: str, audit_id: str, limit: int | None = None,
                      offset: int = 0) -> builtins.list[dict[str, Any]]:
        from app import pagination

        rows = self.db.execute(pagination.apply(
            select(EvidenceRequest).where(
                EvidenceRequest.audit_id == audit_id,
                EvidenceRequest.tenant_id == tenant_id)
            .order_by(EvidenceRequest.created_at.desc(), EvidenceRequest.id),
            limit, offset)).scalars().all()
        return [self._ser_req(r) for r in rows]

    def _ser_req(self, r: EvidenceRequest) -> dict[str, Any]:
        return {"id": r.id, "control_id": r.control_id, "title": r.title,
                "description": r.description, "assignee": r.assignee, "state": r.state,
                "response_note": r.response_note, "evidence_ref": r.evidence_ref,
                "due_date": _iso(r.due_date), "created_at": _iso(r.created_at)}

    def create_request(self, tenant_id: str, audit_id: str, data: EvidenceRequestIn) -> dict[str, Any]:
        r = EvidenceRequest(audit_id=audit_id, tenant_id=tenant_id, title=data.title,
                            control_id=data.control_id, description=data.description,
                            assignee=data.assignee, due_date=data.due_date, state="open")
        self.db.add(r)
        self.db.commit()
        self.db.refresh(r)
        return self._ser_req(r)

    def update_request(self, tenant_id: str, req_id: str,
                       patch: EvidenceRequestPatch) -> dict[str, Any] | None:
        r = self.db.get(EvidenceRequest, req_id)
        if not r or r.tenant_id != tenant_id:
            return None
        for k, v in patch.model_dump(exclude_unset=True).items():
            if v is not None and hasattr(v, "value"):
                v = v.value
            setattr(r, k, v)
        r.updated_at = _now()
        self.db.commit()
        self.db.refresh(r)
        return self._ser_req(r)

    def delete_request(self, tenant_id: str, req_id: str) -> bool:
        r = self.db.get(EvidenceRequest, req_id)
        if not r or r.tenant_id != tenant_id:
            return False
        self.db.delete(r)
        self.db.commit()
        return True

    # ── the auditor-ready export package ──
    def export_package(self, tenant_id: str, audit_id: str) -> dict[str, Any] | None:
        a = self.db.get(Audit, audit_id)
        if not a or a.tenant_id != tenant_id:
            return None
        controls = self.list_controls(tenant_id, audit_id)
        requests = self.list_requests(tenant_id, audit_id)
        progress = self._progress(audit_id, tenant_id)
        return {
            "audit": {"id": a.id, "name": a.name, "framework": a.framework,
                      "auditor": a.auditor, "status": a.status,
                      "period": {"start": _iso(a.period_start), "end": _iso(a.period_end)}},
            "generated_at": _now().isoformat(),
            "summary": progress,
            "controls": controls,
            "evidence_requests": requests,
            "attestation": ("This package reflects the control review states and evidence "
                            "requests recorded in Comp-Lens at generation time. Each control's "
                            "auto_status reflects live connector evidence where available."),
        }
