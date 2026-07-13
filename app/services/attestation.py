"""Attestation service — tracks human-attested status for framework controls and
computes coverage by combining attestations with auto-assessed findings."""
from __future__ import annotations

import builtins
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AttestationStatus, ControlAttestation, ControlStatus, Finding
from app.services import framework_catalog as catalog


class AttestationService:
    def __init__(self, db: Session):
        self.db = db

    def upsert(self, tenant_id: str, framework: str, control_id: str, status: str,
               owner: str | None = None, approver: str | None = None,
               note: str | None = None, evidence_ref: str | None = None) -> ControlAttestation:
        if not catalog.get(framework, control_id):
            raise ValueError(f"Unknown control {control_id} in {framework}")
        st = AttestationStatus(status)
        row = self.db.execute(
            select(ControlAttestation).where(
                ControlAttestation.tenant_id == tenant_id,
                ControlAttestation.framework == framework,
                ControlAttestation.control_id == control_id)).scalar_one_or_none()
        if row is None:
            row = ControlAttestation(tenant_id=tenant_id, framework=framework, control_id=control_id, status=st)
            self.db.add(row)
        row.status = st
        if owner is not None:
            row.owner = owner
        if approver is not None:
            row.approver = approver
        if note is not None:
            row.note = note
        if evidence_ref is not None:
            row.evidence_ref = evidence_ref
        self.db.commit()
        self.db.refresh(row)
        return row

    def list(self, tenant_id: str, framework: str | None = None) -> builtins.list[ControlAttestation]:
        stmt = select(ControlAttestation).where(ControlAttestation.tenant_id == tenant_id)
        if framework:
            stmt = stmt.where(ControlAttestation.framework == framework)
        return list(self.db.execute(stmt).scalars().all())

    def coverage(self, tenant_id: str, framework: str) -> dict[str, Any]:
        ctrls = catalog.controls(framework)
        total = len(ctrls)
        atts = {a.control_id: a for a in self.list(tenant_id, framework)}
        # auto-assessed controls (have at least one finding for this tenant)
        auto_ids = {c["id"] for c in ctrls if c.get("automated")}
        auto_status: dict[str, str] = {}
        if auto_ids:
            rows = self.db.execute(
                select(Finding.control_id, Finding.status).where(Finding.tenant_id == tenant_id)).all()
            for cid, st in rows:
                if cid in auto_ids:
                    # worst-case: any fail => fail
                    prev = auto_status.get(cid)
                    val = "compliant" if st == ControlStatus.PASS else "non_compliant" if st == ControlStatus.FAIL else prev or "in_progress"
                    if prev != "non_compliant":
                        auto_status[cid] = val

        by_status = {s.value: 0 for s in AttestationStatus}
        by_family: dict[str, dict[str, int]] = {}
        assessed = 0
        for c in ctrls:
            cid = c["id"]
            fam = c["family"]
            if cid in auto_status:
                status = auto_status[cid]
            elif cid in atts:
                status = atts[cid].status.value
            else:
                status = "not_assessed"
            by_status[status] = by_status.get(status, 0) + 1
            if status != "not_assessed":
                assessed += 1
            fam_rec = by_family.setdefault(fam, {"family": fam, "total": 0, "assessed": 0, "compliant": 0})
            fam_rec["total"] += 1
            if status != "not_assessed":
                fam_rec["assessed"] += 1
            if status == "compliant":
                fam_rec["compliant"] += 1

        return {
            "framework": framework, "total": total, "assessed": assessed,
            "coverage_pct": round(assessed / total * 100, 1) if total else 0.0,
            "compliant": by_status.get("compliant", 0),
            "compliance_pct": round(by_status.get("compliant", 0) / total * 100, 1) if total else 0.0,
            "by_status": by_status,
            "automated_controls": len(auto_ids),
            "by_family": sorted(by_family.values(), key=lambda x: x["family"]),
        }
