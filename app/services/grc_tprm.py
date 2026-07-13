"""GRC Risk Register + TPRM service layer: CRUD, scoring, lifecycle, summaries."""
from __future__ import annotations

import builtins
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.grc_tprm_models import Risk, RiskIn, RiskPatch, Vendor, VendorIn, VendorPatch


def _now() -> datetime:
    return datetime.now(UTC)


# severity banding shared by risk + vendor scores (out of 25 for risk, 100 for vendor)
def _risk_band(score: int) -> str:
    if score >= 20:
        return "critical"
    if score >= 12:
        return "high"
    if score >= 6:
        return "medium"
    return "low"


# ── GRC Risk Register ──
class RiskService:
    def __init__(self, db: Session):
        self.db = db

    def _ser(self, r: Risk) -> dict[str, Any]:
        inherent = r.likelihood * r.impact
        rl = r.residual_likelihood if r.residual_likelihood else r.likelihood
        ri = r.residual_impact if r.residual_impact else r.impact
        residual = rl * ri
        return {
            "id": r.id, "title": r.title, "description": r.description,
            "category": r.category, "owner": r.owner,
            "likelihood": r.likelihood, "impact": r.impact,
            "inherent_score": inherent, "inherent_band": _risk_band(inherent),
            "residual_score": residual, "residual_band": _risk_band(residual),
            "treatment": r.treatment, "status": r.status,
            "linked_control": r.linked_control, "linked_vendor_id": r.linked_vendor_id,
            "review_date": r.review_date.isoformat() if r.review_date else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        }

    def list(self, tenant_id: str) -> builtins.list[dict[str, Any]]:
        rows = self.db.execute(select(Risk).where(Risk.tenant_id == tenant_id)
                               .order_by(Risk.created_at.desc())).scalars().all()
        out = [self._ser(r) for r in rows]
        out.sort(key=lambda x: x["inherent_score"], reverse=True)
        return out

    def create(self, tenant_id: str, data: RiskIn) -> dict[str, Any]:
        r = Risk(tenant_id=tenant_id, title=data.title, description=data.description,
                 category=data.category, owner=data.owner,
                 likelihood=data.likelihood, impact=data.impact,
                 treatment=data.treatment.value, status=data.status.value,
                 residual_likelihood=data.residual_likelihood,
                 residual_impact=data.residual_impact,
                 linked_control=data.linked_control,
                 linked_vendor_id=data.linked_vendor_id,
                 review_date=data.review_date)
        self.db.add(r)
        self.db.commit()
        self.db.refresh(r)
        return self._ser(r)

    def update(self, tenant_id: str, risk_id: str, patch: RiskPatch) -> dict[str, Any] | None:
        r = self.db.get(Risk, risk_id)
        if not r or r.tenant_id != tenant_id:
            return None
        for k, v in patch.model_dump(exclude_unset=True).items():
            if v is not None and hasattr(v, "value"):
                v = v.value
            setattr(r, k, v)
        r.updated_at = _now()
        self.db.commit()
        self.db.refresh(r)
        return self._ser(r)

    def delete(self, tenant_id: str, risk_id: str) -> bool:
        r = self.db.get(Risk, risk_id)
        if not r or r.tenant_id != tenant_id:
            return False
        self.db.delete(r)
        self.db.commit()
        return True

    def summary(self, tenant_id: str) -> dict[str, Any]:
        rows = self.list(tenant_id)
        by_band: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_status: dict[str, int] = {}
        by_treatment: dict[str, int] = {}
        overdue = 0
        now = _now()
        for r in rows:
            by_band[r["inherent_band"]] = by_band.get(r["inherent_band"], 0) + 1
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
            by_treatment[r["treatment"]] = by_treatment.get(r["treatment"], 0) + 1
            if r["review_date"]:
                try:
                    if datetime.fromisoformat(r["review_date"]) < now:
                        overdue += 1
                except ValueError:
                    pass
        return {"total": len(rows), "by_band": by_band, "by_status": by_status,
                "by_treatment": by_treatment, "overdue_reviews": overdue,
                "top_risks": rows[:5]}


# ── TPRM Vendor lifecycle ──
def _vendor_band(score: float | None, tier: str) -> str:
    if score is None:
        return tier
    if score >= 85:
        return "low"
    if score >= 65:
        return "medium"
    if score >= 40:
        return "high"
    return "critical"


class VendorService:
    def __init__(self, db: Session):
        self.db = db

    def _ser(self, v: Vendor) -> dict[str, Any]:
        return {
            "id": v.id, "name": v.name, "category": v.category,
            "contact_email": v.contact_email, "stage": v.stage,
            "risk_tier": v.risk_tier, "assessment_state": v.assessment_state,
            "assessment_score": v.assessment_score,
            "computed_risk": _vendor_band(v.assessment_score, v.risk_tier),
            "data_access": v.data_access, "has_dpa": v.has_dpa, "has_soc2": v.has_soc2,
            "linked_connector_key": v.linked_connector_key,
            "next_review": v.next_review.isoformat() if v.next_review else None,
            "onboarded_at": v.onboarded_at.isoformat() if v.onboarded_at else None,
            "updated_at": v.updated_at.isoformat() if v.updated_at else None,
        }

    def list(self, tenant_id: str) -> builtins.list[dict[str, Any]]:
        rows = self.db.execute(select(Vendor).where(Vendor.tenant_id == tenant_id)
                               .order_by(Vendor.onboarded_at.desc())).scalars().all()
        return [self._ser(v) for v in rows]

    def create(self, tenant_id: str, data: VendorIn) -> dict[str, Any]:
        v = Vendor(tenant_id=tenant_id, name=data.name, category=data.category,
                   contact_email=data.contact_email, stage=data.stage.value,
                   risk_tier=data.risk_tier, assessment_state=data.assessment_state.value,
                   data_access=data.data_access, has_dpa=data.has_dpa,
                   has_soc2=data.has_soc2, assessment_score=data.assessment_score,
                   linked_connector_key=data.linked_connector_key,
                   next_review=data.next_review)
        self.db.add(v)
        self.db.commit()
        self.db.refresh(v)
        return self._ser(v)

    def update(self, tenant_id: str, vendor_id: str, patch: VendorPatch) -> dict[str, Any] | None:
        v = self.db.get(Vendor, vendor_id)
        if not v or v.tenant_id != tenant_id:
            return None
        for k, val in patch.model_dump(exclude_unset=True).items():
            if val is not None and hasattr(val, "value"):
                val = val.value
            setattr(v, k, val)
        v.updated_at = _now()
        self.db.commit()
        self.db.refresh(v)
        return self._ser(v)

    def delete(self, tenant_id: str, vendor_id: str) -> bool:
        v = self.db.get(Vendor, vendor_id)
        if not v or v.tenant_id != tenant_id:
            return False
        self.db.delete(v)
        self.db.commit()
        return True

    def summary(self, tenant_id: str) -> dict[str, Any]:
        rows = self.list(tenant_id)
        by_stage: dict[str, int] = {}
        by_risk: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        needs_assessment = 0
        missing_dpa = 0
        now = _now()
        overdue = 0
        for v in rows:
            by_stage[v["stage"]] = by_stage.get(v["stage"], 0) + 1
            by_risk[v["computed_risk"]] = by_risk.get(v["computed_risk"], 0) + 1
            if v["assessment_state"] in ("not_started", "sent"):
                needs_assessment += 1
            if v["data_access"] in ("pii", "phi", "financial") and not v["has_dpa"]:
                missing_dpa += 1
            if v["next_review"]:
                try:
                    if datetime.fromisoformat(v["next_review"]) < now:
                        overdue += 1
                except ValueError:
                    pass
        return {"total": len(rows), "by_stage": by_stage, "by_risk": by_risk,
                "needs_assessment": needs_assessment, "missing_dpa": missing_dpa,
                "overdue_reviews": overdue}
