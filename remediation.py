"""Risk-based remediation prioritization.

Ranks open (unwaived) failing controls by impact = severity weight x asset
criticality, and projects the compliance score if the top-N were fixed — so a
team can see "fix these 5 and you go from 72% to 88%."
"""

from __future__ import annotations

from typing import Any, Dict, List

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AssetRecord, Posture
from app.risk import criticality_weight, severity_weight
from app.services.waivers import WaiverService


class RemediationService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def priorities(self, tenant_id: str, top: int = 10) -> Dict[str, Any]:
        rows = self.db.execute(
            select(Posture.control_id, Posture.source_system, Posture.asset_id,
                   Posture.status, Posture.severity)
            .where(Posture.tenant_id == tenant_id)
        ).all()
        # asset criticality lookup from inventory
        crit = {a.asset_id: a.criticality for a in self.db.execute(
            select(AssetRecord).where(AssetRecord.tenant_id == tenant_id)
        ).scalars().all()}
        widx = WaiverService(self.db).active_index(tenant_id)

        applicable_weight = 0.0
        fail_weight = 0.0
        items: List[Dict[str, Any]] = []
        for control_id, source, asset, status, severity in rows:
            if status.value not in ("pass", "fail"):
                continue
            sw = severity_weight(severity)
            applicable_weight += sw
            if status.value != "fail":
                continue
            if widx.covers(control_id, asset):
                continue
            fail_weight += sw
            priority = round(sw * criticality_weight(crit.get(asset)), 2)
            items.append({"control_id": control_id, "source_system": source, "asset_id": asset,
                          "severity": severity.value, "asset_criticality": crit.get(asset, "unknown"),
                          "priority": priority, "_w": sw})

        items.sort(key=lambda x: x["priority"], reverse=True)

        current = round(100 * (1 - fail_weight / applicable_weight), 2) if applicable_weight else 100.0
        # what-if: fix the top N -> remove their weight from exposure
        topn = items[:top]
        recovered = sum(i["_w"] for i in topn)
        projected = round(100 * (1 - max(fail_weight - recovered, 0) / applicable_weight), 2) if applicable_weight else 100.0
        for i in items:
            i.pop("_w", None)

        return {
            "open_findings": len(items),
            "current_risk_weighted_score": current,
            "projected_after_fixing_top": projected,
            "top_n": top,
            "queue": items[:top],
        }
