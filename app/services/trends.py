"""Trend history + drift detection.

- snapshot(): capture the current compliance score as a point-in-time row
  (called by the scheduler or on demand) so trend charts are cheap.
- trends(): return the snapshot series.
- drift(): compare the two most recent findings per (control, asset, source)
  and report regressions (pass -> fail) and recoveries (fail -> pass).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ComplianceSnapshot, Posture


class TrendService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def snapshot(self, tenant_id: str, summary: dict[str, Any], framework: str = "ALL") -> ComplianceSnapshot:
        snap = ComplianceSnapshot(
            tenant_id=tenant_id, framework=framework, score=summary["compliance_score"],
            total=summary["total"], passed=summary["by_status"]["pass"],
            failed=summary["by_status"]["fail"],
        )
        self.db.add(snap)
        self.db.flush()
        return snap

    def trends(self, tenant_id: str, limit: int = 90) -> list[dict[str, Any]]:
        rows = self.db.execute(
            select(ComplianceSnapshot).where(ComplianceSnapshot.tenant_id == tenant_id)
            .order_by(ComplianceSnapshot.captured_at.desc()).limit(limit)
        ).scalars().all()
        return [{"captured_at": r.captured_at.isoformat(), "score": r.score,
                 "total": r.total, "passed": r.passed, "failed": r.failed}
                for r in reversed(rows)]

    def drift(self, tenant_id: str) -> dict[str, Any]:
        # Posture already tracks prev_status vs status per asset — drift is a
        # single point read, no log scan or in-memory history needed.
        rows = self.db.execute(
            select(Posture.control_id, Posture.source_system, Posture.asset_id,
                   Posture.prev_status, Posture.status)
            .where(Posture.tenant_id == tenant_id)
        ).all()
        regressions, recoveries = [], []
        for control_id, source, asset, prev, curr in rows:
            p = prev.value if prev else None
            c = curr.value if curr else None
            if p == "pass" and c == "fail":
                regressions.append({"control_id": control_id, "source_system": source, "asset_id": asset})
            elif p == "fail" and c == "pass":
                recoveries.append({"control_id": control_id, "source_system": source, "asset_id": asset})
        return {"regressions": regressions, "recoveries": recoveries,
                "regression_count": len(regressions), "recovery_count": len(recoveries)}
