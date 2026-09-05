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

    #: Statuses in which the platform actually observed the control.
    _VERIFIED = ("pass", "fail")

    def drift(self, tenant_id: str) -> dict[str, Any]:
        """Every status transition since the previous assessment, not just
        pass<->fail.

        Counting only `pass -> fail` and `fail -> pass` made the two transitions
        that matter most to an auditor invisible: a control going `pass ->
        error` means the platform LOST the ability to verify it, and `error ->
        pass` means it regained it. Since bulk_assess writes ERROR rows for
        assets a connector could not read, a whole estate could go dark between
        two runs and drift would report zero — understating in the reassuring
        direction, which is the only direction that matters here.

        `regressions` and `recoveries` keep their original pass<->fail meaning
        so existing consumers are unchanged; the visibility transitions are
        reported alongside them, and `transitions` is the complete histogram so
        nothing can be silently dropped again.
        """
        # Posture already tracks prev_status vs status per asset — drift is a
        # single point read, no log scan or in-memory history needed.
        rows = self.db.execute(
            select(Posture.control_id, Posture.source_system, Posture.asset_id,
                   Posture.prev_status, Posture.status)
            .where(Posture.tenant_id == tenant_id)
        ).all()
        regressions, recoveries = [], []
        visibility_lost, visibility_gained = [], []
        transitions: dict[str, int] = {}
        for control_id, source, asset, prev, curr in rows:
            p = prev.value if prev else None
            c = curr.value if curr else None
            if p is None or p == c:
                continue
            transitions[f"{p}->{c}"] = transitions.get(f"{p}->{c}", 0) + 1
            item = {"control_id": control_id, "source_system": source,
                    "asset_id": asset, "from": p, "to": c}
            if p == "pass" and c == "fail":
                regressions.append(item)
            elif p == "fail" and c == "pass":
                recoveries.append(item)
            elif p in self._VERIFIED and c not in self._VERIFIED:
                visibility_lost.append(item)
            elif p not in self._VERIFIED and c in self._VERIFIED:
                visibility_gained.append(item)
        return {"regressions": regressions, "recoveries": recoveries,
                "regression_count": len(regressions), "recovery_count": len(recoveries),
                "visibility_lost": visibility_lost, "visibility_gained": visibility_gained,
                "visibility_lost_count": len(visibility_lost),
                "visibility_gained_count": len(visibility_gained),
                "transitions": dict(sorted(transitions.items())),
                "changed_count": sum(transitions.values())}
