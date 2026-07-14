"""Predictive compliance / drift forecasting.

Fits a least-squares trend line to the compliance-score snapshot series and
projects the score forward, estimating when (if declining) it will cross a
target threshold. Also surfaces currently at-risk controls from posture
(failing now, or just regressed pass->fail) so teams can act before the next
audit rather than after.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Posture
from app.services.trends import TrendService


def _least_squares(xs: list[float], ys: list[float]):
    n = len(xs)
    mx = sum(xs) / n
    my = sum(ys) / n
    denom = sum((x - mx) ** 2 for x in xs)
    if denom == 0:
        return 0.0, my
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=False)) / denom
    intercept = my - slope * mx
    return slope, intercept


class ForecastService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def forecast(self, tenant_id: str, horizon_days: int = 30, threshold: float = 80.0) -> dict[str, Any]:
        snaps = TrendService(self.db).trends(tenant_id)
        at_risk = self._at_risk(tenant_id)

        if len(snaps) < 2:
            return {"insufficient_data": True, "snapshots": len(snaps),
                    "at_risk_controls": at_risk, "at_risk_count": len(at_risk)}

        t0 = datetime.fromisoformat(snaps[0]["captured_at"])
        xs = [(datetime.fromisoformat(s["captured_at"]) - t0).total_seconds() / 86400.0 for s in snaps]
        ys = [float(s["score"]) for s in snaps]
        slope, intercept = _least_squares(xs, ys)

        last_x = xs[-1]
        current = ys[-1]
        projected = round(max(0.0, min(100.0, intercept + slope * (last_x + horizon_days))), 2)

        days_to_threshold = None
        if slope < 0 and current > threshold:
            x_cross = (threshold - intercept) / slope
            days_to_threshold = round(x_cross - last_x, 1)
            if days_to_threshold is not None and days_to_threshold < 0:
                days_to_threshold = 0.0

        trend = "improving" if slope > 0.05 else "declining" if slope < -0.05 else "stable"
        return {
            "insufficient_data": False,
            "current_score": current,
            "slope_per_day": round(slope, 3),
            "trend": trend,
            "horizon_days": horizon_days,
            "projected_score": projected,
            "threshold": threshold,
            "days_to_threshold": days_to_threshold,
            "at_risk_controls": at_risk,
            "at_risk_count": len(at_risk),
        }

    def _at_risk(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = self.db.execute(
            select(Posture.control_id, Posture.source_system, Posture.asset_id,
                   Posture.status, Posture.prev_status, Posture.severity)
            .where(Posture.tenant_id == tenant_id)
        ).all()
        out = []
        for control_id, source, asset, status, prev, severity in rows:
            regressed = prev is not None and prev.value == "pass" and status.value == "fail"
            if status.value == "fail" or regressed:
                out.append({"control_id": control_id, "source_system": source, "asset_id": asset,
                            "severity": severity.value,
                            "reason": "recently_regressed" if regressed else "currently_failing"})
        # most severe first
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        out.sort(key=lambda x: order.get(x["severity"], 5))
        return out
