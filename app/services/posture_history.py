"""Reconstruct posture 'as of' any date from the append-only PostureHistory.

This is the query side of the bitemporal spine: given a valid_time, return the
control status that held at that moment for every cell — the snapshot an auditor
means by "compliance as of <date>". The write side lives in
AssessmentService._upsert_posture (it appends an interval on each transition).
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import PostureHistory


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _covers(r: PostureHistory, t: datetime) -> bool:
    vf = _aware(r.valid_from)
    vt = _aware(r.valid_to)
    return vf is not None and vf <= t and (vt is None or t < vt)


def _status(r: PostureHistory) -> str:
    return getattr(r.status, "value", r.status)


def _severity(r: PostureHistory) -> str:
    return getattr(r.severity, "value", r.severity)


def as_of(db: Session, tenant_id: str, valid_time: datetime) -> list[dict[str, Any]]:
    """The status of every control cell that held at `valid_time`.

    The interval predicate runs in SQL, not in Python. PostureHistory is
    append-only — one row per status transition per control per asset — so a
    long-lived tenant accumulates millions of rows, and loading them all to
    discard all but the covering interval made this endpoint scale with total
    history rather than with the size of the answer. `_covers` is kept as the
    authoritative definition of the half-open interval and re-applied below, so
    a row whose timezone was dropped by the database round-trip is still judged
    by the same rule.
    """
    t = _aware(valid_time)
    rows = db.execute(
        select(PostureHistory).where(
            PostureHistory.tenant_id == tenant_id,
            PostureHistory.valid_from <= t,
            or_(PostureHistory.valid_to.is_(None), PostureHistory.valid_to > t),
        ).order_by(PostureHistory.valid_from.asc())
    ).scalars().all()
    snapshot: dict[tuple, dict[str, Any]] = {}
    for r in rows:
        if not _covers(r, t):
            continue
        key = (r.control_id, r.source_system, r.asset_key)
        snapshot[key] = {
            "control_id": r.control_id,
            "source_system": r.source_system,
            "asset_id": r.asset_id,
            "status": _status(r),
            "severity": _severity(r),
            "valid_from": r.valid_from.isoformat() if r.valid_from else None,
        }
    return sorted(snapshot.values(), key=lambda d: (d["control_id"], d["source_system"]))


MAX_TIMELINE = 1000


def timeline(db: Session, tenant_id: str, control_id: str,
             limit: int = MAX_TIMELINE) -> list[dict[str, Any]]:
    """The ordered interval history for one control (all cells).

    Bounded: a control that flaps produces one row per transition per asset, so
    an unbounded read here is the same unbounded-memory problem as `as_of`.
    Newest intervals are the ones an auditor asks about, so the cap keeps the
    most recent `limit` and returns them oldest-first.
    """
    rows = db.execute(
        select(PostureHistory)
        .where(PostureHistory.tenant_id == tenant_id,
               PostureHistory.control_id == control_id)
        .order_by(PostureHistory.valid_from.desc())
        .limit(max(1, limit))
    ).scalars().all()
    rows = list(reversed(rows))
    return [{
        "control_id": r.control_id, "source_system": r.source_system,
        "asset_id": r.asset_id, "status": _status(r), "severity": _severity(r),
        "valid_from": r.valid_from.isoformat() if r.valid_from else None,
        "valid_to": r.valid_to.isoformat() if r.valid_to else None,
    } for r in rows]


__all__ = ["as_of", "timeline"]
