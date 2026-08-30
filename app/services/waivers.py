"""Exception / waiver workflow.

A waiver accepts the risk of a failing control for a tenant (optionally scoped
to one asset), with an approver and optional expiry. Active waivers suppress
matching failures from the compliance score.
"""

from __future__ import annotations

import builtins
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ExceptionStatus, Waiver, WaiverRequest


def _aware(dt: datetime | None) -> datetime | None:
    """Coerce a DB-read datetime to UTC-aware.

    SQLite has no native timezone type, so DateTime(timezone=True) round-trips
    to a NAIVE datetime; comparing that against datetime.now(UTC) raises
    TypeError. Every expiry comparison below goes through here. Eight other
    modules in this codebase (freshness, bitemporal, posture_history,
    evidence_policy, agent_audit, trust_graph, crawler, evidence_sign) each
    carry the same helper for the same reason.
    """
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class WaiverService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, req: WaiverRequest) -> Waiver:
        w = Waiver(
            tenant_id=req.tenant_id, control_id=req.control_id, asset_id=req.asset_id,
            reason=req.reason, approver=req.approver, expires_at=req.expires_at,
        )
        self.db.add(w)
        self.db.flush()
        return w

    def list(self, tenant_id: str) -> builtins.list[Waiver]:
        rows = self.db.execute(
            select(Waiver).where(Waiver.tenant_id == tenant_id).order_by(Waiver.created_at.desc())
        ).scalars().all()
        return [self._refresh_status(w) for w in rows]

    def revoke(self, tenant_id: str, waiver_id: str) -> bool:
        w = self.db.get(Waiver, waiver_id)
        if not w or w.tenant_id != tenant_id:
            return False
        w.status = ExceptionStatus.REVOKED
        self.db.flush()
        return True

    def _refresh_status(self, w: Waiver) -> Waiver:
        expires = _aware(w.expires_at)
        if w.status == ExceptionStatus.ACTIVE and expires and expires < datetime.now(UTC):
            w.status = ExceptionStatus.EXPIRED
        return w

    def active_for(self, tenant_id: str, control_id: str, asset_id: str | None) -> Waiver | None:
        """Return an active waiver covering this control/asset, if any."""
        now = datetime.now(UTC)
        rows = self.db.execute(
            select(Waiver).where(
                Waiver.tenant_id == tenant_id,
                Waiver.control_id == control_id,
                Waiver.status == ExceptionStatus.ACTIVE,
            )
        ).scalars().all()
        for w in rows:
            expires = _aware(w.expires_at)
            if expires and expires < now:
                continue
            if w.asset_id is None or w.asset_id == asset_id:
                return w
        return None

    def active_index(self, tenant_id: str) -> WaiverIndex:
        """Load all active, unexpired waivers for a tenant in ONE query and
        return an O(1) membership index (avoids N+1 lookups during scoring)."""
        now = datetime.now(UTC)
        rows = self.db.execute(
            select(Waiver.control_id, Waiver.asset_id, Waiver.expires_at).where(
                Waiver.tenant_id == tenant_id, Waiver.status == ExceptionStatus.ACTIVE
            )
        ).all()
        all_assets: set[str] = set()
        specific: set[tuple] = set()
        for control_id, asset_id, expires_at in rows:
            expires = _aware(expires_at)
            if expires and expires < now:
                continue
            if asset_id is None:
                all_assets.add(control_id)
            else:
                specific.add((control_id, asset_id))
        return WaiverIndex(all_assets, specific)


class WaiverIndex:
    __slots__ = ("_all", "_specific")

    def __init__(self, all_assets: set, specific: set) -> None:
        self._all = all_assets
        self._specific = specific

    def covers(self, control_id: str, asset_id: str | None) -> bool:
        return control_id in self._all or (control_id, asset_id) in self._specific
