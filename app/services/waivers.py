"""Exception / waiver workflow.

A waiver accepts the risk of a failing control for a tenant (optionally scoped
to one asset), with an approver and optional expiry. Active waivers suppress
matching failures from the compliance score.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ExceptionStatus, Waiver, WaiverRequest


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

    def list(self, tenant_id: str) -> List[Waiver]:
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
        if w.status == ExceptionStatus.ACTIVE and w.expires_at and w.expires_at < datetime.now(timezone.utc):
            w.status = ExceptionStatus.EXPIRED
        return w

    def active_for(self, tenant_id: str, control_id: str, asset_id: Optional[str]) -> Optional[Waiver]:
        """Return an active waiver covering this control/asset, if any."""
        now = datetime.now(timezone.utc)
        rows = self.db.execute(
            select(Waiver).where(
                Waiver.tenant_id == tenant_id,
                Waiver.control_id == control_id,
                Waiver.status == ExceptionStatus.ACTIVE,
            )
        ).scalars().all()
        for w in rows:
            if w.expires_at and w.expires_at < now:
                continue
            if w.asset_id is None or w.asset_id == asset_id:
                return w
        return None

    def active_index(self, tenant_id: str) -> "WaiverIndex":
        """Load all active, unexpired waivers for a tenant in ONE query and
        return an O(1) membership index (avoids N+1 lookups during scoring)."""
        now = datetime.now(timezone.utc)
        rows = self.db.execute(
            select(Waiver.control_id, Waiver.asset_id, Waiver.expires_at).where(
                Waiver.tenant_id == tenant_id, Waiver.status == ExceptionStatus.ACTIVE
            )
        ).all()
        all_assets: set[str] = set()
        specific: set[tuple] = set()
        for control_id, asset_id, expires_at in rows:
            if expires_at and expires_at < now:
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

    def covers(self, control_id: str, asset_id: Optional[str]) -> bool:
        return control_id in self._all or (control_id, asset_id) in self._specific
