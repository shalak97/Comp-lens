"""Ledger of policy obligations that have been dispatched to operational
procedures. Each row is one action a failing rule fanned out to (a ticket,
an alert, an audit event, a retention scan, a DSAR, a re-sync, a waiver)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(UTC)


class ObligationDispatch(Base):
    __tablename__ = "obligation_dispatches"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, default="default")
    control_id: Mapped[str] = mapped_column(String(128), index=True, default="")
    procedure: Mapped[str] = mapped_column(String(48), index=True, default="")     # open_ticket, notify, …
    status: Mapped[str] = mapped_column(String(24), default="done")                # done, queued, skipped, error
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    detail: Mapped[str] = mapped_column(Text, default="")
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    finding_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=utc_now)
