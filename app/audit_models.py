"""Audit management: the engagement lifecycle an external auditor works through.

Three objects orchestrate the existing attestation/evidence primitives into a
real audit:

  Audit          — an engagement: a framework + a period + a lifecycle status.
  AuditControl   — one control in the audit's scope, with its review state
                   (the checklist the auditor signs off line by line).
  EvidenceRequest — a PBC ("provided by client") item: the auditor asks for
                    specific evidence, the owner fulfills it, status is tracked.
"""
from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from pydantic import BaseModel
from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _utc() -> datetime:
    return datetime.now(UTC)


# ── enums ──
class AuditStatus(enum.StrEnum):
    PLANNING = "planning"
    FIELDWORK = "fieldwork"        # evidence collection + review under way
    REVIEW = "review"             # auditor reviewing
    COMPLETE = "complete"
    ARCHIVED = "archived"


class ControlReviewState(enum.StrEnum):
    NOT_STARTED = "not_started"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXCEPTION = "exception"        # accepted deviation


class RequestState(enum.StrEnum):
    OPEN = "open"
    FULFILLED = "fulfilled"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


# ── ORM ──
class Audit(Base):
    __tablename__ = "audits"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[str] = mapped_column(String(256))
    framework: Mapped[str] = mapped_column(String(64))
    period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    auditor: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="planning")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)


class AuditControl(Base):
    __tablename__ = "audit_controls"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    audit_id: Mapped[str] = mapped_column(String(64), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    control_id: Mapped[str] = mapped_column(String(64))
    title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    review_state: Mapped[str] = mapped_column(String(32), default="not_started")
    auto_status: Mapped[str | None] = mapped_column(String(32), nullable=True)  # from live posture
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    evidence_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    reviewer_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)


class EvidenceRequest(Base):
    __tablename__ = "audit_evidence_requests"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    audit_id: Mapped[str] = mapped_column(String(64), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    control_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    assignee: Mapped[str | None] = mapped_column(String(128), nullable=True)
    state: Mapped[str] = mapped_column(String(32), default="open")
    response_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)


# ── schemas ──
class AuditIn(BaseModel):
    name: str
    framework: str = "NIST"
    period_start: datetime | None = None
    period_end: datetime | None = None
    auditor: str | None = None


class AuditPatch(BaseModel):
    name: str | None = None
    auditor: str | None = None
    status: AuditStatus | None = None
    period_start: datetime | None = None
    period_end: datetime | None = None


class ControlReviewPatch(BaseModel):
    review_state: ControlReviewState | None = None
    owner: str | None = None
    evidence_ref: str | None = None
    reviewer_note: str | None = None


class EvidenceRequestIn(BaseModel):
    title: str
    control_id: str | None = None
    description: str | None = None
    assignee: str | None = None
    due_date: datetime | None = None


class EvidenceRequestPatch(BaseModel):
    state: RequestState | None = None
    response_note: str | None = None
    evidence_ref: str | None = None
    assignee: str | None = None
