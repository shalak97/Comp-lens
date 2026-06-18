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
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _utc() -> datetime:
    return datetime.now(timezone.utc)


# ── enums ──
class AuditStatus(str, enum.Enum):
    PLANNING = "planning"
    FIELDWORK = "fieldwork"        # evidence collection + review under way
    REVIEW = "review"             # auditor reviewing
    COMPLETE = "complete"
    ARCHIVED = "archived"


class ControlReviewState(str, enum.Enum):
    NOT_STARTED = "not_started"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXCEPTION = "exception"        # accepted deviation


class RequestState(str, enum.Enum):
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
    period_start: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    period_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    auditor: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="planning")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)


class AuditControl(Base):
    __tablename__ = "audit_controls"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    audit_id: Mapped[str] = mapped_column(String(64), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    control_id: Mapped[str] = mapped_column(String(64))
    title: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    review_state: Mapped[str] = mapped_column(String(32), default="not_started")
    auto_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)  # from live posture
    owner: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    evidence_ref: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    reviewer_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)


class EvidenceRequest(Base):
    __tablename__ = "audit_evidence_requests"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    audit_id: Mapped[str] = mapped_column(String(64), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    control_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    assignee: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    state: Mapped[str] = mapped_column(String(32), default="open")
    response_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence_ref: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)


# ── schemas ──
class AuditIn(BaseModel):
    name: str
    framework: str = "NIST"
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    auditor: Optional[str] = None


class AuditPatch(BaseModel):
    name: Optional[str] = None
    auditor: Optional[str] = None
    status: Optional[AuditStatus] = None
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None


class ControlReviewPatch(BaseModel):
    review_state: Optional[ControlReviewState] = None
    owner: Optional[str] = None
    evidence_ref: Optional[str] = None
    reviewer_note: Optional[str] = None


class EvidenceRequestIn(BaseModel):
    title: str
    control_id: Optional[str] = None
    description: Optional[str] = None
    assignee: Optional[str] = None
    due_date: Optional[datetime] = None


class EvidenceRequestPatch(BaseModel):
    state: Optional[RequestState] = None
    response_note: Optional[str] = None
    evidence_ref: Optional[str] = None
    assignee: Optional[str] = None
