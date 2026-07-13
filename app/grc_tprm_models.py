"""GRC Risk Register + Third-Party Risk Management (TPRM) models & schemas.

Two lifecycles, register-style like Vanta / Drata / OneTrust:

GRC Risk Register
    A risk is a first-class object: likelihood x impact => inherent score, a
    treatment decision (accept / mitigate / transfer / avoid), an owner, and a
    review cadence. Residual score reflects post-treatment exposure.

TPRM (vendor lifecycle)
    A vendor moves through stages: onboarding -> assessment -> active
    (monitoring) -> offboarding. Each vendor has a risk tier, an assessment
    (questionnaire) status, and a next-review date.
"""
from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utc() -> datetime:
    return datetime.now(UTC)


# ── enums ──
class RiskTreatment(enum.StrEnum):
    ACCEPT = "accept"
    MITIGATE = "mitigate"
    TRANSFER = "transfer"
    AVOID = "avoid"


class RiskStatus(enum.StrEnum):
    IDENTIFIED = "identified"
    ASSESSED = "assessed"
    TREATED = "treated"
    MONITORING = "monitoring"
    CLOSED = "closed"


class VendorStage(enum.StrEnum):
    ONBOARDING = "onboarding"
    ASSESSMENT = "assessment"
    ACTIVE = "active"
    OFFBOARDING = "offboarding"
    TERMINATED = "terminated"


class AssessmentState(enum.StrEnum):
    NOT_STARTED = "not_started"
    SENT = "sent"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    FLAGGED = "flagged"


# ── ORM: GRC Risk ──
class Risk(Base):
    __tablename__ = "grc_risks"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(64), default="operational")
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    likelihood: Mapped[int] = mapped_column(Integer, default=3)   # 1-5
    impact: Mapped[int] = mapped_column(Integer, default=3)       # 1-5
    treatment: Mapped[str] = mapped_column(String(32), default="mitigate")
    status: Mapped[str] = mapped_column(String(32), default="identified")
    residual_likelihood: Mapped[int | None] = mapped_column(Integer, nullable=True)
    residual_impact: Mapped[int | None] = mapped_column(Integer, nullable=True)
    linked_control: Mapped[str | None] = mapped_column(String(64), nullable=True)
    linked_vendor_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    review_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)


# ── ORM: TPRM Vendor ──
class Vendor(Base):
    __tablename__ = "tprm_vendors"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[str] = mapped_column(String(256))
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    contact_email: Mapped[str | None] = mapped_column(String(256), nullable=True)
    stage: Mapped[str] = mapped_column(String(32), default="onboarding")
    risk_tier: Mapped[str] = mapped_column(String(32), default="medium")  # critical|high|medium|low
    assessment_state: Mapped[str] = mapped_column(String(32), default="not_started")
    data_access: Mapped[str | None] = mapped_column(String(64), nullable=True)  # pii|phi|financial|none
    has_dpa: Mapped[bool] = mapped_column(Boolean, default=False)        # data processing agreement
    has_soc2: Mapped[bool] = mapped_column(Boolean, default=False)
    assessment_score: Mapped[float | None] = mapped_column(Float, nullable=True)  # 0-100
    linked_connector_key: Mapped[str | None] = mapped_column(String(64), nullable=True)  # ties vendor to a connector
    next_review: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    onboarded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)


# ── pydantic schemas ──
class RiskIn(BaseModel):
    title: str
    description: str | None = None
    category: str = "operational"
    owner: str | None = None
    likelihood: int = Field(3, ge=1, le=5)
    impact: int = Field(3, ge=1, le=5)
    treatment: RiskTreatment = RiskTreatment.MITIGATE
    status: RiskStatus = RiskStatus.IDENTIFIED
    residual_likelihood: int | None = Field(None, ge=1, le=5)
    residual_impact: int | None = Field(None, ge=1, le=5)
    linked_control: str | None = None
    linked_vendor_id: str | None = None
    review_date: datetime | None = None


class RiskPatch(BaseModel):
    title: str | None = None
    description: str | None = None
    category: str | None = None
    owner: str | None = None
    likelihood: int | None = Field(None, ge=1, le=5)
    impact: int | None = Field(None, ge=1, le=5)
    treatment: RiskTreatment | None = None
    status: RiskStatus | None = None
    residual_likelihood: int | None = Field(None, ge=1, le=5)
    residual_impact: int | None = Field(None, ge=1, le=5)
    linked_control: str | None = None
    linked_vendor_id: str | None = None
    review_date: datetime | None = None


class VendorIn(BaseModel):
    name: str
    category: str | None = None
    contact_email: str | None = None
    stage: VendorStage = VendorStage.ONBOARDING
    risk_tier: str = "medium"
    assessment_state: AssessmentState = AssessmentState.NOT_STARTED
    data_access: str | None = None
    has_dpa: bool = False
    has_soc2: bool = False
    assessment_score: float | None = Field(None, ge=0, le=100)
    linked_connector_key: str | None = None
    next_review: datetime | None = None


class VendorPatch(BaseModel):
    name: str | None = None
    category: str | None = None
    contact_email: str | None = None
    stage: VendorStage | None = None
    risk_tier: str | None = None
    assessment_state: AssessmentState | None = None
    data_access: str | None = None
    has_dpa: bool | None = None
    has_soc2: bool | None = None
    assessment_score: float | None = Field(None, ge=0, le=100)
    linked_connector_key: str | None = None
    next_review: datetime | None = None
