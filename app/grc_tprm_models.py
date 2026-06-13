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
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field
from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utc() -> datetime:
    return datetime.now(timezone.utc)


# ── enums ──
class RiskTreatment(str, enum.Enum):
    ACCEPT = "accept"
    MITIGATE = "mitigate"
    TRANSFER = "transfer"
    AVOID = "avoid"


class RiskStatus(str, enum.Enum):
    IDENTIFIED = "identified"
    ASSESSED = "assessed"
    TREATED = "treated"
    MONITORING = "monitoring"
    CLOSED = "closed"


class VendorStage(str, enum.Enum):
    ONBOARDING = "onboarding"
    ASSESSMENT = "assessment"
    ACTIVE = "active"
    OFFBOARDING = "offboarding"
    TERMINATED = "terminated"


class AssessmentState(str, enum.Enum):
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
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(64), default="operational")
    owner: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    likelihood: Mapped[int] = mapped_column(Integer, default=3)   # 1-5
    impact: Mapped[int] = mapped_column(Integer, default=3)       # 1-5
    treatment: Mapped[str] = mapped_column(String(32), default="mitigate")
    status: Mapped[str] = mapped_column(String(32), default="identified")
    residual_likelihood: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    residual_impact: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    linked_control: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    linked_vendor_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    review_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)


# ── ORM: TPRM Vendor ──
class Vendor(Base):
    __tablename__ = "tprm_vendors"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[str] = mapped_column(String(256))
    category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    contact_email: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    stage: Mapped[str] = mapped_column(String(32), default="onboarding")
    risk_tier: Mapped[str] = mapped_column(String(32), default="medium")  # critical|high|medium|low
    assessment_state: Mapped[str] = mapped_column(String(32), default="not_started")
    data_access: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # pii|phi|financial|none
    has_dpa: Mapped[bool] = mapped_column(Boolean, default=False)        # data processing agreement
    has_soc2: Mapped[bool] = mapped_column(Boolean, default=False)
    assessment_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # 0-100
    linked_connector_key: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # ties vendor to a connector
    next_review: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    onboarded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc)


# ── pydantic schemas ──
class RiskIn(BaseModel):
    title: str
    description: Optional[str] = None
    category: str = "operational"
    owner: Optional[str] = None
    likelihood: int = Field(3, ge=1, le=5)
    impact: int = Field(3, ge=1, le=5)
    treatment: RiskTreatment = RiskTreatment.MITIGATE
    status: RiskStatus = RiskStatus.IDENTIFIED
    residual_likelihood: Optional[int] = Field(None, ge=1, le=5)
    residual_impact: Optional[int] = Field(None, ge=1, le=5)
    linked_control: Optional[str] = None
    linked_vendor_id: Optional[str] = None
    review_date: Optional[datetime] = None


class RiskPatch(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    owner: Optional[str] = None
    likelihood: Optional[int] = Field(None, ge=1, le=5)
    impact: Optional[int] = Field(None, ge=1, le=5)
    treatment: Optional[RiskTreatment] = None
    status: Optional[RiskStatus] = None
    residual_likelihood: Optional[int] = Field(None, ge=1, le=5)
    residual_impact: Optional[int] = Field(None, ge=1, le=5)
    linked_control: Optional[str] = None
    linked_vendor_id: Optional[str] = None
    review_date: Optional[datetime] = None


class VendorIn(BaseModel):
    name: str
    category: Optional[str] = None
    contact_email: Optional[str] = None
    stage: VendorStage = VendorStage.ONBOARDING
    risk_tier: str = "medium"
    assessment_state: AssessmentState = AssessmentState.NOT_STARTED
    data_access: Optional[str] = None
    has_dpa: bool = False
    has_soc2: bool = False
    assessment_score: Optional[float] = Field(None, ge=0, le=100)
    linked_connector_key: Optional[str] = None
    next_review: Optional[datetime] = None


class VendorPatch(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    contact_email: Optional[str] = None
    stage: Optional[VendorStage] = None
    risk_tier: Optional[str] = None
    assessment_state: Optional[AssessmentState] = None
    data_access: Optional[str] = None
    has_dpa: Optional[bool] = None
    has_soc2: Optional[bool] = None
    assessment_score: Optional[float] = Field(None, ge=0, le=100)
    linked_connector_key: Optional[str] = None
    next_review: Optional[datetime] = None
