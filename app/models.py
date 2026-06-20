"""Persistence models (SQLAlchemy) and API schemas (Pydantic)."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from sqlalchemy import (JSON, Boolean, DateTime, Enum, Float, Index, Integer, String,
                        Text, UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ── Enums ──
class ControlStatus(str, enum.Enum):
    PASS = "pass"; FAIL = "fail"; ERROR = "error"; NOT_APPLICABLE = "not_applicable"; PENDING = "pending"


class Severity(str, enum.Enum):
    CRITICAL = "critical"; HIGH = "high"; MEDIUM = "medium"; LOW = "low"; INFO = "info"


class JobStatus(str, enum.Enum):
    QUEUED = "queued"; RUNNING = "running"; SUCCEEDED = "succeeded"; FAILED = "failed"


class Lifecycle(str, enum.Enum):
    OPEN = "open"; IN_PROGRESS = "in_progress"; RESOLVED = "resolved"; RISK_ACCEPTED = "risk_accepted"


class ExceptionStatus(str, enum.Enum):
    ACTIVE = "active"; REVOKED = "revoked"; EXPIRED = "expired"


# ── ORM models ──
class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_tenant_created", "tenant_id", "created_at"),
    )
    finding_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    framework: Mapped[str] = mapped_column(String(64))
    control_id: Mapped[str] = mapped_column(String(128), index=True)
    source_system: Mapped[str] = mapped_column(String(64))
    asset_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    status: Mapped[ControlStatus] = mapped_column(Enum(ControlStatus), index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.MEDIUM)
    lifecycle: Mapped[Lifecycle] = mapped_column(Enum(Lifecycle), default=Lifecycle.OPEN, index=True)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    owner: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class Posture(Base):
    """Materialized current state: exactly one row per
    (tenant, control, source, asset). Upserted on each assessment.

    The `findings` table is the append-only audit log; this table is the
    current view, so /summary and /drift are indexed point reads instead of
    scans over the whole log. `asset_key` (asset_id or "") lets the unique
    constraint work even when asset_id is NULL.
    """
    __tablename__ = "posture"
    __table_args__ = (
        UniqueConstraint("tenant_id", "control_id", "source_system", "asset_key",
                         name="uq_posture_key"),
        Index("ix_posture_tenant", "tenant_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128))
    control_id: Mapped[str] = mapped_column(String(128))
    source_system: Mapped[str] = mapped_column(String(64))
    asset_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    asset_key: Mapped[str] = mapped_column(String(256), default="")
    status: Mapped[ControlStatus] = mapped_column(Enum(ControlStatus))
    prev_status: Mapped[Optional[ControlStatus]] = mapped_column(Enum(ControlStatus), nullable=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.MEDIUM)
    last_finding_id: Mapped[str] = mapped_column(String(36))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class EvidenceMeta(Base):
    __tablename__ = "evidence_metadata"
    evidence_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    control_id: Mapped[str] = mapped_column(String(128))
    framework: Mapped[str] = mapped_column(String(64))
    telemetry_hash: Mapped[str] = mapped_column(String(128))
    record_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    status: Mapped[ControlStatus] = mapped_column(Enum(ControlStatus))
    object_uri: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_keys"
    key: Mapped[str] = mapped_column(String(256), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    finding_id: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Waiver(Base):
    """An accepted-risk exception that suppresses a finding from the score."""
    __tablename__ = "waivers"
    __table_args__ = (
        Index("ix_waivers_tenant_control_status", "tenant_id", "control_id", "status"),
    )
    waiver_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    control_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)  # null = all assets
    reason: Mapped[str] = mapped_column(Text)
    approver: Mapped[str] = mapped_column(String(128))
    status: Mapped[ExceptionStatus] = mapped_column(Enum(ExceptionStatus), default=ExceptionStatus.ACTIVE)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class Schedule(Base):
    """A recurring set of assessments (continuous compliance)."""
    __tablename__ = "schedules"
    schedule_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[str] = mapped_column(String(256))
    interval_minutes: Mapped[int] = mapped_column(Integer, default=1440)
    controls: Mapped[list] = mapped_column(JSON, default=list)  # list of assessment request dicts
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AssetRecord(Base):
    """Discovered asset inventory."""
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[str] = mapped_column(String(256), index=True)
    asset_type: Mapped[str] = mapped_column(String(64))
    source_system: Mapped[str] = mapped_column(String(64), index=True)
    owner: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    criticality: Mapped[str] = mapped_column(String(32), default="medium")
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ComplianceSnapshot(Base):
    """Point-in-time compliance score for trend charts."""
    __tablename__ = "compliance_snapshots"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    framework: Mapped[str] = mapped_column(String(64), default="ALL")
    score: Mapped[float] = mapped_column()
    total: Mapped[int] = mapped_column(Integer)
    passed: Mapped[int] = mapped_column(Integer)
    failed: Mapped[int] = mapped_column(Integer)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)




class ConnectorSyncState(Base):
    """Per-tenant sync state for marketplace connectors (framework v2)."""
    __tablename__ = "connector_sync_state"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, default="default")
    connector_key: Mapped[str] = mapped_column(String(64), index=True)
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="never")
    mode: Mapped[str] = mapped_column(String(16), default="demo")
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    __table_args__ = (UniqueConstraint("tenant_id", "connector_key", name="uq_sync_tenant_connector"),)


class ConnectorEvidenceItem(Base):
    """Normalized evidence collected (or demo-generated) by a connector."""
    __tablename__ = "connector_evidence_items"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, default="default")
    connector_key: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(24), default="")
    evidence_type: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(256), default="")
    status: Mapped[str] = mapped_column(String(16), default="info")
    mode: Mapped[str] = mapped_column(String(16), default="demo")
    signals: Mapped[dict] = mapped_column(JSON, default=dict)
    controls: Mapped[list] = mapped_column(JSON, default=list)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


# ── Pydantic API schemas ──
class AssessmentRequest(BaseModel):
    tenant_id: str = Field(default="default")
    framework: str = Field(default="NIST")
    control_id: str
    source_system: str
    asset_id: Optional[str] = None
    params: Dict[str, Any] = Field(default_factory=dict)
    idempotency_key: Optional[str] = None


class BatchAssessmentRequest(BaseModel):
    tenant_id: str = Field(default="default")
    controls: List[AssessmentRequest]


class FindingOut(BaseModel):
    finding_id: str; tenant_id: str; run_id: str; framework: str; control_id: str
    source_system: str; asset_id: Optional[str]; status: ControlStatus; severity: Severity
    lifecycle: Lifecycle; assigned_to: Optional[str]; owner: Optional[str]
    description: Optional[str]; remediation: Optional[dict]; evidence_ids: List[str]
    created_at: datetime
    model_config = {"from_attributes": True}


class FindingUpdate(BaseModel):
    lifecycle: Optional[Lifecycle] = None
    assigned_to: Optional[str] = None


class WaiverRequest(BaseModel):
    tenant_id: str = Field(default="default")
    control_id: str
    asset_id: Optional[str] = None
    reason: str
    approver: str
    expires_at: Optional[datetime] = None


class WaiverOut(BaseModel):
    waiver_id: str; tenant_id: str; control_id: str; asset_id: Optional[str]
    reason: str; approver: str; status: ExceptionStatus
    created_at: datetime; expires_at: Optional[datetime]
    model_config = {"from_attributes": True}


class ScheduleRequest(BaseModel):
    tenant_id: str = Field(default="default")
    name: str
    interval_minutes: int = Field(default=1440, ge=1)
    controls: List[AssessmentRequest]
    enabled: bool = True


class ScheduleOut(BaseModel):
    schedule_id: str; tenant_id: str; name: str; interval_minutes: int
    enabled: bool; last_run_at: Optional[datetime]; next_run_at: datetime
    model_config = {"from_attributes": True}


class BulkAssessRequest(BaseModel):
    tenant_id: str = Field(default="default")
    framework: str = Field(default="NIST")
    control_id: str
    source_system: str
    params: Dict[str, Any] = Field(default_factory=dict)


class ExternalFinding(BaseModel):
    """A pre-evaluated finding from an external scanner."""
    control_id: str
    source_system: str = "EXTERNAL"
    asset_id: Optional[str] = None
    status: ControlStatus
    severity: Severity = Severity.MEDIUM
    framework: str = "NIST"
    description: Optional[str] = None
    external_id: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict)


class IngestRequest(BaseModel):
    tenant_id: str = Field(default="default")
    items: List[ExternalFinding]


# ── AI governance (ISO 42001 / NIST AI RMF / EU AI Act) ──
class AISystem(Base):
    """Inventory of the organization's own AI systems, with the governance
    attributes the AI-governance controls assess on the data plane."""
    __tablename__ = "ai_systems"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[str] = mapped_column(String(256))
    owner: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    risk_tier: Mapped[str] = mapped_column(String(32), default="limited")  # high|limited|minimal
    impact_assessment: Mapped[bool] = mapped_column(Boolean, default=False)
    data_governance: Mapped[bool] = mapped_column(Boolean, default=False)
    human_oversight: Mapped[bool] = mapped_column(Boolean, default=False)
    transparency_notice: Mapped[bool] = mapped_column(Boolean, default=False)
    eval_report: Mapped[bool] = mapped_column(Boolean, default=False)
    logging_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    accuracy_tested: Mapped[bool] = mapped_column(Boolean, default=False)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class MerkleAnchor(Base):
    """A signed Merkle root over a tenant's evidence record_hashes at a point in
    time — a transparency log entry. Lets auditors prove no record was altered."""
    __tablename__ = "merkle_anchors"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    root: Mapped[str] = mapped_column(String(128))
    leaf_count: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)


class PolicyDraft(Base):
    """A natural-language control compiled to a Rego policy, pending human review.
    Nothing is enforced until a human approves it (human-in-the-loop)."""
    __tablename__ = "policy_drafts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(Text)
    control_id: Mapped[str] = mapped_column(String(128))
    rego: Mapped[str] = mapped_column(Text)
    telemetry_field: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    confidence: Mapped[float] = mapped_column(default=0.0)
    status: Mapped[str] = mapped_column(String(32), default="pending")  # pending|approved|rejected
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


# ── schemas for the new features ──
class AISystemRequest(BaseModel):
    tenant_id: str = Field(default="default")
    name: str
    owner: Optional[str] = None
    risk_tier: str = "limited"
    impact_assessment: bool = False
    data_governance: bool = False
    human_oversight: bool = False
    transparency_notice: bool = False
    eval_report: bool = False
    logging_enabled: bool = False
    accuracy_tested: bool = False


class PolicyDraftRequest(BaseModel):
    tenant_id: str = Field(default="default")
    description: str
    control_id: Optional[str] = None


class AttestationStatus(str, enum.Enum):
    compliant = "compliant"
    non_compliant = "non_compliant"
    not_applicable = "not_applicable"
    in_progress = "in_progress"
    not_assessed = "not_assessed"


class ControlAttestation(Base):
    """Human-attested status for a framework control (the ~90% of controls that
    are procedural and cannot be auto-evaluated). One row per tenant+framework+control."""
    __tablename__ = "control_attestations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "framework", "control_id", name="uq_attestation"),
        Index("ix_attestation_tenant_fw", "tenant_id", "framework"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    framework: Mapped[str] = mapped_column(String(64), index=True)
    control_id: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[AttestationStatus] = mapped_column(Enum(AttestationStatus), default=AttestationStatus.not_assessed)
    owner: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    approver: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence_ref: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class EvidenceDocument(Base):
    """An uploaded evidence document and its extraction state."""
    __tablename__ = "evidence_documents"
    __table_args__ = (
        Index("ix_evidence_docs_tenant", "tenant_id"),
        UniqueConstraint("tenant_id", "content_hash", name="uq_evidence_doc_hash"),
    )
    doc_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[str] = mapped_column(String(512))
    content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    char_count: Mapped[int] = mapped_column(Integer, default=0)
    source_type: Mapped[str] = mapped_column(String(32), default="text")
    status: Mapped[str] = mapped_column(String(32), default="pending")
    method: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    model: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    prompt_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    signature: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    signed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class EvidenceConceptHit(Base):
    """A detected concept in a document, grounded by a verbatim quote (provenance)."""
    __tablename__ = "evidence_concept_hits"
    __table_args__ = (
        Index("ix_evidence_hits_tenant", "tenant_id"),
        Index("ix_evidence_hits_doc", "doc_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    doc_id: Mapped[str] = mapped_column(String(36), index=True)
    concept_id: Mapped[str] = mapped_column(String(64), index=True)
    quote: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.6)
    method: Mapped[str] = mapped_column(String(16), default="lexicon")
    confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class RoutingDecision(Base):
    """Audit record of an ontology resolver decision: which plane/module satisfied
    a control on a given occasion, the resulting status, and why others were skipped."""
    __tablename__ = "routing_decisions"
    __table_args__ = (
        Index("ix_routing_tenant_control", "tenant_id", "control_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    framework: Mapped[str] = mapped_column(String(64))
    control_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    plane: Mapped[str] = mapped_column(String(64))
    strategy_type: Mapped[str] = mapped_column(String(32))
    module: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    executed: Mapped[bool] = mapped_column(Boolean, default=False)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    skipped: Mapped[list] = mapped_column(JSON, default=list)
    finding_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


# GRC Risk Register + TPRM (imported so Base registers tables)
from app.grc_tprm_models import Risk, Vendor  # noqa: E402,F401


# Audit management
from app.audit_models import Audit, AuditControl, EvidenceRequest  # noqa: E402,F401

from app.ai_governance_models import AISystemPET  # noqa: E402,F401
