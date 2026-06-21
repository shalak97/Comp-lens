"""Storage for GRC-platform attestations — separate table, its own evidence lane."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import DateTime, String, Text, Float, Integer
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class GRCAttestation(Base):
    __tablename__ = "grc_attestations"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: uuid.uuid4().hex)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    platform: Mapped[str] = mapped_column(String(32), index=True)
    external_test_id: Mapped[str] = mapped_column(String(128))
    external_control_ref: Mapped[str] = mapped_column(String(128))
    comp_lens_control_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32))
    freshness_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    title: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                default=lambda: datetime.now(timezone.utc))
