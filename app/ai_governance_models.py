"""Storage for AI-system privacy-enhancing technologies (PETs)."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


def _uuid() -> str:
    return uuid.uuid4().hex


class AISystemPET(Base):
    __tablename__ = "ai_system_pets"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    pet: Mapped[str] = mapped_column(String(64))
    params_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    data_sensitivity: Mapped[str] = mapped_column(String(32), default="pii")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=lambda: datetime.now(timezone.utc))
