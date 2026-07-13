"""Guardrailed external-page crawler: targets to watch and the results of
each check. Three product feeds sit on top of the same engine:
  vendor_trust  — a vendor's trust/security/subprocessor page (TPRM)
  regulatory    — a regulator or standards body's update page
  advisory      — a security-advisory or breach-disclosure page

The crawler is read-only, public-page-only (no credentials are ever attached),
and every fetch goes through the same SSRF/robots/rate-limit guardrails in
app/services/crawler.py regardless of kind.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(UTC)


class CrawlTarget(Base):
    __tablename__ = "crawl_targets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, default="default")
    kind: Mapped[str] = mapped_column(String(24), index=True, default="advisory")  # vendor_trust|regulatory|advisory
    name: Mapped[str] = mapped_column(String(256), default="")
    url: Mapped[str] = mapped_column(String(2048), default="")
    domain: Mapped[str] = mapped_column(String(256), index=True, default="")       # host, pinned at creation
    linked_vendor_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    linked_framework: Mapped[str | None] = mapped_column(String(64), nullable=True)
    min_interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class CrawlResult(Base):
    __tablename__ = "crawl_results"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, default="default")
    target_id: Mapped[str] = mapped_column(String(36), index=True, default="")
    status: Mapped[str] = mapped_column(String(24), default="ok")
    # ok=unchanged, changed, error, blocked (guardrail), robots_disallowed, rate_limited
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)   # first ~500 chars, for a human to see what changed
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(String(512), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=utc_now)
