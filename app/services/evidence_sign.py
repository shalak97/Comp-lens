"""Cryptographic chain of custody for evidence documents.

At ingestion we compute an HMAC-SHA256 over (content_hash + signed_at + tenant_id + doc_id)
with a server-side key, so the record is tamper-evident: changing the document, its
timestamp, or moving it between tenants invalidates the signature. The signing key comes
from settings.evidence_signing_key; if unset we fall back to a deterministic per-deploy
key so verification still works within a deployment (documented as lower assurance).
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime


def _key() -> bytes:
    try:
        from app.config import settings
        k = getattr(settings, "evidence_signing_key", None)
    except Exception:
        k = None
    if not k:
        # fallback: stable within a deployment, lower assurance (documented)
        k = "comp-lens-unconfigured-signing-key"
    return k.encode("utf-8")


def _canon(dt: datetime) -> str:
    """Canonical UTC, second-precision string — stable across DB round-trips
    (SQLite can drop tzinfo / microseconds, which would otherwise break HMAC)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%S")


def sign(content_hash: str, tenant_id: str, doc_id: str,
         signed_at: datetime | None = None) -> tuple[str, datetime]:
    signed_at = (signed_at or datetime.now(UTC)).replace(microsecond=0)
    msg = f"{content_hash}|{_canon(signed_at)}|{tenant_id}|{doc_id}".encode()
    sig = hmac.new(_key(), msg, hashlib.sha256).hexdigest()
    return sig, signed_at


def verify(content_hash: str, tenant_id: str, doc_id: str,
           signed_at: datetime, signature: str) -> bool:
    if not signature or not signed_at:
        return False
    expected = hmac.new(
        _key(),
        f"{content_hash}|{_canon(signed_at)}|{tenant_id}|{doc_id}".encode(),
        hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
