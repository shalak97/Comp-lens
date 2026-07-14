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

_UNCONFIGURED_KEY = "comp-lens-unconfigured-signing-key"


def _key() -> bytes:
    prod = False
    try:
        from app.config import settings
        k = getattr(settings, "evidence_signing_key", None)
        prod = settings.is_production
    except Exception:
        k = None
    if not k:
        # Fail closed in production: a world-known constant defeats tamper-evidence,
        # so refuse it there. In non-production it's a documented lower-assurance dev key.
        if prod:
            raise RuntimeError(
                "evidence_signing_key must be set in production "
                "(EVIDENCE_SIGNING_KEY); refusing to sign with the unconfigured key.")
        k = _UNCONFIGURED_KEY
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


def sign_root(root: str, tenant_id: str, leaf_count: int) -> str:
    """HMAC over a Merkle anchor root, binding it to its tenant + leaf count.

    Persisting this alongside the anchor makes the transparency log tamper-evident
    against DB modification: an attacker without the signing key cannot forge a
    matching signature for a rewritten root.
    """
    msg = f"{root}|{tenant_id}|{leaf_count}".encode()
    return hmac.new(_key(), msg, hashlib.sha256).hexdigest()


def verify_root(root: str, tenant_id: str, leaf_count: int, signature: str) -> bool:
    if not signature:
        return False
    expected = sign_root(root, tenant_id, leaf_count)
    return hmac.compare_digest(expected, signature)
