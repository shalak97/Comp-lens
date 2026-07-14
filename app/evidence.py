"""Immutable evidence store.

Every assessment produces an evidence artifact: the raw telemetry plus a
SHA-256 hash. Backends:
  - local : append-only JSONL with an exclusive file lock + fsync (safe under
            concurrent writers on one host)
  - s3    : one immutable object per evidence record, with retry (production;
            enable bucket versioning + Object Lock for true immutability)

The hash makes tampering detectable: re-hash the stored telemetry and compare.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.config import settings
from app.retry import TransientError, external_retry

logger = logging.getLogger(__name__)


def telemetry_hash(telemetry: dict[str, Any]) -> str:
    """Deterministic SHA-256 over canonical JSON."""
    canonical = json.dumps(telemetry, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def record_hash(*, evidence_id: str, tenant_id: str, run_id: str, control_id: str,
                framework: str, status: str, telemetry_hash_value: str) -> str:
    """Self-verifying hash over an evidence record's immutable fields. Any later
    edit to the stored metadata or telemetry changes this hash → detectable."""
    canonical = "|".join([evidence_id, tenant_id, run_id, control_id, framework,
                          status, telemetry_hash_value])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class EvidenceStore:
    def __init__(self) -> None:
        self.backend = settings.evidence_backend.lower()
        if self.backend == "s3":
            self._init_s3()
        else:
            self._local_path = Path(settings.evidence_local_path)
            self._local_path.mkdir(parents=True, exist_ok=True)

    def _init_s3(self) -> None:
        import boto3

        if not settings.evidence_s3_bucket:
            raise RuntimeError("EVIDENCE_S3_BUCKET must be set when EVIDENCE_BACKEND=s3")
        self._s3 = boto3.client("s3", region_name=settings.aws_region)
        self._bucket = settings.evidence_s3_bucket
        self._prefix = settings.evidence_s3_prefix

    def store(self, *, evidence_id: str, tenant_id: str, run_id: str, control_id: str,
              framework: str, status: str, telemetry: dict[str, Any]) -> str:
        record = {
            "evidence_id": evidence_id, "tenant_id": tenant_id, "run_id": run_id,
            "control_id": control_id, "framework": framework, "status": status,
            "telemetry": telemetry, "telemetry_hash": telemetry_hash(telemetry),
            "stored_at": datetime.now(UTC).isoformat(),
        }
        payload = json.dumps(record, default=str, sort_keys=True)

        if self.backend == "s3":
            uri = self._put_s3(tenant_id, run_id, evidence_id, payload)
        else:
            uri = self._put_local(tenant_id, evidence_id, payload)

        logger.info("evidence_stored evidence_id=%s", evidence_id)
        return uri

    def _put_local(self, tenant_id: str, evidence_id: str, payload: str) -> str:
        # sanitize tenant_id for filesystem safety
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in tenant_id)[:128] or "tenant"
        f = self._local_path / f"{safe}.jsonl"
        # exclusive lock for concurrent-writer safety, then fsync for durability
        with f.open("a", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                fh.write(payload + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        return f"file://{f.resolve()}#{evidence_id}"

    @external_retry
    def _put_s3(self, tenant_id: str, run_id: str, evidence_id: str, payload: str) -> str:
        key = f"{self._prefix}{tenant_id}/{run_id}/{evidence_id}.json"
        try:
            self._s3.put_object(Bucket=self._bucket, Key=key,
                                Body=payload.encode("utf-8"), ContentType="application/json")
        except Exception as exc:  # noqa: BLE001
            raise TransientError(f"S3 put failed: {exc}") from exc
        return f"s3://{self._bucket}/{key}"

    def stored_hashes(self, tenant_id: str) -> dict[str, str]:
        """Return {evidence_id: telemetry_hash} as actually persisted in the
        store, so verification can detect tampering of the stored artifacts
        independently of the database metadata."""
        out: dict[str, str] = {}
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in tenant_id)[:128] or "tenant"
        if self.backend == "s3":
            try:
                paginator = self._s3.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=self._bucket, Prefix=f"{self._prefix}{tenant_id}/"):
                    for obj in page.get("Contents", []):
                        body = self._s3.get_object(Bucket=self._bucket, Key=obj["Key"])["Body"].read()
                        rec = json.loads(body)
                        out[rec["evidence_id"]] = rec.get("telemetry_hash", "")
            except Exception as exc:  # noqa: BLE001
                logger.warning("evidence read (s3) failed: %s", exc)
        else:
            f = self._local_path / f"{safe}.jsonl"
            if f.exists():
                for line in f.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                        out[rec["evidence_id"]] = rec.get("telemetry_hash", "")
                    except json.JSONDecodeError:
                        continue
        return out


evidence_store = EvidenceStore()
