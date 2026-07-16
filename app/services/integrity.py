"""Tamper-evident evidence verification.

Two independent integrity checks per evidence record:
  1. record_hash recomputed from the stored DB metadata must match — detects
     any edit to the evidence_metadata row.
  2. the telemetry_hash in the DB must match the hash actually persisted in the
     evidence store (file/S3) — detects edits to the stored artifact.

An attacker would have to alter both stores consistently AND forge the
record_hash to escape detection. Reports the first/any broken records.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.evidence import evidence_store, record_hash
from app.models import EvidenceMeta


class IntegrityService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def verify(self, tenant_id: str) -> dict[str, Any]:
        rows = self.db.execute(
            select(EvidenceMeta).where(EvidenceMeta.tenant_id == tenant_id)
            .order_by(EvidenceMeta.created_at.asc())
        ).scalars().all()
        stored = evidence_store.stored_hashes(tenant_id)

        checked = 0
        broken = []
        for e in rows:
            checked += 1
            # 1. self-integrity of the DB metadata
            expected = record_hash(evidence_id=e.evidence_id, tenant_id=e.tenant_id,
                                   run_id=e.run_id, control_id=e.control_id, framework=e.framework,
                                   status=e.status.value, telemetry_hash_value=e.telemetry_hash)
            if e.record_hash and e.record_hash != expected:
                broken.append({"evidence_id": e.evidence_id, "reason": "metadata_tampered"})
                continue
            # 2. cross-check against the evidence store
            s = stored.get(e.evidence_id)
            if s is None:
                broken.append({"evidence_id": e.evidence_id, "reason": "missing_in_store"})
            elif s != e.telemetry_hash:
                broken.append({"evidence_id": e.evidence_id, "reason": "store_tampered"})

        return {"tenant_id": tenant_id, "checked": checked, "intact": len(broken) == 0,
                "broken_count": len(broken), "broken": broken[:50]}

    def verify_one(self, tenant_id: str, evidence_id: str) -> dict[str, Any]:
        """Run the same two integrity checks on a single evidence record.

        Returns {found, verified, detail, reason?}. Mirrors ``verify`` exactly:
        an unhashed record skips the metadata check but is still cross-checked
        against the store.
        """
        e = self.db.execute(
            select(EvidenceMeta).where(
                EvidenceMeta.tenant_id == tenant_id,
                EvidenceMeta.evidence_id == evidence_id,
            )
        ).scalars().first()
        if e is None:
            return {"evidence_id": evidence_id, "found": False, "verified": False,
                    "detail": "Evidence record not found."}
        # 1. self-integrity of the DB metadata
        expected = record_hash(evidence_id=e.evidence_id, tenant_id=e.tenant_id,
                               run_id=e.run_id, control_id=e.control_id, framework=e.framework,
                               status=e.status.value, telemetry_hash_value=e.telemetry_hash)
        if e.record_hash and e.record_hash != expected:
            return {"evidence_id": evidence_id, "found": True, "verified": False,
                    "reason": "metadata_tampered",
                    "detail": "METADATA MISMATCH — the evidence record was altered after capture."}
        # 2. cross-check against the evidence store
        s = evidence_store.stored_hashes(tenant_id).get(e.evidence_id)
        if s is None:
            return {"evidence_id": evidence_id, "found": True, "verified": False,
                    "reason": "missing_in_store",
                    "detail": "Artifact missing from the evidence store."}
        if s != e.telemetry_hash:
            return {"evidence_id": evidence_id, "found": True, "verified": False,
                    "reason": "store_tampered",
                    "detail": "STORE MISMATCH — the stored artifact changed since capture."}
        return {"evidence_id": evidence_id, "found": True, "verified": True,
                "detail": "Integrity intact — hash matches capture."}
