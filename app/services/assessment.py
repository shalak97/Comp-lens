"""Assessment application service.

Write path is centralized in `_commit_finding`, used by both live assessments
and external ingestion, so the audit log, idempotency, evidence, posture
(current-state), and notifications stay consistent no matter how a finding is
produced.

Reads (summary, drift) come from the `posture` materialized table — one row per
(tenant, control, source, asset) — so they're bounded by current state, not the
full findings history.
"""

from __future__ import annotations

import logging
import random
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.connectors.registry import registry
from app.evidence import evidence_store, telemetry_hash
from app.frameworks import controls_for_framework
from app.models import (
    AssessmentRequest,
    ControlStatus,
    EvidenceMeta,
    Finding,
    IdempotencyRecord,
    Posture,
    Severity,
)
from app.policy.engine import policy_engine
from app.services.waivers import WaiverService

logger = logging.getLogger(__name__)

MAX_PAGE = 500
DEFAULT_PAGE = 100

# SQLite (WAL) returns "database is locked" *immediately* — not subject to
# busy_timeout — when a transaction that already holds a read snapshot races
# another writer on the read→write upgrade. Rolling back drops the stale
# snapshot; a fresh attempt then serialises cleanly on the write lock. Retries
# are bounded with jittered exponential backoff. On PostgreSQL this never fires
# (it doesn't raise this error), so the wrapper is a no-op there.
_WRITE_MAX_RETRIES = 6
_WRITE_BACKOFF_BASE = 0.05


def _is_locked_error(exc: OperationalError) -> bool:
    msg = str(getattr(exc, "orig", None) or exc).lower()
    return "database is locked" in msg or "database is busy" in msg


def _idem_key(req: AssessmentRequest) -> str:
    if req.idempotency_key:
        return f"{req.tenant_id}:{req.idempotency_key}"
    return f"{req.tenant_id}:{req.framework}:{req.control_id}:{req.source_system}:{req.asset_id}"


class AssessmentService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def _existing(self, key: str) -> Finding | None:
        rec = self.db.get(IdempotencyRecord, key)
        return self.db.get(Finding, rec.finding_id) if rec else None

    def _upsert_posture(self, *, tenant_id, framework, control_id, source_system,
                        asset_id, status, severity, finding_id) -> None:
        asset_key = asset_id or ""
        p = self.db.execute(
            select(Posture).where(
                Posture.tenant_id == tenant_id, Posture.control_id == control_id,
                Posture.source_system == source_system.upper(), Posture.asset_key == asset_key,
            )
        ).scalar_one_or_none()
        from app.services.freshness import DEFAULT_CADENCE, cadence_days
        now = datetime.now(UTC)
        if p:
            cadence = p.cadence or DEFAULT_CADENCE
            p.prev_status = p.status
            p.status = status
            p.severity = severity
            p.last_finding_id = finding_id
            p.updated_at = now
            p.next_validation = now + timedelta(days=cadence_days(cadence))
        else:
            self.db.add(Posture(
                tenant_id=tenant_id, control_id=control_id, source_system=source_system.upper(),
                asset_id=asset_id, asset_key=asset_key, status=status, prev_status=None,
                severity=severity, last_finding_id=finding_id,
                cadence=DEFAULT_CADENCE,
                next_validation=now + timedelta(days=cadence_days(DEFAULT_CADENCE)),
            ))

    def _commit_finding(self, *, tenant_id, framework, control_id, source_system, asset_id,
                        status: ControlStatus, severity: Severity, reason: str | None,
                        idem_key: str, telemetry: dict[str, Any] | None = None,
                        owner: str | None = None) -> Finding:
        existing = self._existing(idem_key)
        if existing:
            return existing

        run_id = str(uuid.uuid4())
        evidence_id = str(uuid.uuid4())
        remediation = None
        if status.value == "fail":
            remediation = {"summary": f"Remediate control {control_id}",
                           "detail": reason, "requires_approval": True}

        finding = Finding(
            finding_id=str(uuid.uuid4()), tenant_id=tenant_id, run_id=run_id, framework=framework,
            control_id=control_id, source_system=source_system.upper(), asset_id=asset_id,
            status=status, severity=severity, owner=owner, description=reason,
            remediation=remediation, evidence_ids=[evidence_id] if telemetry is not None else [],
        )

        ev_meta = None
        try:
            with self.db.begin_nested():
                if telemetry is not None:
                    th = telemetry_hash(telemetry)
                    from app.evidence import record_hash as _rec_hash
                    ev_meta = EvidenceMeta(
                        evidence_id=evidence_id, tenant_id=tenant_id, run_id=run_id,
                        control_id=control_id, framework=framework,
                        telemetry_hash=th,
                        record_hash=_rec_hash(evidence_id=evidence_id, tenant_id=tenant_id,
                                              run_id=run_id, control_id=control_id, framework=framework,
                                              status=status.value, telemetry_hash_value=th),
                        status=status, object_uri=None,
                    )
                    self.db.add(ev_meta)
                self.db.add(finding)
                self.db.add(IdempotencyRecord(key=idem_key, tenant_id=tenant_id, finding_id=finding.finding_id))
                self._upsert_posture(tenant_id=tenant_id, framework=framework, control_id=control_id,
                                     source_system=source_system, asset_id=asset_id,
                                     status=status, severity=severity, finding_id=finding.finding_id)
        except IntegrityError:
            logger.info("idempotency_race key=%s; returning winner", idem_key)
            winner = self._existing(idem_key)
            if winner:
                return winner
            raise

        if telemetry is not None:
            uri = evidence_store.store(evidence_id=evidence_id, tenant_id=tenant_id, run_id=run_id,
                                       control_id=control_id, framework=framework,
                                       status=status.value, telemetry=telemetry)
            if ev_meta is not None:
                ev_meta.object_uri = uri  # still session-attached; no extra query

        try:
            from app.notifications import notify_finding
            notify_finding(finding)
        except Exception:  # noqa: BLE001
            logger.exception("notification dispatch failed")
        return finding

    def _retry_on_locked(self, fn):
        """Run a write closure, retrying transient SQLite BUSY/locked errors.

        Each retry rolls back first so the next attempt starts from a clean
        transaction (fresh snapshot), which is what lets it acquire the write
        lock instead of re-racing the upgrade. Non-lock errors propagate at once.
        """
        for attempt in range(_WRITE_MAX_RETRIES):
            try:
                return fn()
            except OperationalError as exc:
                if attempt == _WRITE_MAX_RETRIES - 1 or not _is_locked_error(exc):
                    raise
                self.db.rollback()
                time.sleep(_WRITE_BACKOFF_BASE * (2 ** attempt) * (0.5 + random.random()))
        raise RuntimeError("unreachable")  # loop always returns or raises

    def run_single(self, req: AssessmentRequest) -> Finding:
        return self._retry_on_locked(lambda: self._run_single_once(req))

    def _run_single_once(self, req: AssessmentRequest) -> Finding:
        key = _idem_key(req)
        existing = self._existing(key)
        if existing:
            return existing
        connector = registry.get(req.source_system)
        # pass tenant to connectors that scope reads by it (e.g. AIGOV); others ignore it
        telemetry = connector.collect_telemetry(
            req.control_id, req.asset_id, {**req.params, "_tenant_id": req.tenant_id})
        status, reason, severity = policy_engine.evaluate(req.control_id, telemetry)
        sev = severity if isinstance(severity, Severity) else Severity.MEDIUM
        return self._commit_finding(
            tenant_id=req.tenant_id, framework=req.framework, control_id=req.control_id,
            source_system=req.source_system, asset_id=req.asset_id, status=status, severity=sev,
            reason=reason, idem_key=key, telemetry=telemetry, owner=telemetry.get("owner"))

    def record_external_finding(self, *, tenant_id: str, framework: str, control_id: str,
                                source_system: str, asset_id: str | None, status: ControlStatus,
                                severity: Severity, description: str | None = None,
                                raw: dict[str, Any] | None = None,
                                external_id: str | None = None) -> Finding | None:
        """Persist a pre-evaluated finding from an external scanner.

        Returns the created Finding, or None if it was already ingested
        (so callers can report it as skipped — ingestion is idempotent).
        """
        idem = f"{tenant_id}:ext:{external_id or (control_id + ':' + (asset_id or ''))}"
        if self._existing(idem) is not None:
            return None
        return self._commit_finding(
            tenant_id=tenant_id, framework=framework, control_id=control_id,
            source_system=source_system, asset_id=asset_id, status=status,
            severity=severity, reason=description, idem_key=idem,
            telemetry=raw or {"ingested": True}, owner=None)

    def run_batch(self, tenant_id: str, requests: list[AssessmentRequest]) -> dict[str, Any]:
        results: dict[str, Any] = {"succeeded": 0, "failed": 0, "findings": [], "errors": []}
        for r in requests:
            r.tenant_id = tenant_id
            try:
                f = self.run_single(r)
                results["succeeded"] += 1
                results["findings"].append(f.finding_id)
            except Exception as exc:  # noqa: BLE001
                results["failed"] += 1
                results["errors"].append({"control_id": r.control_id, "source_system": r.source_system,
                                          "error_type": type(exc).__name__})
                logger.warning("batch item failed control=%s: %s", r.control_id, exc)
        return results

    def update_finding(self, tenant_id: str, finding_id: str, upd) -> Finding | None:
        f = self.db.get(Finding, finding_id)
        if not f or f.tenant_id != tenant_id:
            return None
        if upd.lifecycle is not None:
            f.lifecycle = upd.lifecycle
        if upd.assigned_to is not None:
            f.assigned_to = upd.assigned_to
        self.db.flush()
        return f

    def list_findings(self, tenant_id: str, control_id: str | None = None,
                      limit: int = DEFAULT_PAGE, offset: int = 0) -> list[Finding]:
        limit = max(1, min(limit, MAX_PAGE))
        offset = max(0, offset)
        stmt = select(Finding).where(Finding.tenant_id == tenant_id)
        if control_id:
            stmt = stmt.where(Finding.control_id == control_id)
        stmt = stmt.order_by(Finding.created_at.desc()).limit(limit).offset(offset)
        return list(self.db.execute(stmt).scalars().all())

    def compliance_summary(self, tenant_id: str, framework: str | None = None) -> dict[str, Any]:
        # Read current state from posture (bounded by distinct assets*controls,
        # not the full findings history).
        from app.risk import severity_weight
        scope = set(controls_for_framework(framework)) if framework else None
        rows = self.db.execute(
            select(Posture.control_id, Posture.asset_id, Posture.status, Posture.severity)
            .where(Posture.tenant_id == tenant_id)
        ).all()
        widx = WaiverService(self.db).active_index(tenant_id)
        by_status = {"pass": 0, "fail": 0, "error": 0, "not_applicable": 0, "pending": 0}
        waived = 0
        risk_exposure = 0.0       # weight of unwaived failing controls
        max_exposure = 0.0        # weight of all applicable controls
        for control_id, asset, status, severity in rows:
            if scope is not None and control_id not in scope:
                continue
            if status.value == "fail" and widx.covers(control_id, asset):
                waived += 1
                continue
            by_status[status.value] += 1
            if status.value in ("pass", "fail"):
                w = severity_weight(severity)
                max_exposure += w
                if status.value == "fail":
                    risk_exposure += w
        total = sum(by_status.values())
        applicable = total - by_status["not_applicable"]
        score = round(by_status["pass"] / applicable * 100, 2) if applicable else 0.0
        # higher is better: 100 means no risk-weighted exposure
        risk_weighted = round(100 * (1 - risk_exposure / max_exposure), 2) if max_exposure else 100.0
        return {"total": total, "by_status": by_status, "waived": waived,
                "compliance_score": score, "risk_weighted_score": risk_weighted,
                "risk_exposure": round(risk_exposure, 1), "framework": framework or "ALL"}
