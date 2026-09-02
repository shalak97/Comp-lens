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
from collections.abc import Iterator
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


#: How long an *implicit* idempotency key suppresses re-assessment.
#:
#: A caller that supplies `idempotency_key` is naming one logical request, and
#: that key dedupes forever — that is the contract of the field. A caller that
#: supplies nothing gets a key derived from what is being assessed
#: (tenant/framework/control/source/asset), which is a different thing
#: entirely: it is the same identity every time that control is evaluated on
#: that asset, today and next month.
#:
#: Treating the derived key as permanent made every re-assessment a no-op. The
#: first evaluation of a control on an asset was returned unchanged forever
#: after: posture never moved, drift never fired, and trend snapshots recorded
#: the same figures indefinitely — a flat line that reads as a stable estate
#: rather than as an estate nobody is looking at. Continuous monitoring was, in
#: the strict sense, a single measurement.
#:
#: A window keeps what the derived key is actually good for — collapsing a
#: double-clicked button or a client retry into one finding — without pinning
#: the verdict. Five minutes is far longer than any retry and far shorter than
#: any monitoring interval.
IMPLICIT_IDEMPOTENCY_WINDOW = timedelta(minutes=5)


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
        from sqlalchemy import update as sa_update

        from app.models import PostureHistory
        from app.services.freshness import DEFAULT_CADENCE, cadence_days
        now = datetime.now(UTC)
        # A status transition (or a brand-new cell) opens a new history interval.
        changed = (p is None) or (p.status != status)
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

        if changed:
            # Close the previously-open interval for this cell, then open a new one.
            self.db.execute(
                sa_update(PostureHistory)
                .where(PostureHistory.tenant_id == tenant_id,
                       PostureHistory.control_id == control_id,
                       PostureHistory.source_system == source_system.upper(),
                       PostureHistory.asset_key == asset_key,
                       PostureHistory.valid_to.is_(None))
                .values(valid_to=now))
            self.db.add(PostureHistory(
                tenant_id=tenant_id, control_id=control_id,
                source_system=source_system.upper(), asset_id=asset_id, asset_key=asset_key,
                status=status, severity=severity, finding_id=finding_id,
                valid_from=now, valid_to=None, recorded_at=now))

    def _commit_finding(self, *, tenant_id, framework, control_id, source_system, asset_id,
                        status: ControlStatus, severity: Severity, reason: str | None,
                        idem_key: str, telemetry: dict[str, Any] | None = None,
                        owner: str | None = None,
                        renew: IdempotencyRecord | None = None) -> Finding:
        # `renew` is the caller saying "this key exists but has aged out of its
        # dedupe window; this is a genuine re-assessment". Re-checking the key
        # here would hand back the stale finding, and inserting a fresh row for
        # a key that already exists would collide with the primary key and be
        # swallowed by the race handler below as a lost race. So the record is
        # repointed at the new finding instead.
        #
        # Known narrow race: two workers that both find the same key stale will
        # both re-assess and both repoint it, leaving two findings in the log
        # for one control. Posture is upserted, so current state and every
        # score derived from it stay correct; the cost is a duplicated row in
        # the audit log. Within the window — where retries and double-clicks
        # actually land — deduplication is still absolute, as is deduplication
        # of any caller-supplied key.
        if renew is None:
            existing = self._existing(idem_key)
            if existing:
                return existing

        run_id = str(uuid.uuid4())
        evidence_id = str(uuid.uuid4())
        remediation = None
        if status.value == "fail":
            remediation = {"summary": f"Remediate control {control_id}",
                           "detail": reason, "requires_approval": True}

        # Durable-store the evidence artifact BEFORE any DB write, not after.
        #
        # The DB row for EvidenceMeta records a hash that promises "the
        # artifact behind this hash exists in the store". Writing that promise
        # to the DB first and the artifact second means a store outage
        # (S3 down, disk full, retries exhausted) leaves a committed,
        # unrecoverable DB row whose backing artifact was never written — and
        # IntegrityService.verify() reports that exact state as
        # "missing_in_store", identical to what deliberate tampering looks
        # like. There is no way for an operator to tell the two apart after
        # the fact. Doing the store write first closes that hole: if it fails,
        # the function raises before touching the DB, so nothing is ever
        # committed that the store can't back up, and a retry re-attempts the
        # store write from scratch (the idempotency check above still runs
        # first, so a retry after a real commit never re-stores).
        #
        # The residual failure — store succeeds, then the DB write fails for
        # an unrelated reason (disk full, lost connection) — leaves an
        # artifact with no DB row pointing at it. That is a materially
        # different failure than the one above: verify() only walks EvidenceMeta
        # rows and checks the store for each one, so an artifact nothing
        # references is invisible to it — wasted storage, never a false
        # tampering signal. Same trade-off applies to the ordinary idempotency
        # race below: the losing writer's store() call still lands, orphaned
        # but harmless for the same reason.
        ev_uri: str | None = None
        th: str | None = None
        record_hash_value: str | None = None
        if telemetry is not None:
            th = telemetry_hash(telemetry)
            from app.evidence import record_hash as _rec_hash
            record_hash_value = _rec_hash(
                evidence_id=evidence_id, tenant_id=tenant_id, run_id=run_id,
                control_id=control_id, framework=framework,
                status=status.value, telemetry_hash_value=th)
            ev_uri = evidence_store.store(
                evidence_id=evidence_id, tenant_id=tenant_id, run_id=run_id,
                control_id=control_id, framework=framework,
                status=status.value, telemetry=telemetry)

        from app.services.framework_versions import version_of
        finding = Finding(
            finding_id=str(uuid.uuid4()), tenant_id=tenant_id, run_id=run_id, framework=framework,
            framework_version=version_of(framework),
            control_id=control_id, source_system=source_system.upper(), asset_id=asset_id,
            status=status, severity=severity, owner=owner, description=reason,
            remediation=remediation, evidence_ids=[evidence_id] if telemetry is not None else [],
        )

        try:
            with self.db.begin_nested():
                if telemetry is not None:
                    ev_meta = EvidenceMeta(
                        evidence_id=evidence_id, tenant_id=tenant_id, run_id=run_id,
                        control_id=control_id, framework=framework,
                        telemetry_hash=th, record_hash=record_hash_value,
                        status=status, object_uri=ev_uri,
                    )
                    self.db.add(ev_meta)
                self.db.add(finding)
                if renew is not None:
                    renew.finding_id = finding.finding_id
                    renew.created_at = datetime.now(UTC)
                else:
                    self.db.add(IdempotencyRecord(key=idem_key, tenant_id=tenant_id,
                                                  finding_id=finding.finding_id))
                self._upsert_posture(tenant_id=tenant_id, framework=framework, control_id=control_id,
                                     source_system=source_system, asset_id=asset_id,
                                     status=status, severity=severity, finding_id=finding.finding_id)
        except IntegrityError:
            logger.info("idempotency_race key=%s; returning winner", idem_key)
            winner = self._existing(idem_key)
            if winner:
                return winner
            raise

        try:
            from app.observability import ASSESSMENTS, EVIDENCE_WRITES
            ASSESSMENTS.labels(source_system.upper(), status.value).inc()
            if telemetry is not None:
                EVIDENCE_WRITES.labels("stored").inc()
        except Exception:  # noqa: BLE001 — instrumentation must never fail a write
            logger.debug("metrics recording failed", exc_info=True)

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

    def _stale_implicit_record(self, key: str, explicit: bool) -> IdempotencyRecord | None:
        """The record for `key` if it exists but no longer suppresses a re-run.

        Returns None both when there is no record and when the record is still
        binding — the caller distinguishes those by having already looked the
        finding up. See IMPLICIT_IDEMPOTENCY_WINDOW for why explicit and
        derived keys are treated differently.
        """
        rec = self.db.get(IdempotencyRecord, key)
        if rec is None or explicit:
            return None
        created = rec.created_at
        if created.tzinfo is None:      # SQLite hands back naive datetimes
            created = created.replace(tzinfo=UTC)
        return rec if datetime.now(UTC) - created > IMPLICIT_IDEMPOTENCY_WINDOW else None

    def _run_single_once(self, req: AssessmentRequest) -> Finding:
        key = _idem_key(req)
        renew = self._stale_implicit_record(key, explicit=bool(req.idempotency_key))
        if renew is None:
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
            reason=reason, idem_key=key, telemetry=telemetry, owner=telemetry.get("owner"),
            renew=renew)

    def record_unverifiable(self, req: AssessmentRequest, *, error: Exception) -> Finding | None:
        """Record that a control could not be evaluated on an asset.

        A fan-out that loses an asset to a connector failure used to increment a
        counter and write nothing. The asset then had no posture row at all, so
        it left the denominator entirely: a control that errored on 400 of 500
        assets produced a compliance score computed over the 100 that worked,
        presented as the tenant's score with nothing marking the hole. The
        estate looked smaller and healthier than the evidence supported.

        ERROR is the honest status for it, and the one the summary already
        handles: error rows count as applicable but not as passes, so a control
        nobody could verify lowers the score instead of vanishing from it. That
        is the same tri-state discipline the evaluator applies to a missing
        signal — "we could not observe this" is its own answer, distinct from
        both "it is fine" and "it is wrong".

        No telemetry is passed, so no evidence artifact and no EvidenceMeta row
        are written: there is no evidence, and inventing a record of one is the
        failure this whole platform exists to prevent. The finding carries the
        error text as its description instead.

        Returns None if a finding already answers for this control and asset, or
        if the write itself fails — recording the hole must never mask the
        original failure, which the caller is already reporting.
        """
        try:
            return self._retry_on_locked(lambda: self._record_unverifiable_once(req, error))
        except Exception:  # noqa: BLE001
            logger.exception("could not record unverifiable control=%s asset=%s",
                             req.control_id, req.asset_id)
            return None

    def _record_unverifiable_once(self, req: AssessmentRequest, error: Exception) -> Finding | None:
        key = _idem_key(req)
        renew = self._stale_implicit_record(key, explicit=bool(req.idempotency_key))
        if renew is None and self._existing(key) is not None:
            return None
        return self._commit_finding(
            tenant_id=req.tenant_id, framework=req.framework, control_id=req.control_id,
            source_system=req.source_system, asset_id=req.asset_id,
            status=ControlStatus.ERROR, severity=Severity.MEDIUM,
            reason=f"Could not verify: {type(error).__name__}: {error}",
            idem_key=key, telemetry=None, owner=None, renew=renew)

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
        """Assess many controls, recording the ones that could not be assessed.

        A failure here splits two ways, and the split decides whether anything
        is written:

        Resolving the connector fails — an unknown source system, or one whose
        credentials are not configured. That is a bad request or a deployment
        gap, not a statement about the estate, so it is reported and nothing is
        persisted; writing a finding per malformed request would fill the log
        with junk from a typo.

        Collection or evaluation fails once the connector exists. Then the
        target was real and we genuinely could not verify it, which is a fact
        about the estate and belongs in posture as ERROR. See
        record_unverifiable().
        """
        results: dict[str, Any] = {"succeeded": 0, "failed": 0, "unverifiable": 0,
                                   "findings": [], "errors": []}
        for r in requests:
            r.tenant_id = tenant_id
            try:
                registry.get(r.source_system)
            except Exception as exc:  # noqa: BLE001
                results["failed"] += 1
                results["errors"].append({"control_id": r.control_id, "source_system": r.source_system,
                                          "error_type": type(exc).__name__, "recorded": False})
                logger.warning("batch item unroutable control=%s: %s", r.control_id, exc)
                continue
            try:
                f = self.run_single(r)
                results["succeeded"] += 1
                results["findings"].append(f.finding_id)
            except Exception as exc:  # noqa: BLE001
                results["failed"] += 1
                recorded = self.record_unverifiable(r, error=exc)
                if recorded is not None:
                    results["unverifiable"] += 1
                    results["findings"].append(recorded.finding_id)
                results["errors"].append({"control_id": r.control_id, "source_system": r.source_system,
                                          "error_type": type(exc).__name__,
                                          "recorded": recorded is not None})
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
        # finding_id breaks ties: created_at is not unique, and without a total
        # order LIMIT/OFFSET may return a row on one page and omit it from the
        # next — which iter_findings() below would then silently drop from a
        # report.
        stmt = (stmt.order_by(Finding.created_at.desc(), Finding.finding_id)
                .limit(limit).offset(offset))
        return list(self.db.execute(stmt).scalars().all())

    def iter_findings(self, tenant_id: str, control_id: str | None = None,
                      batch: int = MAX_PAGE) -> Iterator[Finding]:
        """Every finding for a tenant, fetched a page at a time.

        list_findings() is a paged API read and clamps to MAX_PAGE, which is
        right for an endpoint and wrong for a report: an OSCAL POA&M that stops
        at 500 findings is a document that tells an auditor a tenant has 500
        problems when it has two thousand. Reports need completeness.

        Loading the whole table into one list would fix the truthfulness and
        break the memory bound, so this walks it in pages instead — complete
        output, bounded working set.
        """
        # list_findings clamps its limit to MAX_PAGE. A larger batch would
        # therefore fetch 500 rows while offset advanced by `batch` — skipping
        # everything in between, which is the very failure this method exists
        # to remove. Clamp here so the stride and the page always agree.
        batch = max(1, min(batch, MAX_PAGE))
        offset = 0
        while True:
            page = self.list_findings(tenant_id, control_id, limit=batch, offset=offset)
            if not page:
                return
            yield from page
            if len(page) < batch:
                return
            offset += batch

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
