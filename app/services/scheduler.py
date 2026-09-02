"""Scheduled / continuous assessments.

A Schedule defines a set of assessments and an interval. Two ways to run:
  1. The optional background runner (ENABLE_SCHEDULER=true) wakes periodically,
     finds due schedules, runs them, and reschedules.
  2. POST /schedules/{id}/run triggers one immediately — ideal for free-tier
     hosts with no always-on process, driven by an external cron / Render cron.

After each run, a compliance snapshot is captured for trend history.
"""

from __future__ import annotations

import builtins
import logging
import os
import socket
import threading
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy import update as sa_update
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.models import AssessmentRequest, Schedule, ScheduleRequest
from app.services.assessment import AssessmentService
from app.services.trends import TrendService

logger = logging.getLogger(__name__)

#: How long a claimed schedule stays leased. Long enough that a slow run is not
#: stolen mid-flight, short enough that a replica killed mid-run frees its
#: schedules promptly rather than stranding them until a human intervenes.
LEASE_SECONDS = 900

#: Stable within a process, distinct across replicas.
WORKER_ID = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"


def _claim(db: Session, schedule_id: str, now: datetime) -> bool:
    """Atomically take the lease on one schedule. True if this worker won it.

    One conditional UPDATE: the row is claimable only if it is actually due and
    not already leased by a live worker. Whoever's UPDATE matches first wins;
    everyone else sees rowcount 0 and skips. Correct on both SQLite and
    PostgreSQL because a single UPDATE is atomic on both.
    """
    res = db.execute(
        sa_update(Schedule)
        .where(Schedule.schedule_id == schedule_id,
               Schedule.next_run_at <= now,
               or_(Schedule.locked_until.is_(None), Schedule.locked_until <= now))
        .values(locked_by=WORKER_ID,
                locked_until=now + timedelta(seconds=LEASE_SECONDS))
        # Without this, SQLAlchemy's default "evaluate" strategy re-runs the
        # WHERE clause in PYTHON against objects already in the session, where
        # next_run_at has come back from SQLite naive and `now` is UTC-aware —
        # raising TypeError before the statement ever reaches the database.
        # The claimed row is refreshed by the caller anyway.
        .execution_options(synchronize_session=False))
    db.commit()
    return bool(res.rowcount == 1)


def _release(db: Session, schedule_id: str) -> None:
    """Drop the lease, but only if this worker still holds it."""
    try:
        db.execute(
            sa_update(Schedule)
            .where(Schedule.schedule_id == schedule_id,
                   Schedule.locked_by == WORKER_ID)
            .values(locked_by=None, locked_until=None)
            .execution_options(synchronize_session=False))
        db.commit()
    except Exception:  # noqa: BLE001 — releasing must never mask the real error
        db.rollback()
        logger.exception("failed to release lease on schedule %s", schedule_id)


class ScheduleService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, req: ScheduleRequest) -> Schedule:
        s = Schedule(
            tenant_id=req.tenant_id, name=req.name, interval_minutes=req.interval_minutes,
            controls=[c.model_dump() for c in req.controls], enabled=req.enabled,
            next_run_at=datetime.now(UTC),
        )
        self.db.add(s)
        self.db.flush()
        return s

    def list(self, tenant_id: str, limit: int | None = None,
             offset: int = 0) -> builtins.list[Schedule]:
        from app import pagination

        stmt = pagination.apply(
            select(Schedule).where(Schedule.tenant_id == tenant_id)
            .order_by(Schedule.created_at.desc(), Schedule.schedule_id),
            limit, offset)
        return list(self.db.execute(stmt).scalars().all())

    def delete(self, tenant_id: str, schedule_id: str) -> bool:
        s = self.db.get(Schedule, schedule_id)
        if not s or s.tenant_id != tenant_id:
            return False
        self.db.delete(s)
        self.db.flush()
        return True

    def run(self, tenant_id: str, schedule_id: str) -> dict:
        """Run one schedule on demand.

        tenant_id is required and enforced: loading by id alone let any
        authenticated tenant trigger another tenant's schedule, which writes
        findings and evidence into the victim's tenant, spends the victim's
        connector API quota, and returns the victim's schedule id and next-run
        time to the caller. Every sibling method here already scopes by tenant.
        """
        s = self.db.get(Schedule, schedule_id)
        if not s or s.tenant_id != tenant_id:
            raise ValueError("schedule not found")
        return self._execute(s)

    def _execute(self, s: Schedule) -> dict:
        svc = AssessmentService(self.db)
        ran, failed = 0, 0
        for c in s.controls:
            try:
                req = AssessmentRequest(**{**c, "tenant_id": s.tenant_id})
                svc.run_single(req)
                ran += 1
            except Exception as exc:  # noqa: BLE001
                failed += 1
                logger.warning("scheduled item failed: %s", exc)
        s.last_run_at = datetime.now(UTC)
        s.next_run_at = s.last_run_at + timedelta(minutes=s.interval_minutes)
        # snapshot for trends
        TrendService(self.db).snapshot(s.tenant_id, svc.compliance_summary(s.tenant_id))
        self.db.flush()
        logger.info("schedule_run id=%s ran=%d failed=%d", s.schedule_id, ran, failed)
        return {"schedule_id": s.schedule_id, "ran": ran, "failed": failed,
                "next_run_at": s.next_run_at.isoformat()}

    @staticmethod
    def run_due() -> dict:
        """Run all schedules whose next_run_at has passed.

        Each schedule commits (or rolls back) independently. Previously every
        due schedule in a tick shared one transaction committed once at the
        end: an exception anywhere in the batch — even something unrelated to
        an earlier schedule, like a later schedule's trend snapshot failing —
        rolled back every schedule already processed that tick. Findings that
        had genuinely been assessed, and whose evidence was already durably
        stored (see _commit_finding), were silently discarded with nothing but
        a debug log line, and next_run_at was never advanced so the only
        symptom was the schedule quietly re-running forever. Isolating the
        commit per schedule means one schedule's failure can't erase another's
        completed work, and failures are reported instead of swallowed.
        """
        db = SessionLocal()
        try:
            due = db.execute(
                select(Schedule).where(Schedule.enabled.is_(True),
                                       Schedule.next_run_at <= datetime.now(UTC))
            ).scalars().all()
        except Exception:  # noqa: BLE001
            db.rollback()
            logger.exception("run_due: failed to load due schedules")
            db.close()
            return {"attempted": 0, "succeeded": 0, "failed": 0, "errors": []}

        svc = ScheduleService(db)
        succeeded = 0
        skipped = 0
        errors: list[dict] = []
        now = datetime.now(UTC)
        try:
            for s in due:
                # Every replica runs its own scheduler thread and finds the same
                # due schedules. Only the replica that wins the lease executes;
                # the rest skip, so a horizontally-scaled deployment no longer
                # multiplies connector calls and trend snapshots by replica count.
                if not _claim(db, s.schedule_id, now):
                    skipped += 1
                    continue
                try:
                    db.refresh(s)
                    svc._execute(s)
                    db.commit()
                    succeeded += 1
                except Exception as exc:  # noqa: BLE001
                    db.rollback()
                    logger.exception("run_due: schedule %s failed", s.schedule_id)
                    errors.append({"schedule_id": s.schedule_id, "error": str(exc)})
                finally:
                    # Released whether the run succeeded or failed: a failed
                    # schedule keeps its unchanged next_run_at, so dropping the
                    # lease is what lets it be retried on the next tick.
                    _release(db, s.schedule_id)
        finally:
            db.close()

        try:
            from app.observability import SCHEDULE_RUNS
            SCHEDULE_RUNS.labels("succeeded").inc(succeeded)
            SCHEDULE_RUNS.labels("failed").inc(len(errors))
            SCHEDULE_RUNS.labels("skipped_locked").inc(skipped)
        except Exception:  # noqa: BLE001
            logger.debug("metrics recording failed", exc_info=True)

        result = {"attempted": len(due), "succeeded": succeeded,
                  "failed": len(errors), "skipped_locked": skipped, "errors": errors}
        logger.info("run_due complete attempted=%d succeeded=%d failed=%d",
                   result["attempted"], succeeded, len(errors))
        return result


_runner_thread: threading.Thread | None = None
_stop = threading.Event()


def start_background_runner() -> None:
    global _runner_thread
    if not settings.enable_scheduler or _runner_thread:
        return

    def loop():
        logger.info("scheduler runner started interval=%ss", settings.scheduler_interval_seconds)
        while not _stop.wait(settings.scheduler_interval_seconds):
            try:
                ScheduleService.run_due()
            except Exception:  # noqa: BLE001
                logger.exception("scheduler tick failed")

    _runner_thread = threading.Thread(target=loop, daemon=True)
    _runner_thread.start()


def stop_background_runner() -> None:
    _stop.set()
