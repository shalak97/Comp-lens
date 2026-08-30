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
import threading
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.models import AssessmentRequest, Schedule, ScheduleRequest
from app.services.assessment import AssessmentService
from app.services.trends import TrendService

logger = logging.getLogger(__name__)


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

    def list(self, tenant_id: str) -> builtins.list[Schedule]:
        return list(self.db.execute(
            select(Schedule).where(Schedule.tenant_id == tenant_id)
            .order_by(Schedule.created_at.desc())
        ).scalars().all())

    def delete(self, tenant_id: str, schedule_id: str) -> bool:
        s = self.db.get(Schedule, schedule_id)
        if not s or s.tenant_id != tenant_id:
            return False
        self.db.delete(s)
        self.db.flush()
        return True

    def run(self, schedule_id: str) -> dict:
        s = self.db.get(Schedule, schedule_id)
        if not s:
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
        errors: list[dict] = []
        try:
            for s in due:
                try:
                    svc._execute(s)
                    db.commit()
                    succeeded += 1
                except Exception as exc:  # noqa: BLE001
                    db.rollback()
                    logger.exception("run_due: schedule %s failed", s.schedule_id)
                    errors.append({"schedule_id": s.schedule_id, "error": str(exc)})
        finally:
            db.close()

        result = {"attempted": len(due), "succeeded": succeeded,
                  "failed": len(errors), "errors": errors}
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
