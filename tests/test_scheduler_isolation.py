"""Regression tests for per-schedule transaction isolation in run_due().

Before the fix, every due schedule in one tick shared a single transaction
committed once at the end. An exception anywhere in the batch — even in a
schedule that has nothing to do with an earlier one, like a later schedule's
trend snapshot failing — rolled back every schedule already processed that
tick. Findings that had genuinely been assessed (and whose evidence had
already been durably written to the store) were silently discarded, next_run_at
was never advanced, and the only symptom was a debug log line plus the same
schedule quietly re-running forever.

These tests drive two schedules through one run_due() tick, break the second
one, and assert the first one's work survives and is reported honestly.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select


def _due_schedule(tenant_id: str, control_id: str = "SC-7") -> Schedule:
    from app.models import Schedule

    return Schedule(
        tenant_id=tenant_id,
        name=f"sched-{tenant_id}",
        interval_minutes=60,
        controls=[{"framework": "NIST", "control_id": control_id,
                  "source_system": "DEMO", "asset_id": "a1", "params": {}}],
        enabled=True,
        next_run_at=datetime.now(UTC) - timedelta(minutes=1),
    )


def test_one_schedules_failure_does_not_roll_back_another_schedules_success(db_session, monkeypatch):
    from app.models import Finding
    from app.services import scheduler as scheduler_mod
    from app.services.scheduler import ScheduleService
    from app.services.trends import TrendService

    good = _due_schedule("t-good")
    bad = _due_schedule("t-bad")
    db_session.add_all([good, bad])
    db_session.commit()

    real_snapshot = TrendService.snapshot

    def flaky_snapshot(self, tenant_id, summary, framework="ALL"):
        if tenant_id == "t-bad":
            raise RuntimeError("simulated trend snapshot failure")
        return real_snapshot(self, tenant_id, summary, framework)

    monkeypatch.setattr(TrendService, "snapshot", flaky_snapshot)
    monkeypatch.setattr(scheduler_mod, "SessionLocal", lambda: db_session)
    # SessionLocal.close() would end db_session for the rest of the test suite;
    # the fixture owns that lifecycle, so make close() on the injected session
    # a no-op for this test only.
    monkeypatch.setattr(db_session, "close", lambda: None)

    result = ScheduleService.run_due()

    assert result["attempted"] == 2
    assert result["succeeded"] == 1
    assert result["failed"] == 1
    assert result["errors"] == [{"schedule_id": bad.schedule_id,
                                 "error": "simulated trend snapshot failure"}]

    # the good schedule's finding survived the bad schedule's rollback
    good_finding = db_session.execute(
        select(Finding).where(Finding.tenant_id == "t-good")).first()
    assert good_finding is not None, (
        "an unrelated schedule's failure must not discard this schedule's "
        "already-completed, already-committed work")

    # the bad schedule's finding must NOT have partially landed
    bad_finding = db_session.execute(
        select(Finding).where(Finding.tenant_id == "t-bad")).first()
    assert bad_finding is None, (
        "a schedule whose tick failed must not leave a partial finding behind")


def test_failed_schedule_stays_due_for_immediate_retry(db_session, monkeypatch):
    """next_run_at must not advance for a schedule whose tick failed — a
    rolled-back attempt should be retried on the next poll, not silently
    skipped until the full interval elapses."""
    from app.services import scheduler as scheduler_mod
    from app.services.scheduler import ScheduleService
    from app.services.trends import TrendService

    bad = _due_schedule("t-bad-retry")
    db_session.add(bad)
    db_session.commit()
    original_next_run = bad.next_run_at

    def always_fails(self, tenant_id, summary, framework="ALL"):
        raise RuntimeError("boom")

    monkeypatch.setattr(TrendService, "snapshot", always_fails)
    monkeypatch.setattr(scheduler_mod, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(db_session, "close", lambda: None)

    result = ScheduleService.run_due()
    assert result["failed"] == 1

    db_session.refresh(bad)
    assert bad.next_run_at == original_next_run, (
        "a failed tick must not push next_run_at forward — the schedule "
        "should still be due on the next poll")


def test_all_schedules_succeed_reports_zero_errors(db_session, monkeypatch):
    from app.services import scheduler as scheduler_mod
    from app.services.scheduler import ScheduleService

    s = _due_schedule("t-ok")
    db_session.add(s)
    db_session.commit()

    monkeypatch.setattr(scheduler_mod, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(db_session, "close", lambda: None)

    result = ScheduleService.run_due()
    assert result == {"attempted": 1, "succeeded": 1, "failed": 0, "errors": []}
