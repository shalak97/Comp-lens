"""A schedule must actually re-assess. It used not to.

The product's central claim is continuous compliance: schedules re-run
controls, posture moves when reality moves, drift fires, trends show a line.
None of that held.

Every assessment is deduplicated on an idempotency key. When the caller
supplies one, that is exactly right — it names one logical request, and a
retrying client or a double-clicked button must not become two findings. When
the caller supplies nothing, the key was derived from *what is being assessed*
(tenant / framework / control / source / asset), which is the same value every
time that control is evaluated on that asset — today, tomorrow, next quarter.
Treating that derived key as permanent meant the first evaluation was returned
unchanged forever: `run_single` short-circuited before the connector was even
called.

The scheduler was hit twice over. It stores its assessment requests verbatim,
so a request that carried an explicit key replayed that same key on every run —
frozen just as hard, and by the more careful caller.

The failure was invisible in exactly the wrong direction. `_execute` still
reported `ran=N`, `last_run_at` still advanced, and the trend snapshot recorded
the same figures indefinitely — a flat line that reads as a stable estate
rather than as an estate nobody is measuring. Nothing anywhere said "this
control has not been looked at since March".

These tests assert the connector is called again, which is the only thing that
distinguishes monitoring from a single measurement.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.models import AssessmentRequest, Finding, IdempotencyRecord, Schedule
from app.services.assessment import IMPLICIT_IDEMPOTENCY_WINDOW, AssessmentService


@pytest.fixture
def counting_demo(monkeypatch):
    """Count how many times a control is genuinely evaluated.

    Findings alone cannot answer this: a short-circuited call returns the old
    finding, so the row count stays 1 whether the connector ran or not. Only
    the connector knows.
    """
    from app.connectors.mock import MockConnector

    calls: list[tuple[str, str | None]] = []
    real = MockConnector.collect_telemetry

    def spy(self, control_id, asset_id, params):
        calls.append((control_id, asset_id))
        return real(self, control_id, asset_id, params)

    monkeypatch.setattr(MockConnector, "collect_telemetry", spy)
    return calls


def _schedule(tenant_id: str, controls: list[dict]) -> Schedule:
    return Schedule(
        tenant_id=tenant_id, name=f"sched-{tenant_id}", interval_minutes=60,
        controls=controls, enabled=True, next_run_at=datetime.now(UTC),
    )


def _request(control_id: str = "SC-7", **extra) -> dict:
    return {"framework": "NIST", "control_id": control_id, "source_system": "DEMO",
            "asset_id": "a1", "params": {}, **extra}


# ── the scheduler ──
def test_a_schedule_reassesses_on_every_run(db_session, counting_demo):
    """The headline behaviour. Three runs must be three assessments."""
    from app.services.scheduler import ScheduleService

    s = _schedule("t-sched", [_request()])
    db_session.add(s)
    db_session.commit()

    svc = ScheduleService(db_session)
    for _ in range(3):
        svc._execute(s)

    assert len(counting_demo) == 3, (
        f"schedule ran 3 times but the connector was called {len(counting_demo)} "
        "times — assessments are being served from the idempotency cache")


def test_a_schedule_whose_request_carries_an_explicit_key_still_reassesses(
        db_session, counting_demo):
    """The stored key is replayed identically each run, so it cannot be the
    whole key — otherwise the more careful caller gets the worse behaviour."""
    from app.services.scheduler import ScheduleService

    s = _schedule("t-sched-key", [_request(idempotency_key="pinned")])
    db_session.add(s)
    db_session.commit()

    svc = ScheduleService(db_session)
    svc._execute(s)
    svc._execute(s)

    assert len(counting_demo) == 2


def test_a_schedule_records_a_finding_per_run(db_session, counting_demo):
    """Findings are the audit log: an assessment that happened must leave one.

    Posture stays at a single row — one per (tenant, control, source, asset) —
    which is what makes drift and freshness computable.
    """
    from app.models import Posture
    from app.services.scheduler import ScheduleService

    s = _schedule("t-sched-log", [_request()])
    db_session.add(s)
    db_session.commit()

    svc = ScheduleService(db_session)
    svc._execute(s)
    svc._execute(s)

    findings = db_session.execute(
        select(Finding).where(Finding.tenant_id == "t-sched-log")).scalars().all()
    postures = db_session.execute(
        select(Posture).where(Posture.tenant_id == "t-sched-log")).scalars().all()
    assert len(findings) == 2, "each run must append to the findings log"
    assert len(postures) == 1, "posture is current state, not history"


def test_one_run_still_dedupes_a_repeated_control(db_session, counting_demo):
    """Scoping the key per run must not lose within-run deduplication: a
    schedule listing the same control twice is one thing to assess, not two."""
    from app.services.scheduler import ScheduleService

    s = _schedule("t-sched-dupe", [_request(idempotency_key="same"),
                                   _request(idempotency_key="same")])
    db_session.add(s)
    db_session.commit()

    ScheduleService(db_session)._execute(s)
    assert len(counting_demo) == 1


# ── the underlying idempotency rule ──
def test_an_immediate_retry_is_still_deduplicated(db_session, counting_demo):
    """What the derived key is genuinely for. A double-clicked button or a
    client retry must not become two findings."""
    svc = AssessmentService(db_session)
    req = AssessmentRequest(tenant_id="t-retry", **_request())
    first = svc.run_single(req)
    second = svc.run_single(AssessmentRequest(tenant_id="t-retry", **_request()))

    assert first.finding_id == second.finding_id
    assert len(counting_demo) == 1


def test_the_same_assessment_reruns_once_the_window_has_passed(db_session, counting_demo):
    """The same request, later, is a new measurement rather than a retry."""
    svc = AssessmentService(db_session)
    first = svc.run_single(AssessmentRequest(tenant_id="t-window", **_request()))

    _age_records(db_session, "t-window")

    second = svc.run_single(AssessmentRequest(tenant_id="t-window", **_request()))
    assert len(counting_demo) == 2
    assert second.finding_id != first.finding_id


def test_renewing_repoints_the_key_rather_than_leaving_a_duplicate(db_session, counting_demo):
    """The record is a primary key, so a re-assessment must update it in place.

    Inserting a second row for the same key raises IntegrityError, which the
    write path interprets as a lost idempotency race and answers by returning
    the *existing* finding — quietly restoring the bug it was meant to fix.
    """
    svc = AssessmentService(db_session)
    svc.run_single(AssessmentRequest(tenant_id="t-repoint", **_request()))
    _age_records(db_session, "t-repoint")
    latest = svc.run_single(AssessmentRequest(tenant_id="t-repoint", **_request()))

    records = db_session.execute(
        select(IdempotencyRecord).where(
            IdempotencyRecord.tenant_id == "t-repoint")).scalars().all()
    assert len(records) == 1
    assert records[0].finding_id == latest.finding_id, "key still points at the stale finding"


def test_an_explicit_key_dedupes_for_good(db_session, counting_demo):
    """A caller-supplied key names one request, not a moment in time. Ageing it
    must not turn one logical submission into two findings."""
    svc = AssessmentService(db_session)
    first = svc.run_single(AssessmentRequest(
        tenant_id="t-explicit", **_request(idempotency_key="order-42")))
    _age_records(db_session, "t-explicit")
    second = svc.run_single(AssessmentRequest(
        tenant_id="t-explicit", **_request(idempotency_key="order-42")))

    assert first.finding_id == second.finding_id
    assert len(counting_demo) == 1


def _age_records(db_session, tenant_id: str) -> None:
    """Push a tenant's idempotency records past the window.

    Cheaper and more precise than sleeping, and it keeps the test honest about
    what it is asserting: elapsed time, not some other state change.
    """
    stale = datetime.now(UTC) - IMPLICIT_IDEMPOTENCY_WINDOW - timedelta(minutes=1)
    for rec in db_session.execute(
            select(IdempotencyRecord).where(
                IdempotencyRecord.tenant_id == tenant_id)).scalars().all():
        rec.created_at = stale
    db_session.commit()
