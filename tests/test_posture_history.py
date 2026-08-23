"""Bitemporal posture history (needs SQLAlchemy — runs in CI via db_session).

Verifies that status transitions are recorded as valid-time intervals and that
posture can be reconstructed 'as of' a point in time.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta


def _record(db, control_id, status, ext, sev):
    from app.services.assessment import AssessmentService
    AssessmentService(db).record_external_finding(
        tenant_id="th", framework="NIST", control_id=control_id, source_system="TEST",
        asset_id="a", status=status, severity=sev, external_id=ext)
    db.commit()


def test_transitions_recorded_and_reconstructable(db_session):
    from app.models import ControlStatus, Severity
    from app.services import posture_history as ph

    _record(db_session, "AC-2", ControlStatus.FAIL, "f1", Severity.HIGH)
    time.sleep(0.02)
    _record(db_session, "AC-2", ControlStatus.PASS, "f2", Severity.LOW)

    tl = ph.timeline(db_session, "th", "AC-2")
    assert [i["status"] for i in tl] == ["fail", "pass"]
    assert tl[0]["valid_to"] is not None    # first interval was closed
    assert tl[1]["valid_to"] is None        # current interval is open

    now = datetime.now(UTC)
    assert ph.as_of(db_session, "th", now)[0]["status"] == "pass"          # current
    t_fail = datetime.fromisoformat(tl[0]["valid_from"])
    assert ph.as_of(db_session, "th", t_fail)[0]["status"] == "fail"        # as of the past
    assert ph.as_of(db_session, "th", now - timedelta(days=1)) == []        # before it existed


def test_unchanged_status_does_not_add_interval(db_session):
    from app.models import ControlStatus, Severity
    from app.services import posture_history as ph
    _record(db_session, "SC-7", ControlStatus.FAIL, "s1", Severity.MEDIUM)
    _record(db_session, "SC-7", ControlStatus.FAIL, "s2", Severity.MEDIUM)  # same status
    tl = ph.timeline(db_session, "th", "SC-7")
    assert len(tl) == 1   # no new interval for an unchanged status
