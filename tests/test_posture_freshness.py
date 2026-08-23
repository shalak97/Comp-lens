"""Posture freshness columns (needs SQLAlchemy — runs in CI via db_session).

Verifies that recording a finding stamps the materialized posture row with a
validation cadence and a next_validation expiry (the freshness guarantee).
"""
from __future__ import annotations

from sqlalchemy import select


def test_posture_row_gets_cadence_and_next_validation(db_session):
    from app.models import ControlStatus, Posture, Severity
    from app.services.assessment import AssessmentService
    from app.services.freshness import freshness

    AssessmentService(db_session).record_external_finding(
        tenant_id="tf", framework="NIST", control_id="AC-2", source_system="TEST",
        asset_id="a1", status=ControlStatus.FAIL, severity=Severity.HIGH,
        description="dormant accounts", external_id="e1")
    db_session.commit()

    p = db_session.execute(
        select(Posture).where(Posture.tenant_id == "tf")).scalar_one()
    assert p.cadence == "monthly"
    assert p.next_validation is not None
    # next_validation is one cadence period after the last validation (updated_at)
    assert 29 <= (p.next_validation - p.updated_at).days <= 31
    # a just-validated row is not stale
    assert freshness(p.updated_at, p.cadence, now=p.updated_at)["is_stale"] is False


def test_reassessment_refreshes_next_validation(db_session):
    from app.models import ControlStatus, Posture, Severity
    from app.services.assessment import AssessmentService
    svc = AssessmentService(db_session)
    svc.record_external_finding(
        tenant_id="tf2", framework="NIST", control_id="SC-7", source_system="TEST",
        asset_id="a", status=ControlStatus.FAIL, severity=Severity.MEDIUM, external_id="a1")
    db_session.commit()
    first = db_session.execute(
        select(Posture).where(Posture.tenant_id == "tf2")).scalar_one().next_validation
    # a new finding on the same cell re-validates and pushes next_validation forward
    svc.record_external_finding(
        tenant_id="tf2", framework="NIST", control_id="SC-7", source_system="TEST",
        asset_id="a", status=ControlStatus.PASS, severity=Severity.LOW, external_id="a2")
    db_session.commit()
    second = db_session.execute(
        select(Posture).where(Posture.tenant_id == "tf2")).scalar_one().next_validation
    assert second >= first
