"""Regression tests for the evidence-store / DB ordering fix in _commit_finding.

Before the fix, `_commit_finding` committed the Finding + EvidenceMeta rows to
the DB *before* writing the telemetry artifact to the evidence store. A store
outage after the DB commit left a permanently orphaned EvidenceMeta row — a
hash promising an artifact that was never written — and IntegrityService.verify()
reports that state as "missing_in_store", the exact same signal it uses for
deliberate tampering. Retrying the same request made it worse: the idempotency
check returned the already-committed (broken) Finding without ever re-attempting
the store write, so the gap was permanent.

These tests exercise the fixed ordering: the store write happens first, so a
store failure never leaves a DB row behind, and a retry genuinely retries.
"""
from __future__ import annotations

import pytest
from sqlalchemy import select


def test_store_failure_leaves_no_db_row_at_all(db_session, monkeypatch):
    """A store outage must not commit a Finding/EvidenceMeta pair the store
    can't back up — the DB write should never happen if the artifact write
    failed first."""
    from app.models import ControlStatus, EvidenceMeta, Finding, Severity
    from app.services import assessment as assessment_mod
    from app.services.assessment import AssessmentService

    def boom(**kwargs):
        raise RuntimeError("simulated evidence-store outage")

    monkeypatch.setattr(assessment_mod.evidence_store, "store", boom)

    with pytest.raises(RuntimeError, match="simulated evidence-store outage"):
        AssessmentService(db_session).record_external_finding(
            tenant_id="t-outage", framework="NIST", control_id="SC-7",
            source_system="TEST", asset_id="a1", status=ControlStatus.FAIL,
            severity=Severity.HIGH, external_id="e-outage")
    db_session.rollback()

    assert db_session.execute(
        select(Finding).where(Finding.tenant_id == "t-outage")).first() is None
    assert db_session.execute(
        select(EvidenceMeta).where(EvidenceMeta.tenant_id == "t-outage")).first() is None


def test_retry_after_outage_clears_actually_retries_the_store_write(db_session, monkeypatch):
    """Because nothing was committed on the failed attempt, a retry with the
    same idempotency key must genuinely re-attempt the store write — not
    short-circuit on a broken committed row."""
    from app.models import ControlStatus, EvidenceMeta, Finding, Severity
    from app.services import assessment as assessment_mod
    from app.services.assessment import AssessmentService

    real_store = assessment_mod.evidence_store.store
    calls = {"n": 0}

    def flaky(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("outage")
        return real_store(**kwargs)

    monkeypatch.setattr(assessment_mod.evidence_store, "store", flaky)
    svc = AssessmentService(db_session)

    with pytest.raises(RuntimeError, match="outage"):
        svc.record_external_finding(
            tenant_id="t-retry", framework="NIST", control_id="SC-7",
            source_system="TEST", asset_id="a1", status=ControlStatus.FAIL,
            severity=Severity.HIGH, external_id="e-retry")
    db_session.rollback()

    finding = svc.record_external_finding(
        tenant_id="t-retry", framework="NIST", control_id="SC-7",
        source_system="TEST", asset_id="a1", status=ControlStatus.FAIL,
        severity=Severity.HIGH, external_id="e-retry")
    db_session.commit()

    assert calls["n"] == 2, "the retry must re-attempt the store write, not skip it"
    assert finding is not None
    row = db_session.execute(
        select(Finding).where(Finding.tenant_id == "t-retry")).scalar_one()
    assert row.finding_id == finding.finding_id
    ev = db_session.execute(
        select(EvidenceMeta).where(EvidenceMeta.tenant_id == "t-retry")).scalar_one()
    assert ev.object_uri is not None, "a committed EvidenceMeta row must have a real artifact URI"


def test_successful_write_never_reports_as_tampered(db_session):
    """The failure this fix targets is specifically that a store outage was
    indistinguishable from tampering after the fact. Confirm the healthy path
    still verifies clean — the guard that matters is in the two tests above
    (no broken row is ever committed in the first place)."""
    from app.models import ControlStatus, Severity
    from app.services.assessment import AssessmentService
    from app.services.integrity import IntegrityService

    AssessmentService(db_session).record_external_finding(
        tenant_id="t-clean", framework="NIST", control_id="SC-7",
        source_system="TEST", asset_id="a1", status=ControlStatus.FAIL,
        severity=Severity.HIGH, external_id="e-clean")
    db_session.commit()

    report = IntegrityService(db_session).verify("t-clean")
    assert report["intact"] is True
    assert report["broken_count"] == 0


def test_object_uri_is_never_null_on_a_committed_evidence_row(db_session):
    """The old two-phase write (insert with object_uri=None, patch after)
    is gone; a committed row must carry its real URI from the start."""
    from app.models import ControlStatus, EvidenceMeta, Severity
    from app.services.assessment import AssessmentService

    AssessmentService(db_session).record_external_finding(
        tenant_id="t-uri", framework="NIST", control_id="SC-7",
        source_system="TEST", asset_id="a1", status=ControlStatus.FAIL,
        severity=Severity.HIGH, external_id="e-uri")
    db_session.commit()

    ev = db_session.execute(
        select(EvidenceMeta).where(EvidenceMeta.tenant_id == "t-uri")).scalar_one()
    assert ev.object_uri
