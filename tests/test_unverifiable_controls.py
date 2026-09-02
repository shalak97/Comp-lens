"""An asset we could not read is not an asset that passed.

Fan-out assessment — bulk_assess over an inventory, run_batch over a list of
requests — used to answer a connector failure by incrementing a counter and
writing nothing. The asset then had no posture row at all, so it left the
denominator: a control that errored on 400 of 500 assets produced a compliance
score computed over the 100 that worked, reported as the tenant's score with
nothing marking the hole. Less of the estate was measured and the number went
*up*, because the assets that could not be read were the ones dropped.

ERROR is the honest status, and the summary already handled it correctly —
error rows count as applicable but not as passes. Nothing was writing them.
This is the same tri-state discipline the evaluator applies to a missing
signal: "we could not observe this" is its own answer, distinct from both "it
is fine" and "it is wrong".

The other half is knowing when *not* to write one. An unroutable request — an
unknown source system, or one whose credentials are unset — is a bad request or
a deployment gap, not a fact about the estate. Recording a finding per
malformed request would fill the audit log with the consequences of a typo, so
those are reported and nothing is persisted. These tests pin both sides.
"""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models import (
    AssessmentRequest,
    AssetRecord,
    ControlStatus,
    EvidenceMeta,
    Finding,
    Posture,
)
from app.services.assessment import AssessmentService
from app.services.inventory import InventoryService

TENANT = "t-unverifiable"
CONTROL = "SC-28-OBJSTORE-KMS"        # declarative, asset_type object_storage
READABLE = ["bucket-ok-1", "bucket-ok-2"]
UNREADABLE = ["bucket-down-1", "bucket-down-2", "bucket-down-3"]


@pytest.fixture
def estate(db_session):
    """Five object-storage assets, three of which the connector cannot read."""
    for asset_id in READABLE + UNREADABLE:
        db_session.add(AssetRecord(
            tenant_id=TENANT, asset_id=asset_id, asset_type="object_storage",
            source_system="DEMO", owner="cloud-platform-team"))
    db_session.commit()
    return TENANT


@pytest.fixture
def flaky_demo(monkeypatch):
    """DEMO, but three named buckets raise the way a real API outage does."""
    from app.connectors.base import ConnectorError
    from app.connectors.mock import MockConnector

    real = MockConnector.collect_telemetry

    def spy(self, control_id, asset_id, params):
        if asset_id in UNREADABLE:
            raise ConnectorError(f"DEMO: 503 reading {asset_id}")
        return real(self, control_id, asset_id, params)

    monkeypatch.setattr(MockConnector, "collect_telemetry", spy)


def _postures(db_session) -> dict[str, ControlStatus]:
    rows = db_session.execute(
        select(Posture).where(Posture.tenant_id == TENANT)).scalars().all()
    return {p.asset_id: p.status for p in rows}


# ── bulk_assess ──
def test_unreadable_assets_are_recorded_rather_than_dropped(db_session, estate, flaky_demo):
    result = InventoryService(db_session).bulk_assess(TENANT, "NIST", CONTROL, "DEMO", {})

    assert result["eligible_assets"] == 5
    assert result["assessed"] == 2
    assert result["failed"] == 3
    assert result["unverifiable"] == 3, "failures were counted but not recorded"

    statuses = _postures(db_session)
    assert set(statuses) == set(READABLE + UNREADABLE), (
        "an asset the connector could not read is missing from posture entirely")
    assert all(statuses[a] is ControlStatus.ERROR for a in UNREADABLE)


def test_the_score_is_computed_over_the_whole_estate(db_session, estate, flaky_demo):
    """The regression that matters.

    With the three unreadable buckets dropped, this tenant scored 100% — two of
    two. Every asset the platform failed to read made the number better.
    """
    InventoryService(db_session).bulk_assess(TENANT, "NIST", CONTROL, "DEMO", {})
    summary = AssessmentService(db_session).compliance_summary(TENANT)

    assert summary["total"] == 5
    assert summary["by_status"]["error"] == 3
    assert summary["compliance_score"] == 40.0, (
        "score must be computed over every eligible asset, not just the "
        f"readable ones: {summary}")


def test_an_unverifiable_finding_carries_no_evidence(db_session, estate, flaky_demo):
    """There is no evidence — so there must be no evidence record.

    Writing an artifact or an EvidenceMeta row for a collection that never
    happened would be fabricating exactly the thing this platform exists to
    verify.
    """
    InventoryService(db_session).bulk_assess(TENANT, "NIST", CONTROL, "DEMO", {})

    errors = db_session.execute(
        select(Finding).where(Finding.tenant_id == TENANT,
                              Finding.status == ControlStatus.ERROR)).scalars().all()
    assert len(errors) == 3
    for f in errors:
        assert f.evidence_ids == []
        assert "Could not verify" in (f.description or "")

    # The two readable buckets do have evidence; nothing else should.
    meta = db_session.execute(
        select(EvidenceMeta).where(EvidenceMeta.tenant_id == TENANT)).scalars().all()
    assert len(meta) == len(READABLE)
    assert all(m.status is not ControlStatus.ERROR for m in meta)


def test_posture_recovers_when_the_connector_does(db_session, estate, monkeypatch):
    """An ERROR is a statement about a moment, not a permanent verdict."""
    from app.connectors.base import ConnectorError
    from app.connectors.mock import MockConnector

    real = MockConnector.collect_telemetry
    broken = {"yes": True}

    def spy(self, control_id, asset_id, params):
        if broken["yes"] and asset_id in UNREADABLE:
            raise ConnectorError("DEMO: 503")
        return real(self, control_id, asset_id, params)

    monkeypatch.setattr(MockConnector, "collect_telemetry", spy)
    inv = InventoryService(db_session)
    inv.bulk_assess(TENANT, "NIST", CONTROL, "DEMO", {})
    assert all(_postures(db_session)[a] is ControlStatus.ERROR for a in UNREADABLE)

    broken["yes"] = False
    _age_idempotency(db_session)
    inv.bulk_assess(TENANT, "NIST", CONTROL, "DEMO", {})

    statuses = _postures(db_session)
    assert all(statuses[a] is not ControlStatus.ERROR for a in UNREADABLE), (
        "posture stayed ERROR after the connector recovered")


def test_an_unroutable_source_system_fails_the_call_and_writes_nothing(db_session, estate):
    """One misconfiguration must not become one junk finding per asset."""
    from app.connectors.base import ConnectorError

    with pytest.raises(ConnectorError):
        InventoryService(db_session).bulk_assess(TENANT, "NIST", CONTROL, "NOT_A_SYSTEM", {})

    assert db_session.execute(
        select(Finding).where(Finding.tenant_id == TENANT)).scalars().all() == []


# ── run_batch ──
def test_batch_records_what_it_could_not_verify(db_session, flaky_demo):
    requests = [
        AssessmentRequest(tenant_id=TENANT, framework="NIST", control_id=CONTROL,
                          source_system="DEMO", asset_id=a)
        for a in READABLE + UNREADABLE
    ]
    result = AssessmentService(db_session).run_batch(TENANT, requests)

    assert result["succeeded"] == 2
    assert result["failed"] == 3
    assert result["unverifiable"] == 3
    assert all(e["recorded"] is True for e in result["errors"])
    assert len(result["findings"]) == 5, "every request must leave a finding"


def test_batch_reports_an_unroutable_request_without_recording_it(db_session):
    result = AssessmentService(db_session).run_batch(TENANT, [
        AssessmentRequest(tenant_id=TENANT, framework="NIST", control_id=CONTROL,
                          source_system="NOT_A_SYSTEM", asset_id="x"),
    ])

    assert result["failed"] == 1
    assert result["unverifiable"] == 0
    assert result["errors"][0]["recorded"] is False
    assert db_session.execute(
        select(Finding).where(Finding.tenant_id == TENANT)).scalars().all() == []


def _age_idempotency(db_session) -> None:
    """Push this tenant's idempotency records past their dedupe window, so the
    second pass is a genuine re-assessment rather than a cached read."""
    from datetime import UTC, datetime, timedelta

    from app.models import IdempotencyRecord
    from app.services.assessment import IMPLICIT_IDEMPOTENCY_WINDOW

    stale = datetime.now(UTC) - IMPLICIT_IDEMPOTENCY_WINDOW - timedelta(minutes=1)
    for rec in db_session.execute(
            select(IdempotencyRecord).where(
                IdempotencyRecord.tenant_id == TENANT)).scalars().all():
        rec.created_at = stale
    db_session.commit()
