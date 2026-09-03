"""Drift is counted, not sampled.

`unified_trust` reports how many external pages the crawlers have seen change
recently — vendor trust pages, regulatory pages, advisories. It is tenant-level
context rather than a per-control multiplier, but it is the signal that ground
truth is moving underneath the estate, so a wrong number is wrong in the one
direction that matters.

It read the 50 most recent `changed` rows and then filtered them to the
fourteen-day window in Python, so any tenant past 50 detections reported
exactly 50, with nothing in the response saying it had been capped. More
churn produced the same reassuring figure.

The count is now exact and still bounded: rows come back newest first, so the
walk stops at the first row older than the cutoff. These tests pin both halves
— the count is right well past the old cap, and old rows stay excluded.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

# Imported at module scope, not inside the fixture: the crawler tables only
# register on Base.metadata when this module is imported, and conftest's
# create_all() runs before any fixture body does. A local import leaves the
# tables uncreated — which is also why _drift_signal treats the crawler plane
# as optional.
from app.crawler_models import CrawlResult, CrawlTarget
from app.services.trust_telemetry import _DRIFT_SAMPLE, _DRIFT_WINDOW_DAYS, unified_trust

TENANT = "t-drift"
#: Comfortably past the old cap of 50 and past one page of the walk, so a
#: regression to either bound shows up as a wrong count rather than landing on
#: a boundary and looking correct.
INSIDE = 237
OUTSIDE = 40


@pytest.fixture
def crawl_history(db_session):
    now = datetime.now(UTC)
    db_session.add(CrawlTarget(
        id="tgt-1", tenant_id=TENANT, kind="vendor_trust", name="acme trust",
        url="https://example.com/trust", domain="example.com"))

    for i in range(INSIDE):
        db_session.add(CrawlResult(
            id=f"in-{i:04d}", tenant_id=TENANT, target_id="tgt-1", status="changed",
            fetched_at=now - timedelta(hours=i % (_DRIFT_WINDOW_DAYS * 24 - 1))))
    for i in range(OUTSIDE):
        db_session.add(CrawlResult(
            id=f"out-{i:04d}", tenant_id=TENANT, target_id="tgt-1", status="changed",
            fetched_at=now - timedelta(days=_DRIFT_WINDOW_DAYS + 1 + i)))
    # Unchanged fetches are not drift and must not be counted.
    for i in range(25):
        db_session.add(CrawlResult(
            id=f"ok-{i:04d}", tenant_id=TENANT, target_id="tgt-1", status="ok",
            fetched_at=now - timedelta(hours=i)))
    db_session.commit()
    return TENANT


def test_every_change_in_the_window_is_counted(db_session, crawl_history):
    drift = unified_trust(db_session, TENANT)["drift"]
    assert drift["recent_changes"] == INSIDE, (
        "drift is capped rather than counted — a tenant with more churn than "
        f"the read bound reports the bound: {drift['recent_changes']}")


def test_changes_outside_the_window_are_excluded(db_session, crawl_history):
    drift = unified_trust(db_session, TENANT)["drift"]
    assert drift["window_days"] == _DRIFT_WINDOW_DAYS
    assert drift["recent_changes"] < INSIDE + OUTSIDE


def test_the_described_sample_stays_small(db_session, crawl_history):
    """Counting everything must not mean returning everything: the response
    describes a handful of changes and reports the true total alongside."""
    drift = unified_trust(db_session, TENANT)["drift"]
    assert len(drift["changes"]) == _DRIFT_SAMPLE
    assert drift["changes"][0]["target"] == "acme trust"
    assert drift["changes"][0]["kind"] == "vendor_trust"


def test_a_tenant_with_no_crawl_history_reports_no_drift(db_session):
    drift = unified_trust(db_session, "t-drift-empty")["drift"]
    assert drift["recent_changes"] == 0
