"""Losing a race is not a server error.

Iteration 5 of a fault-finding sweep, instrument: concurrency and idempotency.

Six places SELECT a row, branch on whether it came back, and INSERT if it did
not. Between the SELECT and the INSERT another worker can insert the same row.
The reassuring half, established by checking every table rather than assuming:
**each of those upserts is backed by a UNIQUE constraint on exactly the key
being upserted** — uq_sync_tenant_connector, uq_evidence_doc_hash, and the
Posture tuple. No race has ever produced a duplicate; the database refuses the
second INSERT.

The unreassuring half is what happened next. Nothing caught the refusal, so
three paths turned a lost race into an unhandled IntegrityError:

    POST /connectors/{name}/sync   a manual sync overlapping a scheduled one —
                                   the scheduler leases SCHEDULES, not
                                   connectors, so these genuinely overlap
    POST /evidence/documents       two uploads of the same content
    policy evaluation             two runs materialising the same posture cell

Each surfaced as a 500 for an operation that had actually succeeded, just in
someone else's transaction — and the retry then worked, which is the most
confusing symptom a bug can have.

`get_or_create` inserts inside a SAVEPOINT and, on refusal, reads the row the
winner wrote. The savepoint is the part that matters: without it the failed
INSERT poisons the enclosing transaction and everything already done in it is
lost.
"""
from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from app.models import ConnectorSyncState
from app.services.upsert import get_or_create


def test_it_creates_a_row_that_is_not_there(db_session):
    row, created = get_or_create(
        db_session, ConnectorSyncState,
        match={"tenant_id": "t1", "connector_key": "AWS"},
        defaults={"status": "ok"})
    assert created is True
    assert row.tenant_id == "t1" and row.connector_key == "AWS"
    assert row.status == "ok"


def test_it_returns_the_existing_row_rather_than_a_second_one(db_session):
    first, created_first = get_or_create(
        db_session, ConnectorSyncState,
        match={"tenant_id": "t1", "connector_key": "AWS"})
    db_session.commit()
    second, created_second = get_or_create(
        db_session, ConnectorSyncState,
        match={"tenant_id": "t1", "connector_key": "AWS"})
    assert created_first is True and created_second is False
    assert second.id == first.id


def test_defaults_are_not_reapplied_to_an_existing_row(db_session):
    """`defaults` describes how to CREATE the row. Applying them on a hit would
    silently revert whatever the row had been updated to."""
    row, _ = get_or_create(db_session, ConnectorSyncState,
                           match={"tenant_id": "t1", "connector_key": "AWS"},
                           defaults={"status": "ok"})
    row.status = "degraded"
    db_session.commit()
    again, created = get_or_create(db_session, ConnectorSyncState,
                                   match={"tenant_id": "t1", "connector_key": "AWS"},
                                   defaults={"status": "ok"})
    assert created is False
    assert again.status == "degraded"


def test_losing_the_race_returns_the_winners_row_instead_of_raising(db_session, monkeypatch):
    """The actual defect. Simulated by making the initial SELECT miss a row
    that is really there — which is exactly what a concurrent inserter looks
    like from inside this transaction."""
    db_session.add(ConnectorSyncState(tenant_id="t1", connector_key="AWS",
                                      status="written-by-the-winner"))
    db_session.commit()

    real_execute = db_session.execute
    calls = {"n": 0}

    class _Empty:
        def scalars(self):
            return self

        def first(self):
            return None

    def _blind_first_select(stmt, *a, **kw):
        # Miss once — the stale read — then behave normally, so the recovery
        # path has to find the winner by re-reading.
        calls["n"] += 1
        if calls["n"] == 1:
            return _Empty()
        return real_execute(stmt, *a, **kw)

    monkeypatch.setattr(db_session, "execute", _blind_first_select)
    row, created = get_or_create(db_session, ConnectorSyncState,
                                 match={"tenant_id": "t1", "connector_key": "AWS"})
    assert created is False, "the row existed; this transaction did not create it"
    assert row.status == "written-by-the-winner"


def test_the_transaction_survives_a_lost_race(db_session, monkeypatch):
    """Without the SAVEPOINT, the refused INSERT poisons the whole
    transaction: work done before the upsert is rolled back too, and every
    later statement fails until someone rolls back explicitly."""
    db_session.add(ConnectorSyncState(tenant_id="t1", connector_key="AWS"))
    db_session.commit()
    db_session.add(ConnectorSyncState(tenant_id="t1", connector_key="OKTA"))

    real_execute = db_session.execute
    calls = {"n": 0}

    class _Empty:
        def scalars(self):
            return self

        def first(self):
            return None

    def _blind(stmt, *a, **kw):
        calls["n"] += 1
        return _Empty() if calls["n"] == 1 else real_execute(stmt, *a, **kw)

    monkeypatch.setattr(db_session, "execute", _blind)
    get_or_create(db_session, ConnectorSyncState,
                  match={"tenant_id": "t1", "connector_key": "AWS"})
    monkeypatch.undo()
    db_session.commit()

    keys = {r.connector_key for r in
            db_session.query(ConnectorSyncState).filter_by(tenant_id="t1").all()}
    assert keys == {"AWS", "OKTA"}, (
        "work done before the lost race was rolled back with it")


def test_a_violation_that_is_not_this_race_is_not_swallowed(db_session):
    """If the constraint refuses the insert but no matching row appears, the
    cause was a different constraint — reporting that as a quiet hit would
    hide a real schema violation."""
    with pytest.raises(IntegrityError):
        get_or_create(db_session, ConnectorSyncState,
                      match={"tenant_id": None, "connector_key": None})


# ── the sites that were racing ──
def test_a_repeated_document_upload_is_still_one_document(db_session):
    """Idempotency by content hash, which the fix had to preserve: the same
    document uploaded twice is one row, with its old concept hits cleared
    rather than accumulated."""
    from app.models import EvidenceDocument
    from app.services.evidence_graph import EvidenceService

    svc = EvidenceService(db_session)
    svc.add_document("t1", "policy.md", "AC-2 accounts are reviewed quarterly.")
    svc.add_document("t1", "policy-again.md", "AC-2 accounts are reviewed quarterly.")
    docs = db_session.query(EvidenceDocument).filter_by(tenant_id="t1").all()
    assert len(docs) == 1


def test_every_racing_upsert_is_backed_by_a_unique_constraint():
    """get_or_create can only recover from a race the DATABASE refuses. On a
    table with no constraint on the match key, both inserts succeed and the
    duplicate is silent — so the helper would give false confidence."""
    from app.models import ConnectorSyncState as CSS
    from app.models import EvidenceDocument, Posture

    def constrained_columns(model) -> set[frozenset[str]]:
        out = set()
        for c in model.__table__.constraints:
            cols = frozenset(col.name for col in getattr(c, "columns", []))
            if cols and type(c).__name__ in ("UniqueConstraint", "PrimaryKeyConstraint"):
                out.add(cols)
        return out

    assert frozenset({"tenant_id", "connector_key"}) in constrained_columns(CSS)
    assert frozenset({"tenant_id", "content_hash"}) in constrained_columns(EvidenceDocument)
    assert frozenset({"tenant_id", "control_id", "source_system", "asset_key"}) \
        in constrained_columns(Posture)
