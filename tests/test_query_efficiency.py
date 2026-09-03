"""Work that grows with the estate, pinned by counting queries.

Correctness tests do not notice an N+1. A loop issuing one SELECT per row
returns exactly the right answer, passes every assertion about that answer, and
falls over the first time a customer has ten thousand of something. The only
way to catch it is to count the round trips and assert the count does not track
the row count.

So each test here runs the same operation at two sizes and asserts the query
count is flat. The absolute numbers are deliberately loose — a refactor that
adds one query is fine, a refactor that adds one query *per asset* is the
regression — but they are bounded, because "flat" stated without a ceiling is
satisfied by any constant, including a large one.

Discovery is the sharpest case. It was one SELECT per discovered asset, which
was survivable only because the Okta and GitHub connectors fetched a single
page of fifty. Fixing those connectors to enumerate the whole estate turned the
same loop into three thousand queries for a three thousand seat org — a
performance bug created by a correctness fix, which is exactly the pairing a
correctness-only suite cannot see.
"""
from __future__ import annotations

from contextlib import contextmanager

import pytest
from sqlalchemy import event

# Imported at module scope, not inside the tests: these tables only register on
# Base.metadata when the module is imported, and conftest's create_all() runs
# before any test body does.
from app.audit_models import Audit, AuditControl, EvidenceRequest  # noqa: E402
from app.connectors.base import Asset
from app.models import AssetRecord
from app.services.audit_service import AuditService  # noqa: E402
from app.services.inventory import InventoryService


@contextmanager
def counted(session):
    """Count SQL statements issued on this session's connection."""
    stmts: list[str] = []

    def before(conn, cursor, statement, params, context, executemany):
        stmts.append(statement)

    engine = session.get_bind()
    event.listen(engine, "before_cursor_execute", before)
    try:
        yield stmts
    finally:
        event.remove(engine, "before_cursor_execute", before)


class _FakeConnector:
    """A connector that enumerates however many assets the test asks for."""

    def __init__(self, n: int, source: str = "DEMO") -> None:
        self.n, self.source = n, source

    def discover_assets(self, params):
        return [Asset(asset_id=f"asset-{i:05d}", asset_type="host",
                      source_system=self.source, owner="team")
                for i in range(self.n)]


@pytest.fixture
def fake_registry(monkeypatch):
    def use(n, source="DEMO"):
        from app.services import inventory
        monkeypatch.setattr(inventory.registry, "get", lambda _s: _FakeConnector(n, source))
    return use


def _discover_queries(db_session, fake_registry, tenant, n) -> int:
    fake_registry(n)
    with counted(db_session) as stmts:
        InventoryService(db_session).discover(tenant, "DEMO", {})
    # Inserts scale with new rows and are the actual work; reads are what the
    # N+1 was, so those are what gets counted.
    return sum(1 for s in stmts if s.lstrip().upper().startswith("SELECT"))


def test_discovery_reads_do_not_grow_with_the_estate(db_session, fake_registry):
    small = _discover_queries(db_session, fake_registry, "t-disc-small", 5)
    large = _discover_queries(db_session, fake_registry, "t-disc-large", 400)
    assert large == small, (
        f"discovery issued {small} reads for 5 assets and {large} for 400 — "
        "one query per asset is back")
    assert large <= 3, f"discovery should read once, not {large} times"


def test_discovery_still_finds_everything(db_session, fake_registry):
    """The efficiency fix must not cost completeness."""
    fake_registry(250)
    n = InventoryService(db_session).discover("t-disc-all", "DEMO", {})
    assert n == 250
    rows = db_session.query(AssetRecord).filter_by(tenant_id="t-disc-all").all()
    assert len(rows) == 250


def test_rediscovery_updates_in_place_and_stays_flat(db_session, fake_registry):
    fake_registry(120)
    svc = InventoryService(db_session)
    assert svc.discover("t-disc-again", "DEMO", {}) == 120

    fake_registry(120)
    with counted(db_session) as stmts:
        assert svc.discover("t-disc-again", "DEMO", {}) == 0, "re-discovery created duplicates"
    reads = sum(1 for s in stmts if s.lstrip().upper().startswith("SELECT"))
    assert reads <= 3, f"re-discovery issued {reads} reads"
    assert db_session.query(AssetRecord).filter_by(tenant_id="t-disc-again").count() == 120


def test_a_connector_returning_the_same_asset_twice_stores_it_once(db_session, monkeypatch):
    """A correctness bug the batched lookup fixes on the way past.

    A pending INSERT is not visible to a later SELECT in the same flush, so the
    per-asset existence check could not see a row the same call had just added.
    A connector listing an asset twice therefore inserted it twice.
    """
    from app.services import inventory

    class Dupes:
        def discover_assets(self, params):
            a = Asset(asset_id="same-one", asset_type="host",
                      source_system="DEMO", owner="team")
            return [a, a, a]

    monkeypatch.setattr(inventory.registry, "get", lambda _s: Dupes())
    assert InventoryService(db_session).discover("t-disc-dupe", "DEMO", {}) == 1
    assert db_session.query(AssetRecord).filter_by(tenant_id="t-disc-dupe").count() == 1


# ── audit progress ──
def _audit_with_requests(db_session, tenant, n_audits):
    ids = []
    for i in range(n_audits):
        a = Audit(id=f"aud-{tenant}-{i}", tenant_id=tenant, name=f"audit {i}",
                  framework="NIST", status="planning")
        db_session.add(a)
        ids.append(a.id)
        for j in range(20):
            db_session.add(AuditControl(
                id=f"ac-{tenant}-{i}-{j}", audit_id=a.id, tenant_id=tenant,
                control_id=f"AC-{j}", title=f"c{j}",
                review_state="approved" if j < 5 else "not_started"))
        db_session.add(EvidenceRequest(
            id=f"er-{tenant}-{i}", audit_id=a.id, tenant_id=tenant,
            title="provide evidence", state="open"))
    db_session.commit()
    return ids


def test_listing_audits_does_not_query_per_audit(db_session):
    """list() served each audit's progress with its own pair of queries, and
    loaded every control row in full to count six integers."""
    _audit_with_requests(db_session, "t-aud-one", 1)
    _audit_with_requests(db_session, "t-aud-many", 12)
    svc = AuditService(db_session)

    with counted(db_session) as one:
        assert len(svc.list("t-aud-one")) == 1
    with counted(db_session) as many:
        assert len(svc.list("t-aud-many")) == 12

    assert len(many) == len(one), (
        f"{len(one)} queries for one audit, {len(many)} for twelve — "
        "progress is still computed per audit")
    assert len(many) <= 4, f"listing audits takes {len(many)} queries"


def test_audit_progress_is_still_correct(db_session):
    """Counting in SQL must produce the same six numbers as counting in Python."""
    ids = _audit_with_requests(db_session, "t-aud-num", 2)
    rows = {r["id"]: r for r in AuditService(db_session).list("t-aud-num")}
    for audit_id in ids:
        r = rows[audit_id]
        assert r["controls_total"] == 20
        assert r["controls_approved"] == 5
        assert r["readiness_pct"] == 25          # 5 of 20 reviewed
        assert r["approval_pct"] == 25
        assert r["evidence_requests_total"] == 1
        assert r["evidence_requests_open"] == 1


def test_deleting_an_audit_does_not_issue_a_delete_per_row(db_session):
    ids = _audit_with_requests(db_session, "t-aud-del", 1)
    svc = AuditService(db_session)
    with counted(db_session) as stmts:
        assert svc.delete("t-aud-del", ids[0]) is True
    deletes = sum(1 for s in stmts if s.lstrip().upper().startswith("DELETE"))
    assert deletes <= 3, f"{deletes} DELETEs to remove one audit with 20 controls"
    assert db_session.query(AuditControl).filter_by(audit_id=ids[0]).count() == 0


def test_deleting_one_tenants_audit_leaves_anothers_rows(db_session):
    """The bulk delete is tenant-scoped, so a shared audit id cannot reach across."""
    mine = _audit_with_requests(db_session, "t-del-a", 1)
    _audit_with_requests(db_session, "t-del-b", 1)
    AuditService(db_session).delete("t-del-a", mine[0])
    assert db_session.query(AuditControl).filter_by(tenant_id="t-del-b").count() == 20


# ── bundle config ──
def test_the_policy_bundle_config_is_parsed_once_per_version(tmp_path, monkeypatch):
    """Read on every enforcement call and every unified-trust request. It must
    not be reparsed each time — but it must not go stale either, because
    set_mode() rewrites the file to flip a system into enforce."""
    import json

    from app.services import enforcement

    monkeypatch.setattr(enforcement, "POLICY_DIR", tmp_path)
    enforcement._systems_config_at.cache_clear()
    path = tmp_path / "data.json"
    path.write_text(json.dumps({"systems": {"api": {"mode": "shadow"}}}))

    assert enforcement._systems_config()["api"]["mode"] == "shadow"
    for _ in range(20):
        enforcement._systems_config()
    assert enforcement._systems_config_at.cache_info().misses == 1, "config reparsed per call"

    # A rewrite must be picked up, or an operator flips to enforce and the
    # platform keeps reporting shadow.
    path.write_text(json.dumps({"systems": {"api": {"mode": "enforce", "fail": "closed"}}}))
    assert enforcement._systems_config()["api"]["mode"] == "enforce", "cache served a stale bundle"


def test_a_missing_bundle_is_empty_rather_than_an_error(tmp_path, monkeypatch):
    from app.services import enforcement

    monkeypatch.setattr(enforcement, "POLICY_DIR", tmp_path / "nope")
    enforcement._systems_config_at.cache_clear()
    assert enforcement._systems_config() == {}
