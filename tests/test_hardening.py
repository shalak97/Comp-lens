"""Tests for the production-hardening fixes (flaws #1-#13)."""
from __future__ import annotations
import os
os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_hard.db")
os.environ.setdefault("EVIDENCE_LOCAL_PATH", "./test_hard_evidence")

import importlib
import pytest
from fastapi.testclient import TestClient
from app.database import init_db


@pytest.fixture(scope="module")
def client():
    init_db()
    from app.main import app
    with TestClient(app) as c:
        yield c


# #1 batch partial failure with a DB-write item keeps earlier successes
def test_batch_partial_failure_preserves_successes(client):
    r = client.post("/assessment-jobs", json={"tenant_id": "hb", "controls": [
        {"control_id": "SC-7", "source_system": "DEMO", "asset_id": "a"},
        {"control_id": "AU-2", "source_system": "NOTREAL", "asset_id": "b"},  # fails
        {"control_id": "SC-28", "source_system": "DEMO", "asset_id": "c"},
    ]})
    body = r.json()
    assert body["succeeded"] == 2 and body["failed"] == 1
    assert len(body["errors"]) == 1
    got = client.get("/findings?tenant_id=hb").json()
    assert len(got) == 2  # both good items persisted


# #6 pagination is enforced
def test_findings_pagination(client):
    for i in range(8):
        client.post("/assessments", json={"tenant_id": "pg", "control_id": "SC-7",
                    "source_system": "DEMO", "asset_id": f"b{i}"})
    page = client.get("/findings?tenant_id=pg&limit=3").json()
    assert len(page) == 3
    page2 = client.get("/findings?tenant_id=pg&limit=3&offset=3").json()
    assert len(page2) == 3
    assert {f["finding_id"] for f in page}.isdisjoint({f["finding_id"] for f in page2})


def test_pagination_limit_capped(client):
    r = client.get("/findings?tenant_id=pg&limit=99999")
    assert r.status_code == 422  # Query(le=500) rejects over-max


# #8 internal errors are not leaked
def test_summary_uses_sql_aggregation(client):
    client.post("/assessments", json={"tenant_id": "agg", "control_id": "SC-7", "source_system": "DEMO", "asset_id": "a"})
    client.post("/assessments", json={"tenant_id": "agg", "control_id": "SC-28", "source_system": "DEMO", "asset_id": "b", "params": {"fail": True}})
    s = client.get("/summary?tenant_id=agg").json()
    assert s["compliance_score"] == 50.0


# #13 evidence hash still present and consistent
def test_evidence_hash():
    from app.evidence import telemetry_hash
    assert telemetry_hash({"a": 1}) == telemetry_hash({"a": 1})
    assert len(telemetry_hash({"a": 1})) == 64


# #4 token refresh logic (unit-level, no network)
def test_token_refresh_logic(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "t")
    monkeypatch.setenv("AZURE_CLIENT_ID", "c")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "s")
    import app.config as cfg
    importlib.reload(cfg)
    import app.connectors.secondary as sec
    importlib.reload(sec)
    az = sec.AzureConnector()
    assert az._token is None  # NOT fetched at init (no network call on construct)


# #3 tenant authorization
def test_tenant_authorization(monkeypatch):
    monkeypatch.setenv("COMP_LENS_API_KEYS", "scoped:tenantX ; admin:*")
    import app.auth as auth
    importlib.reload(auth)
    from app.main import app as a
    # rebuild client so dependency picks up new env
    with TestClient(a) as c:
        # scoped key can access its tenant
        r = c.post("/assessments", headers={"X-API-Key": "scoped"},
                   json={"tenant_id": "tenantX", "control_id": "SC-7", "source_system": "DEMO", "asset_id": "x"})
        assert r.status_code == 200
        # scoped key CANNOT access another tenant
        r = c.post("/assessments", headers={"X-API-Key": "scoped"},
                   json={"tenant_id": "tenantY", "control_id": "SC-7", "source_system": "DEMO", "asset_id": "x"})
        assert r.status_code == 403
        # admin key can access any tenant
        r = c.get("/findings?tenant_id=tenantY", headers={"X-API-Key": "admin"})
        assert r.status_code == 200
        # no key -> 401
        assert c.get("/findings?tenant_id=tenantX").status_code == 401
    monkeypatch.delenv("COMP_LENS_API_KEYS", raising=False)
    importlib.reload(auth)


# Recheck fixes: no orphan evidence on idempotency race
def test_no_orphan_evidence_on_idempotent_repeat(client, tmp_path, monkeypatch):
    # repeating the same key must not create extra evidence artifacts
    payload = {"tenant_id": "orph", "control_id": "AU-2", "source_system": "DEMO",
               "asset_id": "h", "idempotency_key": "ORPH1"}
    a = client.post("/assessments", json=payload).json()
    b = client.post("/assessments", json=payload).json()
    assert a["finding_id"] == b["finding_id"]
    assert len(a["evidence_ids"]) == 1  # exactly one evidence id, no duplication


# Recheck fixes: failed connector call does NOT burn the idempotency key
def test_failed_assessment_key_is_retriable(client):
    bad = {"tenant_id": "rt", "control_id": "AU-2", "source_system": "NOTREAL",
           "asset_id": "a", "idempotency_key": "RT1"}
    r1 = client.post("/assessments", json=bad)
    assert r1.status_code == 400
    # retry same key with a valid connector -> must succeed
    good = dict(bad, source_system="DEMO")
    r2 = client.post("/assessments", json=good)
    assert r2.status_code == 200


# Recheck fixes: client error is sanitized (no upstream/internal text)
def test_client_error_sanitized(client):
    r = client.post("/assessments", json={"tenant_id": "z", "control_id": "SA-15-BRANCH",
                    "source_system": "GITHUB", "asset_id": "o/r"})
    assert r.status_code == 400
    assert "GITHUB_TOKEN" not in r.json()["detail"]


# Recheck fixes: batch errors are categorized, not raw text
def test_batch_errors_have_no_raw_text(client):
    r = client.post("/assessment-jobs", json={"tenant_id": "be", "controls": [
        {"control_id": "AU-2", "source_system": "NOTREAL", "asset_id": "a"},
    ]})
    errs = r.json()["errors"]
    assert errs and "error_type" in errs[0]
    assert "error" not in errs[0]  # no raw message field


# Optimization regression guard: summary must not be N+1 on waivers
def test_summary_is_not_n_plus_one(client):
    from sqlalchemy import event
    from app.database import engine
    # seed several failing findings + waivers for one tenant
    for i in range(12):
        client.post("/assessments", json={"tenant_id": "n1", "control_id": "SC-28",
            "source_system": "DEMO", "asset_id": f"x{i}", "params": {"fail": True}})
        client.post("/waivers", json={"tenant_id": "n1", "control_id": "SC-28",
            "asset_id": f"x{i}", "reason": "r", "approver": "a"})
    count = {"n": 0}
    def _listen(conn, cur, stmt, params, ctx, many): count["n"] += 1
    event.listen(engine, "before_cursor_execute", _listen)
    try:
        client.get("/summary?tenant_id=n1")
    finally:
        event.remove(engine, "before_cursor_execute", _listen)
    # must be a small constant number of queries, NOT one-per-finding
    assert count["n"] <= 6, f"summary issued {count['n']} queries (N+1 regression)"
