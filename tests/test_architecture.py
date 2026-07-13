"""Tests for the architecture upgrade: posture, OPA engine, ingestion, OSCAL."""
from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_arch.db")
os.environ.setdefault("EVIDENCE_LOCAL_PATH", "./test_arch_ev")

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


# ── Posture current-state table ──
def test_posture_maintained_and_summary_reads_it(client):
    from sqlalchemy import select

    from app.database import SessionLocal
    from app.models import Posture
    client.post("/assessments", json={"tenant_id": "ps", "control_id": "SC-7",
        "source_system": "DEMO", "asset_id": "a", "idempotency_key": "p1"})
    db = SessionLocal()
    rows = db.execute(select(Posture).where(Posture.tenant_id == "ps")).scalars().all()
    db.close()
    assert len(rows) == 1 and rows[0].status.value == "pass" and rows[0].prev_status is None


def test_reassessment_updates_posture_not_duplicates(client):
    # same asset assessed twice (pass then fail) -> ONE posture row, prev tracked
    client.post("/assessments", json={"tenant_id": "ps2", "control_id": "SC-28",
        "source_system": "DEMO", "asset_id": "x", "idempotency_key": "a1"})
    client.post("/assessments", json={"tenant_id": "ps2", "control_id": "SC-28",
        "source_system": "DEMO", "asset_id": "x", "params": {"fail": True}, "idempotency_key": "a2"})
    from sqlalchemy import select

    from app.database import SessionLocal
    from app.models import Posture
    db = SessionLocal()
    rows = db.execute(select(Posture).where(Posture.tenant_id == "ps2")).scalars().all()
    db.close()
    assert len(rows) == 1
    assert rows[0].status.value == "fail" and rows[0].prev_status.value == "pass"


def test_drift_from_posture(client):
    client.post("/assessments", json={"tenant_id": "dr2", "control_id": "AU-2",
        "source_system": "DEMO", "asset_id": "h", "idempotency_key": "x1"})
    client.post("/assessments", json={"tenant_id": "dr2", "control_id": "AU-2",
        "source_system": "DEMO", "asset_id": "h", "params": {"fail": True}, "idempotency_key": "x2"})
    d = client.get("/drift?tenant_id=dr2").json()
    assert d["regression_count"] == 1


def test_summary_query_count_constant_with_posture(client):
    from sqlalchemy import event

    from app.database import engine
    for i in range(15):
        client.post("/assessments", json={"tenant_id": "pc", "control_id": "SC-7",
            "source_system": "DEMO", "asset_id": f"b{i}"})
    n = {"c": 0}
    def fn(*a):
        return n.__setitem__("c", n["c"] + 1)
    event.listen(engine, "before_cursor_execute", fn)
    try:
        client.get("/summary?tenant_id=pc")
    finally:
        event.remove(engine, "before_cursor_execute", fn)
    assert n["c"] <= 4  # posture read + waiver read, regardless of finding count


# ── OPA policy engine ──
def test_opa_engine_maps_decision(monkeypatch):
    monkeypatch.setenv("POLICY_ENGINE", "opa")
    import app.config as cfg
    importlib.reload(cfg)
    import app.policy.engine as pe
    importlib.reload(pe)
    eng = pe.OPAEngine()
    class R:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"result": {"status": "fail", "reason": "from OPA"}}
    monkeypatch.setattr(pe, "_build_engine", lambda: eng)
    monkeypatch.setattr("requests.post", lambda *a, **k: R())
    status, reason, sev = eng.evaluate("SC-7", {"public_access_blocked": False})
    assert status.value == "fail" and reason == "from OPA"


def test_opa_engine_handles_unreachable(monkeypatch):
    monkeypatch.setenv("POLICY_ENGINE", "opa")
    import app.config as cfg
    importlib.reload(cfg)
    import app.policy.engine as pe
    importlib.reload(pe)
    eng = pe.OPAEngine()
    def boom(*a, **k): raise ConnectionError("no opa")
    monkeypatch.setattr("requests.post", boom)
    status, reason, sev = eng.evaluate("SC-7", {})
    assert status.value == "error"  # never crashes


# ── Ingestion ──
def test_ingest_report_prowler_style(client):
    payload = {"findings": [
        {"check_id": "SC-7", "status": "FAIL", "resource": "bucket-1", "severity": "HIGH", "id": "p-1"},
        {"check_id": "AU-2", "status": "PASS", "resource": "trail-1", "severity": "MEDIUM", "id": "p-2"},
    ]}
    r = client.post("/ingest/report?tenant_id=ing&source=PROWLER", json=payload).json()
    assert r["ingested"] == 2
    findings = client.get("/findings?tenant_id=ing").json()
    assert {f["source_system"] for f in findings} == {"PROWLER"}
    # ingestion is idempotent on external id
    r2 = client.post("/ingest/report?tenant_id=ing&source=PROWLER", json=payload).json()
    assert r2["ingested"] == 0 and r2["skipped"] == 2


def test_ingested_findings_feed_posture_and_summary(client):
    client.post("/ingest/report?tenant_id=ing2&source=STEAMPIPE", json={"findings": [
        {"control_id": "SC-28", "result": "alarm", "resource": "db-1", "severity": "critical", "id": "s-1"}]})
    s = client.get("/summary?tenant_id=ing2").json()
    assert s["by_status"]["fail"] == 1


def test_asff_mapper_unit():
    from app.database import SessionLocal
    from app.services.ingestion import IngestionService
    svc = IngestionService(SessionLocal())
    asff = {"Id": "arn:finding/1", "Title": "S3 bucket is public",
            "Compliance": {"Status": "FAILED", "SecurityControlId": "S3.2"},
            "Severity": {"Label": "HIGH"}, "Resources": [{"Id": "arn:s3:::bucket"}]}
    ok = svc._ingest_asff("asff", asff)
    svc.db.commit()
    assert ok is True
    svc.db.close()


# ── OSCAL export ──
def test_oscal_export(client):
    client.post("/assessments", json={"tenant_id": "osc", "control_id": "SC-7",
        "source_system": "DEMO", "asset_id": "a"})
    doc = client.get("/reports/oscal?tenant_id=osc").json()
    assert "assessment-results" in doc
    ar = doc["assessment-results"]
    assert ar["metadata"]["oscal-version"]
    assert ar["results"][0]["findings"]
    assert ar["results"][0]["findings"][0]["target"]["target-id"] == "SC-7"


# Security Hub ingestion (mocked boto3) — was previously untested
def test_security_hub_ingest_mocked(client, monkeypatch):
    import app.services.ingestion as ing

    class _Paginator:
        def paginate(self, **kw):
            yield {"Findings": [
                {"Id": "sh-1", "Title": "S3 bucket is public",
                 "Compliance": {"Status": "FAILED", "SecurityControlId": "SC-7"},
                 "Severity": {"Label": "HIGH"},
                 "Resources": [{"Id": "arn:aws:s3:::bucket-1"}]},
                {"Id": "sh-2", "Title": "CloudTrail enabled",
                 "Compliance": {"Status": "PASSED", "SecurityControlId": "AU-2"},
                 "Severity": {"Label": "INFORMATIONAL"},
                 "Resources": [{"Id": "arn:aws:cloudtrail:::trail-1"}]},
            ]}

    class _Client:
        def get_paginator(self, name):
            assert name == "get_findings"
            return _Paginator()

    import boto3
    monkeypatch.setattr(boto3, "client", lambda *a, **k: _Client())

    from app.database import SessionLocal
    db = SessionLocal()
    try:
        out = ing.IngestionService(db).from_security_hub("shtenant", max_findings=100)
        db.commit()
    finally:
        db.close()
    assert out["ingested"] == 2

    findings = client.get("/findings?tenant_id=shtenant").json()
    assert {f["source_system"] for f in findings} == {"SECURITYHUB"}
    assert {f["control_id"] for f in findings} == {"SC-7", "AU-2"}
    statuses = {f["control_id"]: f["status"] for f in findings}
    assert statuses["SC-7"] == "fail" and statuses["AU-2"] == "pass"

    # idempotent: re-ingest same ASFF ids -> all skipped
    db = SessionLocal()
    try:
        out2 = ing.IngestionService(db).from_security_hub("shtenant", max_findings=100)
        db.commit()
    finally:
        db.close()
    assert out2["ingested"] == 0 and out2["skipped"] == 2
