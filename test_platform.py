"""Test suite for Comp-Lens. Uses the DEMO connector so no real creds needed.

Run:  pytest -q
"""

from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_complens.db")
os.environ.setdefault("EVIDENCE_LOCAL_PATH", "./test_evidence_pytest")

import pytest
from fastapi.testclient import TestClient

from app.database import init_db
from app.main import app


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


def test_root_lists_connectors_and_controls(client):
    r = client.get("/")
    assert r.status_code == 200
    body = r.json()
    assert "DEMO" in body["connectors"]
    assert "AWS" in body["connectors"]
    assert "AC-2-7" in body["controls"]


def test_pass_assessment(client):
    r = client.post("/assessments", json={
        "tenant_id": "t1", "control_id": "SC-7", "source_system": "DEMO", "asset_id": "b1",
    })
    assert r.status_code == 200
    assert r.json()["status"] == "pass"


def test_fail_assessment_creates_remediation(client):
    r = client.post("/assessments", json={
        "tenant_id": "t1", "control_id": "SC-28", "source_system": "DEMO",
        "asset_id": "b2", "params": {"fail": True},
    })
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "fail"
    assert body["remediation"] is not None
    assert body["remediation"]["requires_approval"] is True


def test_idempotency_returns_same_finding(client):
    payload = {
        "tenant_id": "t2", "control_id": "AC-2-7", "source_system": "DEMO",
        "asset_id": "u1", "idempotency_key": "fixed-key",
    }
    a = client.post("/assessments", json=payload).json()
    b = client.post("/assessments", json=payload).json()
    assert a["finding_id"] == b["finding_id"]


def test_unknown_control_is_error_status(client):
    r = client.post("/assessments", json={
        "tenant_id": "t3", "control_id": "NOPE", "source_system": "DEMO",
    })
    assert r.status_code == 200
    assert r.json()["status"] == "error"


def test_unsupported_source_system_400(client):
    r = client.post("/assessments", json={
        "tenant_id": "t3", "control_id": "SC-7", "source_system": "NOTREAL",
    })
    assert r.status_code == 400


def test_stale_account_fails(client):
    r = client.post("/assessments", json={
        "tenant_id": "t4", "control_id": "AC-2-3", "source_system": "DEMO",
        "asset_id": "u9", "params": {"fail": True},
    })
    assert r.json()["status"] == "fail"


def test_findings_listing_and_summary(client):
    client.post("/assessments", json={
        "tenant_id": "rep", "control_id": "AU-2", "source_system": "DEMO", "asset_id": "a1",
    })
    findings = client.get("/findings?tenant_id=rep").json()
    assert len(findings) >= 1
    summary = client.get("/summary?tenant_id=rep").json()
    assert summary["total"] >= 1
    assert "compliance_score" in summary


def test_batch_assessment(client):
    r = client.post("/assessment-jobs", json={
        "tenant_id": "batch",
        "controls": [
            {"control_id": "SC-7", "source_system": "DEMO", "asset_id": "b1"},
            {"control_id": "SC-28", "source_system": "DEMO", "asset_id": "b2", "params": {"fail": True}},
        ],
    })
    body = r.json()
    assert body["succeeded"] == 2


def test_evidence_hash_present(client):
    from app.evidence import telemetry_hash
    h1 = telemetry_hash({"a": 1, "b": 2})
    h2 = telemetry_hash({"b": 2, "a": 1})  # order-independent
    assert h1 == h2
    assert len(h1) == 64  # sha256 hex


def test_auth_enforced_when_keys_set(monkeypatch):
    """When COMP_LENS_API_KEYS is set, protected routes require the header."""
    monkeypatch.setenv("COMP_LENS_API_KEYS", "topsecret")
    from app.main import app as auth_app
    with TestClient(auth_app) as c:
        # no key -> 401
        r = c.post("/assessments", json={"control_id": "SC-7", "source_system": "DEMO", "asset_id": "x"})
        assert r.status_code == 401
        # wrong key -> 403
        r = c.post("/assessments", headers={"X-API-Key": "nope"},
                   json={"control_id": "SC-7", "source_system": "DEMO", "asset_id": "x"})
        assert r.status_code == 403
        # right key -> 200
        r = c.post("/assessments", headers={"X-API-Key": "topsecret"},
                   json={"control_id": "SC-7", "source_system": "DEMO", "asset_id": "x"})
        assert r.status_code == 200
        # health stays public
        assert c.get("/health/live").status_code == 200
