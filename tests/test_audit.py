"""Audit management: lifecycle, checklist review, PBC requests, export package."""
import os
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/test_audit.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "ci")


@pytest.fixture()
def client():
    import app.main as M
    with TestClient(M.app) as c:
        yield c


def test_create_builds_checklist(client):
    a = client.post("/audits", json={"name": "Audit A", "framework": "NIST"}).json()
    assert a["id"]
    assert a["controls_total"] > 0
    assert a["readiness_pct"] == 0
    ctrls = client.get(f"/audits/{a['id']}/controls").json()
    assert len(ctrls) == a["controls_total"]


def test_review_moves_readiness(client):
    a = client.post("/audits", json={"name": "Audit B", "framework": "NIST"}).json()
    ctrls = client.get(f"/audits/{a['id']}/controls").json()
    client.patch(f"/audits/controls/{ctrls[0]['id']}", json={"review_state": "approved"})
    a2 = client.get(f"/audits/{a['id']}").json()
    assert a2["readiness_pct"] > 0
    assert a2["controls_approved"] == 1


def test_evidence_request_lifecycle(client):
    a = client.post("/audits", json={"name": "Audit C", "framework": "NIST"}).json()
    r = client.post(f"/audits/{a['id']}/requests",
                    json={"title": "Provide logs", "control_id": "AC-2"}).json()
    assert r["state"] == "open"
    f = client.patch(f"/audits/requests/{r['id']}",
                     json={"state": "fulfilled", "evidence_ref": "doc-1"}).json()
    assert f["state"] == "fulfilled"
    a2 = client.patch(f"/audits/requests/{r['id']}", json={"state": "accepted"}).json()
    assert a2["state"] == "accepted"


def test_lifecycle_status(client):
    a = client.post("/audits", json={"name": "Audit D", "framework": "NIST"}).json()
    up = client.patch(f"/audits/{a['id']}", json={"status": "fieldwork"}).json()
    assert up["status"] == "fieldwork"


def test_export_package(client):
    a = client.post("/audits", json={"name": "Audit E", "framework": "NIST",
                                     "auditor": "EY"}).json()
    client.post(f"/audits/{a['id']}/requests", json={"title": "Req 1"})
    pkg = client.get(f"/audits/{a['id']}/export").json()
    assert pkg["audit"]["auditor"] == "EY"
    assert len(pkg["controls"]) == a["controls_total"]
    assert len(pkg["evidence_requests"]) == 1
    assert "attestation" in pkg
    assert "generated_at" in pkg


def test_delete_cascades(client):
    a = client.post("/audits", json={"name": "Audit F", "framework": "NIST"}).json()
    assert client.delete(f"/audits/{a['id']}").status_code == 200
    assert client.get(f"/audits/{a['id']}/controls").json() == []


def test_audit_tenant_isolation(client):
    client.post("/audits", json={"name": "iso-audit"}, params={"tenant_id": "ta"})
    other = client.get("/audits", params={"tenant_id": "tb"}).json()
    assert all(x["name"] != "iso-audit" for x in other)


def test_audit_404(client):
    assert client.get("/audits/nope").status_code == 404
    assert client.patch("/audits/nope", json={"name": "x"}).status_code == 404
