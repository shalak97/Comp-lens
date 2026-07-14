"""GRC Risk Register + TPRM lifecycle tests."""
import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/test_grc.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "ci")


@pytest.fixture()
def client():
    import app.main as M
    with TestClient(M.app) as c:
        yield c


def test_risk_scoring(client):
    r = client.post("/grc/risks", json={"title": "X", "likelihood": 4, "impact": 5}).json()
    assert r["inherent_score"] == 20
    assert r["inherent_band"] == "critical"


def test_risk_residual(client):
    r = client.post("/grc/risks", json={"title": "Y", "likelihood": 5, "impact": 5,
                                        "residual_likelihood": 1, "residual_impact": 1}).json()
    assert r["inherent_score"] == 25
    assert r["residual_score"] == 1
    assert r["residual_band"] == "low"


def test_risk_crud_and_summary(client):
    r = client.post("/grc/risks", json={"title": "Z", "likelihood": 3, "impact": 3}).json()
    rid = r["id"]
    up = client.patch(f"/grc/risks/{rid}", json={"status": "treated"}).json()
    assert up["status"] == "treated"
    s = client.get("/grc/risks/summary").json()
    assert s["total"] >= 1
    assert "by_band" in s and "by_treatment" in s
    assert client.delete(f"/grc/risks/{rid}").status_code == 200


def test_risk_404(client):
    assert client.patch("/grc/risks/nope", json={"title": "a"}).status_code == 404
    assert client.delete("/grc/risks/nope").status_code == 404


def test_vendor_risk_banding(client):
    good = client.post("/tprm/vendors", json={"name": "Good", "assessment_score": 90}).json()
    assert good["computed_risk"] == "low"
    bad = client.post("/tprm/vendors", json={"name": "Bad", "assessment_score": 30}).json()
    assert bad["computed_risk"] == "critical"


def test_vendor_lifecycle(client):
    v = client.post("/tprm/vendors", json={"name": "Acme", "stage": "onboarding"}).json()
    vid = v["id"]
    moved = client.patch(f"/tprm/vendors/{vid}", json={"stage": "active"}).json()
    assert moved["stage"] == "active"
    assert client.delete(f"/tprm/vendors/{vid}").status_code == 200


def test_vendor_dpa_gap(client):
    client.post("/tprm/vendors", json={"name": "PiiNoDpa", "data_access": "pii", "has_dpa": False})
    s = client.get("/tprm/vendors/summary").json()
    assert s["missing_dpa"] >= 1


def test_tenant_isolation(client):
    client.post("/grc/risks", json={"title": "iso-A"}, params={"tenant_id": "tA"})
    other = client.get("/grc/risks", params={"tenant_id": "tB"}).json()
    assert all(r["title"] != "iso-A" for r in other)
