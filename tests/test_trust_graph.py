"""Trust graph + live telemetry: evidence must flow into risk scores."""
import os
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/test_trust.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "ci")
for k in ("LIVE_CONNECTORS_ENABLED", "LIVE_CONNECTORS_ALLOWLIST"):
    os.environ.pop(k, None)


@pytest.fixture()
def client():
    import app.main as M
    with TestClient(M.app) as c:
        yield c


def test_unevidenced_risk_residual_equals_inherent(client):
    r = client.post("/grc/risks", json={"title": "X", "likelihood": 4, "impact": 4,
                                        "linked_control": "ZZ-99"}).json()
    tel = [t for t in client.get("/trust/risk-telemetry").json() if t["id"] == r["id"]][0]
    assert tel["inherent_score"] == 16
    assert tel["computed_residual"] == 16        # no connector evidences ZZ-99
    assert tel["evidence_strength"] == 0.0


def test_evidence_lowers_residual(client):
    r = client.post("/grc/risks", json={"title": "Y", "likelihood": 4, "impact": 4,
                                        "linked_control": "AC-2"}).json()
    before = [t for t in client.get("/trust/risk-telemetry").json() if t["id"] == r["id"]][0]
    client.post("/connectors/OKTA/sync", json={"tenant_id": "default"})
    after = [t for t in client.get("/trust/risk-telemetry").json() if t["id"] == r["id"]][0]
    assert after["evidence_strength"] > 0
    assert after["computed_residual"] <= before["computed_residual"]
    assert len(after["backed_by"]) >= 1


def test_graph_has_full_chain(client):
    client.post("/grc/risks", json={"title": "Z", "likelihood": 3, "impact": 3,
                                    "linked_control": "AC-2"})
    client.post("/connectors/OKTA/sync", json={"tenant_id": "default"})
    client.post("/tprm/vendors", json={"name": "Okta Inc", "linked_connector_key": "OKTA"})
    g = client.get("/trust/graph").json()
    types = {n["type"] for n in g["nodes"]}
    assert {"vendor", "connector", "control", "risk"} <= types
    kinds = {e["kind"] for e in g["edges"]}
    assert {"operates", "evidences", "mitigates"} <= kinds


def test_vendor_persists_connector_link(client):
    v = client.post("/tprm/vendors", json={"name": "V", "linked_connector_key": "GITHUB"}).json()
    assert v["linked_connector_key"] == "GITHUB"


def test_graph_tenant_scoped(client):
    client.post("/grc/risks", json={"title": "iso", "linked_control": "AC-2"},
                params={"tenant_id": "tg_a"})
    g = client.get("/trust/graph", params={"tenant_id": "tg_b"}).json()
    assert not any(n.get("label") == "iso" for n in g["nodes"])
