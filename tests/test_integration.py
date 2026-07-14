"""Cross-feature integration: policy→findings, AI-gov→risk, threat→escalation."""
import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/test_integ.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "ci")


@pytest.fixture()
def client():
    import app.main as M
    with TestClient(M.app) as c:
        yield c


def test_policy_becomes_findings(client):
    r = client.post("/v1/integrate/policy-to-findings", json={"evidence": {
        "SC-28": {"storage": [{"encryption_at_rest": False}], "scan_age_days": 5}}}).json()
    # created OR updated (test DB may be shared) — either way the finding must exist
    assert r["findings_created"] + r["findings_updated"] > 0
    pol = [f for f in client.get("/findings?tenant_id=default").json()
           if f.get("source_system") == "policy-as-code"]
    assert len(pol) > 0


def test_policy_findings_idempotent(client):
    ev = {"evidence": {"RA-5": {"critical_vulns": 3, "scan_age_days": 5}}}
    client.post("/v1/integrate/policy-to-findings", json=ev)
    r2 = client.post("/v1/integrate/policy-to-findings", json=ev).json()
    assert r2["findings_created"] == 0   # no duplication
    ra5 = [f for f in client.get("/findings?tenant_id=default").json()
           if f.get("control_id") == "RA-5" and f.get("source_system") == "policy-as-code"]
    assert len(ra5) == 1


def test_policy_finding_feeds_simulator(client):
    client.post("/v1/integrate/policy-to-findings", json={"evidence": {
        "RA-5": {"critical_vulns": 5, "scan_age_days": 5}}})
    sim = client.post("/simulate", json={"framework": "NIST",
                                         "changes": [{"control_id": "RA-5", "state": "failed"}]}).json()
    assert "cascade" in sim


def test_ai_system_becomes_risk(client):
    sys = client.post("/ai-systems", json={"name": "Model X", "risk_tier": "high"}).json()
    client.post(f"/v1/ai-gov/systems/{sys['id']}/pets",
                json={"pet": "k_anonymity", "params": {"k": 2}, "data_sensitivity": "phi"})
    r = client.post(f"/v1/integrate/ai-systems/{sys['id']}/to-risk").json()
    assert r["linked"] is True and r["risk_id"]
    ai_risks = [x for x in client.get("/grc/risks?tenant_id=default").json()
                if x.get("category") == "ai_governance"]
    assert len(ai_risks) > 0


def test_ai_to_risk_idempotent(client):
    sys = client.post("/ai-systems", json={"name": "Model Y"}).json()
    client.post(f"/v1/ai-gov/systems/{sys['id']}/pets",
                json={"pet": "differential_privacy", "params": {"epsilon": 5}, "data_sensitivity": "pii"})
    client.post(f"/v1/integrate/ai-systems/{sys['id']}/to-risk")
    r2 = client.post(f"/v1/integrate/ai-systems/{sys['id']}/to-risk").json()
    assert "already exists" in r2.get("note", "")


def test_threat_escalates_risk(client):
    client.post("/grc/risks?tenant_id=default",
                json={"title": "CVEs", "linked_control": "RA-5", "impact": 3, "likelihood": 4})
    te = client.post("/v1/integrate/threat-escalation").json()
    assert te["escalated"] > 0


def test_unified_pipeline(client):
    u = client.post("/v1/integrate/run",
                    json={"evidence": {"SI-2": {"critical_vulns": 1, "scan_age_days": 5}}}).json()
    assert len(u["ran"]) == 3
