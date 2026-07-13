"""AI governance: PET assessment + dynamic privacy-risk scoring + EU AI Act."""
import os

import pytest
from fastapi.testclient import TestClient

from app.services.ai_governance import ai_act_obligations, assess_pet, compute_privacy_risk

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/test_aigov.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "ci")


@pytest.fixture()
def client():
    import app.main as M
    with TestClient(M.app) as c:
        yield c


# ── PET assessment ──
def test_dp_epsilon_strength():
    assert assess_pet("differential_privacy", {"epsilon": 0.5})["effectiveness"] > 0.9
    assert assess_pet("differential_privacy", {"epsilon": 20})["effectiveness"] < 0.4

def test_he_scheme_strength():
    assert assess_pet("homomorphic_encryption", {"scheme": "CKKS"})["effectiveness"] > 0.85
    phe = assess_pet("homomorphic_encryption", {"scheme": "Paillier"})["effectiveness"]
    assert phe < assess_pet("homomorphic_encryption", {"scheme": "CKKS"})["effectiveness"]

def test_k_anonymity():
    assert assess_pet("k_anonymity", {"k": 15})["effectiveness"] > 0.7
    assert assess_pet("k_anonymity", {"k": 2})["effectiveness"] < 0.3

def test_unknown_pet():
    assert assess_pet("nonsense")["known"] is False


# ── dynamic risk ──
def test_dynamic_residual():
    none = compute_privacy_risk("phi", [])
    prot = compute_privacy_risk("phi", [
        {"pet": "differential_privacy", "params": {"epsilon": 0.5}},
        {"pet": "homomorphic_encryption", "params": {"scheme": "CKKS"}}])
    assert none["residual_risk"] > 70
    assert prot["residual_risk"] < none["residual_risk"]
    assert prot["residual_risk"] > 0   # honest floor

def test_defense_in_depth():
    # use moderate PETs so the residual floor isn't reached — then a 2nd PET genuinely lowers it
    one = compute_privacy_risk("special_category",
                               [{"pet": "k_anonymity", "params": {"k": 3}}])
    two = compute_privacy_risk("special_category",
                               [{"pet": "k_anonymity", "params": {"k": 3}},
                                {"pet": "data_minimization"}])
    assert two["residual_risk"] < one["residual_risk"]


# ── EU AI Act ──
def test_ai_act_obligations():
    high = ai_act_obligations("high", {"impact_assessment": True, "human_oversight": False,
                                       "data_governance": False, "accuracy_tested": False,
                                       "logging_enabled": True, "transparency_notice": True})
    assert len(high["obligations"]) > 5
    assert len(high["gaps"]) > 0


# ── API ──
def test_pet_catalog_endpoint(client):
    cat = client.get("/v1/ai-gov/pet-catalog").json()
    assert cat["count"] >= 7

def test_adhoc_score(client):
    r = client.post("/v1/ai-gov/score", json={"data_sensitivity": "biometric", "pets": []}).json()
    assert r["residual_band"] == "critical"

def test_full_system_flow(client):
    sys = client.post("/ai-systems", json={"name": "Test Model", "risk_tier": "high"}).json()
    sid = sys["id"]
    client.post(f"/v1/ai-gov/systems/{sid}/pets",
                json={"pet": "differential_privacy", "params": {"epsilon": 0.5}, "data_sensitivity": "phi"})
    risk = client.get(f"/v1/ai-gov/systems/{sid}/risk").json()
    assert risk["residual_risk"] < risk["inherent_risk"]
    assert "ai_act" in risk

def test_unknown_pet_rejected(client):
    sys = client.post("/ai-systems", json={"name": "X"}).json()
    assert client.post(f"/v1/ai-gov/systems/{sys['id']}/pets", json={"pet": "fake"}).status_code == 400
