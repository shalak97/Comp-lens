"""Tests for AI-governance domain, Merkle transparency log, NL->policy, forecast."""
from __future__ import annotations
import os
os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_v16.db")
os.environ.setdefault("EVIDENCE_LOCAL_PATH", "./test_v16_ev")

import pytest
from fastapi.testclient import TestClient
from app.database import init_db


@pytest.fixture(scope="module")
def client():
    init_db()
    from app.main import app
    with TestClient(app) as c:
        yield c


# ── 1. AI-governance domain ──
def test_ai_frameworks_present(client):
    fw = client.get("/frameworks").json()["frameworks"]
    assert {"ISO42001", "NIST_AI_RMF", "EU_AI_ACT"} <= set(fw)
    cw = client.get("/crosswalk?control_id=AI-OVERSIGHT").json()["mappings"]
    assert "EU_AI_ACT" in cw and "ISO42001" in cw


def test_ai_system_register_and_assess(client):
    # a well-governed system passes; a poorly-governed one fails
    good = client.post("/ai-systems", json={"tenant_id": "ai", "name": "fraud-model", "owner": "ml-team",
        "risk_tier": "high", "impact_assessment": True, "data_governance": True, "human_oversight": True,
        "transparency_notice": True, "eval_report": True, "logging_enabled": True, "accuracy_tested": True}).json()
    bad = client.post("/ai-systems", json={"tenant_id": "ai", "name": "shadow-bot", "owner": "unknown",
        "risk_tier": "high"}).json()
    assert client.get("/ai-systems?tenant_id=ai").json().__len__() == 2

    r = client.post("/assessments", json={"tenant_id": "ai", "framework": "EU_AI_ACT",
        "control_id": "AI-OVERSIGHT", "source_system": "AIGOV", "asset_id": good["id"]}).json()
    assert r["status"] == "pass"
    r2 = client.post("/assessments", json={"tenant_id": "ai", "framework": "EU_AI_ACT",
        "control_id": "AI-OVERSIGHT", "source_system": "AIGOV", "asset_id": bad["id"]}).json()
    assert r2["status"] == "fail"


def test_aigov_cross_tenant_refused(client):
    sys = client.post("/ai-systems", json={"tenant_id": "owner1", "name": "m", "owner": "o",
        "human_oversight": True}).json()
    # tenant owner2 must not be able to assess owner1's system
    r = client.post("/assessments", json={"tenant_id": "owner2", "control_id": "AI-OVERSIGHT",
        "source_system": "AIGOV", "asset_id": sys["id"]})
    assert r.status_code == 400


# ── 2. Merkle transparency log ──
def test_merkle_anchor_and_proof(client):
    for i in range(5):
        client.post("/assessments", json={"tenant_id": "mk", "control_id": "SC-7",
            "source_system": "DEMO", "asset_id": f"a{i}"})
    anchor = client.post("/evidence/anchor?tenant_id=mk").json()
    assert anchor["leaf_count"] == 5 and len(anchor["root"]) == 64
    # inclusion proof for one finding's evidence
    findings = client.get("/findings?tenant_id=mk").json()
    ev_id = findings[0]["evidence_ids"][0]
    proof = client.get(f"/evidence/proof?tenant_id=mk&evidence_id={ev_id}").json()
    assert proof["found"] is True and proof["verified"] is True


def test_merkle_detects_tamper(client):
    for i in range(4):
        client.post("/assessments", json={"tenant_id": "mk2", "control_id": "AU-2",
            "source_system": "DEMO", "asset_id": f"b{i}"})
    anchor = client.post("/evidence/anchor?tenant_id=mk2").json()
    old_root = anchor["root"]
    # tamper a record_hash after anchoring
    from app.database import SessionLocal
    from app.models import EvidenceMeta
    from sqlalchemy import select
    db = SessionLocal()
    e = db.execute(select(EvidenceMeta).where(EvidenceMeta.tenant_id == "mk2")).scalars().first()
    e.record_hash = "f" * 64
    db.commit(); db.close()
    # re-anchor -> root changes, proving the log was altered
    new_anchor = client.post("/evidence/anchor?tenant_id=mk2").json()
    assert new_anchor["root"] != old_root


def test_merkle_tree_unit():
    from app.services.merkle import build_tree, inclusion_proof, verify_proof
    leaves = [f"h{i}" * 16 for i in range(6)]  # 64-char-ish
    root, levels = build_tree(leaves)
    for i in range(6):
        proof = inclusion_proof(levels, i)
        assert verify_proof(leaves[i], proof, root)
    # a wrong leaf must fail
    assert not verify_proof("x" * 64, inclusion_proof(levels, 0), root)


# ── 3. NL -> policy authoring (human-in-the-loop) ──
def test_policy_draft_and_approve(client):
    d = client.post("/policy/draft", json={"tenant_id": "pol",
        "description": "All production databases must enforce encryption at rest"}).json()
    assert d["telemetry_field"] == "encryption_at_rest"
    assert "input.telemetry.encryption_at_rest" in d["rego"]
    assert d["status"] == "pending"            # nothing enforced yet
    assert 0 < d["confidence"] <= 1
    # human approves
    ap = client.post(f"/policy/{d['id']}/approve?tenant_id=pol&approve=true").json()
    assert ap["status"] == "approved"
    drafts = client.get("/policy/drafts?tenant_id=pol").json()
    assert any(x["id"] == d["id"] and x["status"] == "approved" for x in drafts)


def test_policy_draft_mfa_and_numeric(client):
    d1 = client.post("/policy/draft", json={"tenant_id": "pol",
        "description": "Require multi-factor authentication for all admins"}).json()
    assert d1["telemetry_field"] == "mfa_enforced"
    d2 = client.post("/policy/draft", json={"tenant_id": "pol",
        "description": "Hosts must have no critical vulnerabilities"}).json()
    assert d2["telemetry_field"] == "critical_vulnerabilities"
    assert "<= 0" in d2["rego"]


# ── 4. Predictive forecast ──
def test_forecast_declining_trend(client):
    # build a declining snapshot series by capturing after worsening posture
    import time
    from app.database import SessionLocal
    from app.models import ComplianceSnapshot
    from datetime import datetime, timezone, timedelta
    db = SessionLocal()
    base = datetime.now(timezone.utc) - timedelta(days=5)
    for i, score in enumerate([95.0, 90.0, 85.0, 80.0, 75.0]):
        db.add(ComplianceSnapshot(tenant_id="fc", framework="ALL", score=score,
                                  total=10, passed=int(score/10), failed=10-int(score/10),
                                  captured_at=base + timedelta(days=i)))
    db.commit(); db.close()
    f = client.get("/forecast?tenant_id=fc&horizon_days=10&threshold=70").json()
    assert f["insufficient_data"] is False
    assert f["trend"] == "declining"
    assert f["projected_score"] < f["current_score"]
    assert f["days_to_threshold"] is not None


def test_forecast_insufficient_data(client):
    f = client.get("/forecast?tenant_id=empty").json()
    assert f["insufficient_data"] is True
