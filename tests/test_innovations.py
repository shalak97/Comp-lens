"""Tests for risk-weighted scoring, remediation prioritization, tamper-evidence."""
from __future__ import annotations
import os
os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_innov.db")
os.environ.setdefault("EVIDENCE_LOCAL_PATH", "./test_innov_ev")

import pytest
from fastapi.testclient import TestClient
from app.database import init_db


@pytest.fixture(scope="module")
def client():
    init_db()
    from app.main import app
    with TestClient(app) as c:
        yield c


# ── Risk-weighted scoring ──
def test_risk_weighted_score_penalizes_severity(client):
    # one critical fail (SC-7) vs everything else passing
    client.post("/assessments", json={"tenant_id": "rw", "control_id": "SC-7",
        "source_system": "DEMO", "asset_id": "a", "params": {"fail": True}})
    client.post("/assessments", json={"tenant_id": "rw", "control_id": "AU-2",
        "source_system": "DEMO", "asset_id": "b"})
    s = client.get("/summary?tenant_id=rw").json()
    assert "risk_weighted_score" in s and "risk_exposure" in s
    # a critical fail should pull risk-weighted below the raw pass-ratio score
    assert s["risk_weighted_score"] <= s["compliance_score"]
    assert s["risk_exposure"] > 0


# ── Remediation prioritization ──
def test_remediation_priority_orders_by_impact(client):
    from app.models import AssetRecord
    from app.database import SessionLocal
    db = SessionLocal()
    db.add(AssetRecord(tenant_id="rem", asset_id="prod-db", asset_type="db",
                       source_system="DEMO", criticality="critical"))
    db.commit(); db.close()
    client.post("/assessments", json={"tenant_id": "rem", "control_id": "SC-7",
        "source_system": "DEMO", "asset_id": "prod-db", "params": {"fail": True}})  # critical
    client.post("/assessments", json={"tenant_id": "rem", "control_id": "AC-2-3",
        "source_system": "DEMO", "asset_id": "minor", "params": {"fail": True}})    # medium
    r = client.get("/remediation?tenant_id=rem&top=5").json()
    assert r["open_findings"] == 2
    # critical-on-critical-asset must rank first
    assert r["queue"][0]["control_id"] == "SC-7"
    assert r["queue"][0]["priority"] > r["queue"][1]["priority"]
    # what-if projection improves the score
    assert r["projected_after_fixing_top"] >= r["current_risk_weighted_score"]


# ── Tamper-evident evidence ──
def test_evidence_verify_clean(client):
    for i in range(3):
        client.post("/assessments", json={"tenant_id": "ev", "control_id": "SC-7",
            "source_system": "DEMO", "asset_id": f"a{i}"})
    v = client.get("/evidence/verify?tenant_id=ev").json()
    assert v["intact"] is True and v["checked"] == 3 and v["broken_count"] == 0


def test_evidence_verify_detects_db_tamper(client):
    client.post("/assessments", json={"tenant_id": "tamper", "control_id": "AU-2",
        "source_system": "DEMO", "asset_id": "a"})
    from app.database import SessionLocal
    from app.models import EvidenceMeta
    from sqlalchemy import select
    db = SessionLocal()
    e = db.execute(select(EvidenceMeta).where(EvidenceMeta.tenant_id == "tamper")).scalars().first()
    e.telemetry_hash = "0" * 64  # tamper
    db.commit(); db.close()
    v = client.get("/evidence/verify?tenant_id=tamper").json()
    assert v["intact"] is False
    assert v["broken"][0]["reason"] == "metadata_tampered"


def test_record_hash_helper():
    from app.evidence import record_hash
    a = record_hash(evidence_id="e", tenant_id="t", run_id="r", control_id="c",
                    framework="NIST", status="pass", telemetry_hash_value="h")
    b = record_hash(evidence_id="e", tenant_id="t", run_id="r", control_id="c",
                    framework="NIST", status="fail", telemetry_hash_value="h")
    assert a != b and len(a) == 64  # status change flips the hash
