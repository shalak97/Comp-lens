"""Connector framework v2: catalog, registry wiring, normalization, API routes."""
import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/test_conn_v2.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "ci-key")


@pytest.fixture(scope="module")
def client():
    import app.main as M
    with TestClient(M.app) as c:
        yield c


# ── catalog & registry ────────────────────────────────────────────────────────

def test_catalog_has_all_categories(client):
    from app.connectors.catalog import all_connectors, CATEGORIES
    cats = {c["category"] for c in all_connectors()}
    assert cats == set(CATEGORIES)


def test_catalog_has_flagship_eight(client):
    from app.connectors.catalog import get
    for key in ["AWS_SECURITY_HUB", "OKTA", "GITHUB", "JIRA",
                "SERVICENOW", "CROWDSTRIKE", "ENTRA_ID", "ONETRUST"]:
        c = get(key)
        assert c is not None, key
        assert c["evidence_types"], key


def test_catalog_implemented_link_to_real_registry(client):
    from app.connectors.catalog import all_connectors
    from app.connectors.registry import registry
    supported = set(registry.supported())
    for c in all_connectors():
        if c["maturity"] == "implemented":
            assert c["registry_key"] in supported, c["key"]


def test_catalog_never_contains_secret_values(client):
    from app.connectors.catalog import all_connectors
    for c in all_connectors():
        for v in c["env_vars"]:
            assert v.isupper() and "=" not in v  # names only


# ── evidence normalization ────────────────────────────────────────────────────

def test_demo_evidence_deterministic(client):
    from app.connectors.catalog import get
    from app.connectors.evidence_profiles import demo_evidence
    c = get("TENABLE")
    assert demo_evidence(c) == demo_evidence(c)


def test_normalized_evidence_has_control_mappings(client):
    from app.connectors.catalog import get
    from app.connectors.framework import _normalize
    from app.connectors.evidence_profiles import demo_evidence
    c = get("OKTA")
    norm = _normalize(c, demo_evidence(c), "demo")
    assert all(n["controls"] for n in norm)
    mfa = next(n for n in norm if n["evidence_type"] == "mfa_enabled")
    fams = {m["framework"] for m in mfa["controls"]}
    assert "NIST_800_53" in fams and "ISO_27001_2022" in fams
    assert any(m["control_id"].startswith("IA-2") for m in mfa["controls"])


def test_supported_controls_multi_framework(client):
    from app.connectors.catalog import get
    from app.connectors.framework import supported_controls
    sc = supported_controls(get("ENTRA_ID"))
    assert "NIST_800_53" in sc and "SOC_2" in sc and "GDPR" in sc


def test_ai_governance_maps_to_ai_frameworks(client):
    from app.connectors.framework import _control_map
    m = _control_map()["ai_system_inventory"]
    assert "ISO_42001" in m and "NIST_AI_RMF" in m


# ── API routes ────────────────────────────────────────────────────────────────

def test_connectors_catalog_endpoint(client):
    r = client.get("/connectors/catalog")
    assert r.status_code == 200
    assert len(r.json()) >= 40


def test_connectors_catalog_category_filter(client):
    r = client.get("/connectors/catalog?category=security")
    assert r.status_code == 200
    assert all(c["category"] == "security" for c in r.json())


def test_connectors_status_masks_secrets(client):
    r = client.get("/connectors/status")
    assert r.status_code == 200
    body = r.text
    # env var NAMES may appear; obviously secret-looking values must not
    for s in r.json():
        assert "value" not in s.get("credentials", {})
        assert set(s["credentials"].keys()) <= {"required", "missing"}


def test_connector_detail_and_404(client):
    ok = client.get("/connectors/GITHUB")
    assert ok.status_code == 200
    assert ok.json()["supported_controls"]
    assert client.get("/connectors/DOES_NOT_EXIST").status_code == 404


def test_connector_test_endpoint_demo_mode(client):
    r = client.post("/connectors/WIZ/test")
    assert r.status_code == 200
    d = r.json()
    assert d["ok"] is True and d["mode"] in ("demo", "live")


def test_connector_sync_persists_evidence(client):
    r = client.post("/connectors/CROWDSTRIKE/sync", json={"tenant_id": "ct"})
    assert r.status_code == 200
    assert r.json()["evidence_count"] >= 3
    ev = client.get("/connectors/CROWDSTRIKE/evidence?tenant_id=ct").json()
    assert len(ev) == r.json()["evidence_count"]
    assert all(e["controls"] for e in ev)


def test_sync_is_idempotent_replace(client):
    a = client.post("/connectors/JIRA/sync", json={"tenant_id": "idem"}).json()
    b = client.post("/connectors/JIRA/sync", json={"tenant_id": "idem"}).json()
    ev = client.get("/connectors/JIRA/evidence?tenant_id=idem").json()
    assert len(ev) == b["evidence_count"] == a["evidence_count"]  # replaced, not duplicated


def test_evidence_by_connector_alias(client):
    client.post("/connectors/ONETRUST/sync", json={"tenant_id": "alias_t"})
    a = client.get("/connectors/ONETRUST/evidence?tenant_id=alias_t").json()
    b = client.get("/evidence/by-connector/ONETRUST?tenant_id=alias_t").json()
    assert len(a) == len(b) >= 1


def test_status_reflects_last_sync(client):
    client.post("/connectors/SNYK/sync", json={"tenant_id": "default"})
    st = client.get("/connectors/status").json()
    snyk = next(s for s in st if s["key"] == "SNYK")
    assert snyk["last_sync_at"] is not None
    assert snyk["evidence_count"] >= 1


def test_demo_connector_live_collection(client):
    r = client.post("/connectors/DEMO/sync", json={"tenant_id": "default"}).json()
    assert r["mode"] == "live"  # registry collect_telemetry path


def test_legacy_connectors_route_unchanged(client):
    r = client.get("/connectors")
    assert r.status_code == 200
    assert "source_system" in r.json()[0]
