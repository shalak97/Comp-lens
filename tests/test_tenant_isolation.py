"""Cross-tenant isolation regressions.

Each test here encodes a bug that was live: a route where holding a valid id
for *someone else's* row was enough to read or write it, because the
permission check only proved the caller may write *something*, never that they
may write *this*.

The pattern worth remembering when adding a route: `require(Permission.WRITE)`
and `authorize_tenant(p, tenant_id)` both answer "may this principal act as
this tenant". Neither answers "does the object named in the URL belong to that
tenant". When a path carries an id, that second question needs its own check.

A note on why some tests configure COMP_LENS_API_KEYS and others don't. With
no keys set, auth is disabled and every caller becomes an all-tenant admin
(app/auth.require_principal), so `p.can_access(...)` is always True. A test for
a principal-based check is therefore vacuous unless it runs under a
tenant-scoped key. Checks that compare a row's tenant_id against the tenant
named in the request are independent of the principal and test fine either way.
"""
from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_isolation.db")
os.environ.setdefault("EVIDENCE_LOCAL_PATH", "./test_isolation_ev")

import pytest
from fastapi.testclient import TestClient

from app.database import init_db


@pytest.fixture(scope="module")
def client():
    init_db()
    from app.main import app
    with TestClient(app) as c:
        yield c


# ──────────────────────────────────────────────────────────────────────
# audits: refresh-posture wrote across tenants
#
# refresh_posture() selected AuditControl rows by audit_id alone and mutated
# auto_status on them. authorize_tenant() passed because the caller genuinely
# owned the tenant they named — but nothing tied the audit in the URL to it,
# so tenant A's posture was written onto tenant B's audit rows.
# ──────────────────────────────────────────────────────────────────────
def test_refresh_posture_rejects_another_tenants_audit(client):
    made = client.post("/audits", params={"tenant_id": "victim-b"},
                       json={"name": "B's audit", "framework": "NIST"})
    assert made.status_code == 200, made.text
    audit_id = made.json()["id"]

    r = client.post(f"/audits/{audit_id}/refresh-posture",
                    params={"tenant_id": "attacker-a"})
    assert r.status_code == 404, (
        "an audit owned by another tenant must not be refreshable, "
        f"got {r.status_code}: {r.text}")

    # the victim's audit is untouched and still readable
    assert client.get(f"/audits/{audit_id}",
                      params={"tenant_id": "victim-b"}).status_code == 200


def test_refresh_posture_still_works_for_the_owning_tenant(client):
    made = client.post("/audits", params={"tenant_id": "owner-t"},
                       json={"name": "own audit", "framework": "NIST"})
    audit_id = made.json()["id"]
    r = client.post(f"/audits/{audit_id}/refresh-posture", params={"tenant_id": "owner-t"})
    assert r.status_code == 200, r.text
    assert "controls" in r.json()


def test_refresh_posture_unknown_audit_is_404(client):
    r = client.post("/audits/no-such-audit/refresh-posture", params={"tenant_id": "owner-t"})
    assert r.status_code == 404


def test_audit_progress_counts_only_the_owning_tenants_rows(client):
    """_progress() accepted tenant_id but did not apply it, counting
    AuditControl/EvidenceRequest rows by audit_id alone."""
    made = client.post("/audits", params={"tenant_id": "prog-t"},
                       json={"name": "progress audit", "framework": "NIST"})
    audit_id = made.json()["id"]
    body = client.get(f"/audits/{audit_id}", params={"tenant_id": "prog-t"}).json()
    assert body["controls_total"] >= 0
    assert body["controls_total"] == len(
        client.get(f"/audits/{audit_id}/controls", params={"tenant_id": "prog-t"}).json())


# ──────────────────────────────────────────────────────────────────────
# evidence hits: confirm accepted any hit id from any tenant
#
# The route took Permission.WRITE and passed hit_id straight through with no
# tenant check at all. Beyond flipping another tenant's hit, auto_attest would
# mint attestations *in that tenant* marking its controls compliant, under an
# approver string chosen by the caller.
#
# This one is principal-based, so it needs a tenant-scoped key to mean anything.
# ──────────────────────────────────────────────────────────────────────
def _seed_hit(tenant: str, doc_id: str = "doc-x") -> str:
    from app.database import SessionLocal
    from app.models import EvidenceConceptHit
    db = SessionLocal()
    try:
        hit = EvidenceConceptHit(tenant_id=tenant, doc_id=doc_id,
                                 concept_id="encryption_at_rest",
                                 quote="All data at rest is encrypted.",
                                 confidence=0.9, method="lexicon", confirmed=False)
        db.add(hit)
        db.commit()
        db.refresh(hit)
        return hit.id
    finally:
        db.close()


def _hit_is_confirmed(hit_id: str) -> bool:
    from app.database import SessionLocal
    from app.models import EvidenceConceptHit
    db = SessionLocal()
    try:
        return bool(db.get(EvidenceConceptHit, hit_id).confirmed)
    finally:
        db.close()


def test_confirm_hit_rejects_a_hit_owned_by_another_tenant(client, monkeypatch):
    init_db()
    hit_id = _seed_hit("hit-victim")

    # a key scoped to a different tenant, with WRITE via the operator role
    monkeypatch.setenv("COMP_LENS_API_KEYS", "attackerkey:hit-attacker:operator")
    from app.main import app as scoped_app
    with TestClient(scoped_app) as c:
        r = c.post(f"/evidence/hits/{hit_id}/confirm",
                   headers={"X-API-Key": "attackerkey"},
                   json={"confirmed": True, "auto_attest": True, "approver": "attacker"})
        assert r.status_code == 404, (
            "confirming a hit owned by another tenant must 404, "
            f"got {r.status_code}: {r.text}")

    assert not _hit_is_confirmed(hit_id), "the victim's hit was mutated"


def test_confirm_hit_works_for_the_owning_tenant(client, monkeypatch):
    init_db()
    hit_id = _seed_hit("hit-owner")

    monkeypatch.setenv("COMP_LENS_API_KEYS", "ownerkey:hit-owner:operator")
    from app.main import app as scoped_app
    with TestClient(scoped_app) as c:
        r = c.post(f"/evidence/hits/{hit_id}/confirm",
                   headers={"X-API-Key": "ownerkey"},
                   json={"confirmed": True})
        assert r.status_code == 200, r.text

    assert _hit_is_confirmed(hit_id)


def test_confirm_hit_unknown_id_is_404(client):
    r = client.post("/evidence/hits/no-such-hit/confirm", json={"confirmed": True})
    assert r.status_code == 404


# ──────────────────────────────────────────────────────────────────────
# the duplicate registration
#
# POST /v1/integrate/ai-systems/{system_id}/to-risk was declared twice. FastAPI
# serves the first, so the body-only variant won and the query parameter the
# dashboard actually sends was discarded — every risk landed in "default".
# ──────────────────────────────────────────────────────────────────────
def test_route_is_registered_exactly_once():
    from app.main import app
    matches = [r for r in app.routes
               if getattr(r, "path", None) == "/v1/integrate/ai-systems/{system_id}/to-risk"]
    assert len(matches) == 1, (
        f"route registered {len(matches)} times; the later one is unreachable "
        f"and silently diverges from the one FastAPI serves")


def test_ai_system_to_risk_honours_the_tenant_query_parameter(client):
    """The dashboard sends the tenant as ?tenant_id= (see withTenant() in
    dashboard.html) with an empty body, which the surviving body-only handler
    ignored — so a non-default tenant's risk was filed under "default"."""
    made = client.post("/ai-systems", json={"tenant_id": "aitenant",
                                            "name": "scoring-model", "risk_tier": "high"})
    assert made.status_code == 200, made.text
    system_id = made.json()["id"]

    r = client.post(f"/v1/integrate/ai-systems/{system_id}/to-risk",
                    params={"tenant_id": "aitenant"}, json={})
    assert r.status_code == 200, r.text

    mine = client.get("/grc/risks", params={"tenant_id": "aitenant"}).json()
    assert any(x.get("category") == "ai_governance" for x in mine), (
        "the risk was not filed under the tenant named in ?tenant_id")


def test_ai_system_to_risk_still_accepts_the_tenant_in_the_body(client):
    """Backward compatibility: the body form was the only one that worked
    before, so existing API clients must keep working."""
    made = client.post("/ai-systems", json={"tenant_id": "bodytenant",
                                            "name": "body-model", "risk_tier": "high"})
    system_id = made.json()["id"]
    r = client.post(f"/v1/integrate/ai-systems/{system_id}/to-risk",
                    json={"tenant_id": "bodytenant"})
    assert r.status_code == 200, r.text
    mine = client.get("/grc/risks", params={"tenant_id": "bodytenant"}).json()
    assert any(x.get("category") == "ai_governance" for x in mine)
