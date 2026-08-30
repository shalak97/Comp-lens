"""Real-world scenario tests: multi-tenant SaaS operation.

Comp-Lens is sold as a multi-tenant platform, so the scenarios that matter most
are the ones where one customer's actions must not be able to reach another
customer's data — and where an ordinary compliance workflow (a time-boxed
waiver) has to survive a round trip through the database.

These are written from the operator's point of view: what a real tenant would
actually do through the HTTP API, not what the internals happen to make easy.
"""
from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_rw_mt.db")
os.environ.setdefault("EVIDENCE_LOCAL_PATH", "./test_rw_mt_evidence")

from datetime import UTC, datetime, timedelta  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import init_db  # noqa: E402


@pytest.fixture(scope="module")
def client():
    init_db()
    from app.main import app
    with TestClient(app) as c:
        yield c


def _make_schedule(client, tenant: str, asset: str) -> str:
    r = client.post("/schedules", json={
        "tenant_id": tenant, "name": f"{tenant}-nightly", "interval_minutes": 1440,
        "controls": [{"framework": "NIST", "control_id": "SC-7",
                      "source_system": "DEMO", "asset_id": asset}],
    })
    assert r.status_code == 200, r.text
    return r.json()["schedule_id"]


# ──────────────────────────────────────────────────────────────────────────
# Scenario: two customers on one deployment
# ──────────────────────────────────────────────────────────────────────────
def test_tenant_cannot_run_another_tenants_schedule(client):
    """A tenant must not be able to trigger another tenant's scheduled run.

    Real-world shape: an authenticated customer holds an API key scoped to
    their own tenant, so `authorize_tenant` legitimately passes for the tenant
    they name. If the service layer then loads the schedule by id alone, that
    customer can fire someone else's schedule — writing findings and evidence
    into the victim's tenant, burning the victim's connector API quota, and
    reading back the victim's schedule id and next-run time in the response.

    Every sibling method on ScheduleService (delete, list) filters on
    tenant_id; run() is the one that does not.
    """
    victim_schedule = _make_schedule(client, "victim-corp", "victim-asset")

    r = client.post(f"/schedules/{victim_schedule}/run?tenant_id=attacker-corp")

    assert r.status_code == 404, (
        "a schedule owned by another tenant must not be runnable — got "
        f"{r.status_code}: {r.text}")


def test_tenant_cannot_delete_another_tenants_schedule(client):
    """The delete counterpart — this one already scopes by tenant."""
    victim_schedule = _make_schedule(client, "victim-corp-2", "victim-asset-2")
    r = client.delete(f"/schedules/{victim_schedule}?tenant_id=attacker-corp")
    assert r.status_code == 404

    still_there = client.get("/schedules?tenant_id=victim-corp-2").json()
    assert any(s["schedule_id"] == victim_schedule for s in still_there)


def test_tenant_cannot_mutate_another_tenants_finding(client):
    """Marking someone else's finding 'risk_accepted' would silently clear a
    real violation off their compliance report."""
    client.post("/assessments", json={
        "tenant_id": "victim-corp-3", "control_id": "SC-28", "source_system": "DEMO",
        "asset_id": "db-1", "params": {"fail": True}})
    findings = client.get("/findings?tenant_id=victim-corp-3").json()
    assert findings, "setup failed: victim has no finding"
    fid = findings[0]["finding_id"]

    r = client.patch(f"/findings/{fid}?tenant_id=attacker-corp",
                     json={"lifecycle": "risk_accepted"})
    assert r.status_code == 404

    after = client.get("/findings?tenant_id=victim-corp-3").json()
    assert after[0]["lifecycle"] != "risk_accepted"


def test_summary_never_mixes_tenants(client):
    """The compliance score is the number customers act on; it must count only
    their own estate."""
    client.post("/assessments", json={
        "tenant_id": "iso-a", "control_id": "SC-28", "source_system": "DEMO",
        "asset_id": "a-1", "params": {"fail": True}})
    client.post("/assessments", json={
        "tenant_id": "iso-b", "control_id": "SC-28", "source_system": "DEMO",
        "asset_id": "b-1"})

    a = client.get("/summary?tenant_id=iso-a").json()
    b = client.get("/summary?tenant_id=iso-b").json()

    assert a["by_status"]["fail"] == 1 and a["by_status"]["pass"] == 0
    assert b["by_status"]["pass"] == 1 and b["by_status"]["fail"] == 0


# ──────────────────────────────────────────────────────────────────────────
# Scenario: the ordinary time-boxed waiver workflow
# ──────────────────────────────────────────────────────────────────────────
def test_waiver_with_an_expiry_date_suppresses_the_failure(client):
    """A waiver with an end date is the *normal* compliance case.

    Auditors expect exceptions to be time-boxed; an open-ended waiver is the
    unusual one. The existing suite only ever creates waivers with no
    expires_at, so the expiry comparison in WaiverService is never exercised.

    On SQLite, DateTime(timezone=True) round-trips to a NAIVE datetime (SQLite
    has no native timezone type), while the comparison operand is
    datetime.now(UTC) — timezone-aware. Comparing the two raises TypeError,
    which surfaces as a 500 on /summary. Eight other modules in this codebase
    (freshness, bitemporal, posture_history, evidence_policy, agent_audit,
    trust_graph, crawler, evidence_sign) each carry their own naive->aware
    coercion helper for exactly this reason; waivers.py does not.
    """
    client.post("/assessments", json={
        "tenant_id": "wv-exp", "control_id": "SC-28", "source_system": "DEMO",
        "asset_id": "bucket-x", "params": {"fail": True}})
    assert client.get("/summary?tenant_id=wv-exp").json()["by_status"]["fail"] == 1

    expires = (datetime.now(UTC) + timedelta(days=90)).isoformat()
    w = client.post("/waivers", json={
        "tenant_id": "wv-exp", "control_id": "SC-28", "asset_id": "bucket-x",
        "reason": "compensating control; remediation scheduled Q3",
        "approver": "ciso@acme.example", "expires_at": expires})
    assert w.status_code == 200, w.text

    r = client.get("/summary?tenant_id=wv-exp")
    assert r.status_code == 200, (
        "a waiver with an expiry date must not break the compliance summary — "
        f"got {r.status_code}: {r.text}")
    body = r.json()
    assert body["waived"] == 1
    assert body["by_status"]["fail"] == 0


def test_expired_waiver_stops_suppressing_the_failure(client):
    """Once the exception lapses, the violation must reappear — otherwise a
    lapsed waiver hides a real finding indefinitely."""
    client.post("/assessments", json={
        "tenant_id": "wv-lapsed", "control_id": "SC-28", "source_system": "DEMO",
        "asset_id": "bucket-y", "params": {"fail": True}})

    expired = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    w = client.post("/waivers", json={
        "tenant_id": "wv-lapsed", "control_id": "SC-28", "asset_id": "bucket-y",
        "reason": "expired exception", "approver": "ciso@acme.example",
        "expires_at": expired})
    assert w.status_code == 200, w.text

    r = client.get("/summary?tenant_id=wv-lapsed")
    assert r.status_code == 200, f"expired waiver broke /summary: {r.text}"
    body = r.json()
    assert body["by_status"]["fail"] == 1, "an expired waiver must not suppress"
    assert body["waived"] == 0


# ──────────────────────────────────────────────────────────────────────────
# Scenario: duplicate submissions from a retrying client
# ──────────────────────────────────────────────────────────────────────────
def test_repeated_assessment_is_idempotent(client):
    """A retrying client (or a double-clicked UI) must not create duplicate
    findings that inflate the failure count."""
    payload = {"tenant_id": "idem-rw", "control_id": "SC-28", "source_system": "DEMO",
               "asset_id": "same-asset", "params": {"fail": True}}
    first = client.post("/assessments", json=payload).json()
    second = client.post("/assessments", json=payload).json()

    assert first["finding_id"] == second["finding_id"]
    assert client.get("/summary?tenant_id=idem-rw").json()["total"] == 1
