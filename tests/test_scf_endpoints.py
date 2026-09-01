"""HTTP surface for the SCF crosswalk endpoints.

tests/test_scf_crosswalk.py deliberately stays stdlib-only so it runs under
plain unittest; this module covers what only a real FastAPI stack can reach —
the routes' status codes, RBAC gating, and response shape.

The most load-bearing test here is
``test_verification_reports_a_complete_scope``. Locally the declarative check
pack cannot load at all (it imports app.models, which needs SQLAlchemy and
pydantic), so every local run is a *degraded* run — which is precisely how the
silent-scope-collapse defect stayed invisible in the first place. Under CI the
pack does load, so this is the only place the healthy path is exercised for
real rather than under a stub. If the pack ever silently stops merging, this
test fails instead of the report quietly returning a smaller denominator and a
higher percentage.
"""
from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_scf_api.db")
os.environ.setdefault("EVIDENCE_LOCAL_PATH", "./test_scf_api_ev")

import pytest
from fastapi.testclient import TestClient

from app.database import init_db


@pytest.fixture(scope="module")
def client():
    init_db()
    from app.main import app
    with TestClient(app) as c:
        yield c


# ── /v1/scf/crosswalk ──
def test_lookup_by_nist_id(client):
    r = client.get("/v1/scf/crosswalk", params={"nist_id": "SC-28"})
    assert r.status_code == 200
    body = r.json()
    assert body["nist_id"] == "SC-28"
    assert body["nist_id_in_catalog"] is True
    assert "A.8.24" in body["iso_27001_annex_a"]
    assert body["scf_version"].startswith("scf-")


def test_lookup_by_iso_id(client):
    r = client.get("/v1/scf/crosswalk", params={"iso_id": "A.8.24"})
    assert r.status_code == 200
    body = r.json()
    assert body["iso_id_in_catalog"] is True
    assert "SC-28" in body["nist_800_53_r5"]


def test_lookup_requires_at_least_one_id(client):
    assert client.get("/v1/scf/crosswalk").status_code == 400


def test_unknown_id_is_flagged_rather_than_answered(client):
    """A typo must not come back looking like a real finding.

    Both of these return an empty list; only the in_catalog flag distinguishes
    "SCF doesn't map this real control" from "this control doesn't exist".
    """
    real_unmapped = client.get("/v1/scf/crosswalk", params={"nist_id": "AC-25"}).json()
    typo = client.get("/v1/scf/crosswalk", params={"nist_id": "SC-999"}).json()
    assert real_unmapped["iso_27001_annex_a"] == typo["iso_27001_annex_a"] == []
    assert real_unmapped["nist_id_in_catalog"] is True
    assert typo["nist_id_in_catalog"] is False


# ── /v1/scf/verify-crosswalk ──
def test_verification_reports_a_complete_scope(client):
    """The healthy path, exercised for real — see the module docstring."""
    body = client.get("/v1/scf/verify-crosswalk").json()
    assert body["reference_data"]["loaded"] is True
    assert body["declarative_pack"]["loaded"] is True, (
        f"the declarative check pack failed to merge: "
        f"{body['declarative_pack']['error']} — the verification report is "
        f"silently covering only the hand-written controls")
    assert body["scope_complete"] is True
    # the declarative pack must actually contribute controls, not merge zero
    assert body["declarative_pack"]["checks_with_crosswalk"] > 0
    assert body["controls_in_crosswalk"] > body["declarative_pack"]["checks_with_crosswalk"]


def test_verification_denominator_reconciles(client):
    body = client.get("/v1/scf/verify-crosswalk").json()
    assert (body["controls_checked"] + body["controls_skipped"]
            == body["controls_in_crosswalk"])
    assert (body["controls_verified"] + body["controls_unverified"]
            == body["controls_checked"])


def test_skipped_controls_are_named_not_just_counted(client):
    body = client.get("/v1/scf/verify-crosswalk").json()
    assert len(body["skipped"]) == body["controls_skipped"]
    for entry in body["skipped"]:
        assert entry["control_id"] and entry["reason"]


# ── RBAC ──
def test_scf_routes_require_a_key_when_keys_are_configured(monkeypatch):
    """Both routes are gated on Permission.READ; with keys configured an
    unauthenticated caller must not reach either of them."""
    monkeypatch.setenv("COMP_LENS_API_KEYS", "scfsecret")
    from app.main import app as auth_app
    with TestClient(auth_app) as c:
        assert c.get("/v1/scf/crosswalk", params={"nist_id": "SC-28"}).status_code == 401
        assert c.get("/v1/scf/verify-crosswalk").status_code == 401
        ok = c.get("/v1/scf/crosswalk", params={"nist_id": "SC-28"},
                   headers={"X-API-Key": "scfsecret"})
        assert ok.status_code == 200
