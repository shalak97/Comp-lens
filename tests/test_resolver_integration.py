"""The resolver through the real HTTP surface, against a real database.

The companion file, test_resolver_routing_paths.py, lifts `resolve()` out of
its module and drives it with fakes — that is a unit test, and it is where the
branch coverage comes from. It deliberately proves nothing about whether the
function is wired to a route, whether its decision actually persists, or whether
the persisted row can be read back.

This file covers exactly that seam, and only that seam: request in, routing
decision on disk, decision out. It uses a real control from
app/data/control_bindings.json rather than an invented one, because a binding
that exists in a fixture but not in the shipped data would make this pass while
the product was broken.

AC-1 is chosen because its binding is document-then-attestation with no
telemetry strategy, so on an empty tenant it resolves deterministically to the
attestation floor with no connectors configured and no evidence loaded — an
outcome that does not depend on any connector's credentials being present.
"""
from __future__ import annotations

import json
import pathlib

import pytest
from fastapi.testclient import TestClient

from app.database import init_db

ROOT = pathlib.Path(__file__).resolve().parent.parent
BINDINGS = ROOT / "app" / "data" / "control_bindings.json"

TENANT = "resolver-integration"


@pytest.fixture(scope="module")
def client():
    init_db()
    from app.main import app
    with TestClient(app) as c:
        yield c


def test_the_control_this_file_relies_on_still_has_a_binding():
    """Guards the premise rather than the behaviour.

    Every assertion below assumes AC-1 routes document-then-attestation. If the
    shipped bindings change, this fails first and says so, instead of the other
    tests failing for a reason that looks like a resolver bug.
    """
    data = json.loads(BINDINGS.read_text())
    binding = data["frameworks"]["NIST_800_53"]["AC-1"]
    types = {s["type"] for s in binding["strategies"]}
    assert "attestation" in types, "AC-1 no longer has an attestation floor"
    assert "telemetry" not in types, (
        "AC-1 grew a telemetry strategy; this file's expected outcome on an "
        "empty tenant is no longer deterministic")


# ── the seam: request in, decision persisted, decision out ──
def test_resolving_a_control_persists_a_decision_that_can_be_read_back(client):
    resolved = client.post("/resolve", json={
        "tenant_id": TENANT, "framework": "NIST_800_53",
        "control_id": "AC-1", "dry_run": False})
    assert resolved.status_code == 200, resolved.text
    body = resolved.json()
    assert body["decision_id"], "no decision id came back"
    assert body["chosen"]["type"] == "attestation"
    assert body["status"] == "not_assessed"

    listed = client.get("/resolve/decisions", params={"tenant_id": TENANT})
    assert listed.status_code == 200
    ids = [d["decision_id"] for d in listed.json()]
    assert body["decision_id"] in ids, (
        "the decision the POST returned is not in the decision log — the write "
        "and the read disagree about where decisions live")


def test_a_dry_run_records_the_route_without_claiming_an_outcome(client):
    body = client.post("/resolve", json={
        "tenant_id": TENANT, "framework": "NIST_800_53",
        "control_id": "AC-1", "dry_run": True}).json()
    assert body["executed"] is False
    assert body["status"] is None, "a dry run reported a compliance status"
    # ...and it is still logged, because "what would we have done" is itself
    # worth an audit record.
    listed = client.get("/resolve/decisions", params={"tenant_id": TENANT}).json()
    assert any(d["decision_id"] == body["decision_id"] for d in listed)


def test_decisions_are_scoped_to_their_tenant(client):
    """Not an authorization test — the suite runs as a dev-mode admin who may
    read every tenant. This is about the QUERY: asking for one tenant's
    decisions must not return another's."""
    other = f"{TENANT}-other"
    mine = client.post("/resolve", json={
        "tenant_id": TENANT, "control_id": "AC-1", "dry_run": True}).json()
    theirs = client.post("/resolve", json={
        "tenant_id": other, "control_id": "AC-1", "dry_run": True}).json()

    listed = client.get("/resolve/decisions", params={"tenant_id": other}).json()
    ids = [d["decision_id"] for d in listed]
    assert theirs["decision_id"] in ids
    assert mine["decision_id"] not in ids, (
        "a decision belonging to another tenant appeared in this tenant's log")


# ── error paths reach the client as errors, not as verdicts ──
def test_an_unknown_control_is_a_400_not_a_silent_attestation(client):
    """resolve() raises ValueError for a control with no binding, and the route
    turns that into a 400. The failure mode worth guarding is the opposite:
    answering 'not_assessed' for a control the platform has never heard of,
    which reads like a real assessment of a real control."""
    response = client.post("/resolve", json={
        "tenant_id": TENANT, "control_id": "NOT-A-REAL-CONTROL", "dry_run": True})
    assert response.status_code == 400
    assert "NOT-A-REAL-CONTROL" in response.json()["detail"]


def test_an_unknown_binding_lookup_is_a_404(client):
    response = client.get("/ontology/bindings",
                          params={"control_id": "NOT-A-REAL-CONTROL"})
    assert response.status_code == 404


def test_the_ontology_is_served_and_declares_planes(client):
    body = client.get("/ontology/planes").json()
    assert body.get("planes"), "the ontology served no planes"


# ── the record carries its explanation ──
def test_the_logged_decision_explains_what_was_skipped(client):
    """The reason the decision log exists. A route with no alternatives recorded
    is indistinguishable from a route that had no alternatives."""
    body = client.post("/resolve", json={
        "tenant_id": TENANT, "control_id": "AC-1", "dry_run": True}).json()
    assert body["skipped"], (
        "AC-1 skipped its document strategy on an empty tenant but recorded no "
        "reason for it")
    assert all("reason" in s for s in body["skipped"])
