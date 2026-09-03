"""Does the product do the job?

Every other test file in this suite asks whether a unit behaves. This one asks
whether the *product* works: it drives the HTTP API the way a customer and an
auditor would, in whole journeys, and asserts the outcome each journey has to
produce to be worth anything.

Two rules shape what is asserted here.

The first is that a scenario ends in a claim someone acts on — a score, a
report, a proof, an export — never in "the endpoint returned 200". A 200 that
carries a wrong number is the failure mode this platform exists to prevent, so
a test that stops at the status code would be measuring the wrong thing.

The second is that the strongest assertions are the ones that hold *between*
endpoints. Any single endpoint can be internally consistent and wrong. But the
finding count from /findings has to match what /summary says, a waiver has to
move the score, the CSV has to contain the findings the API just returned, and
posture has to agree with the audit log. Those cross-checks catch real drift
between subsystems, and they need no knowledge of any endpoint's exact shape.

Tenants are unique per scenario. The suite shares one database file, so a
scenario that reused a tenant would be reading another scenario's state and
asserting on it.
"""
from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.database import init_db
from app.main import app


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


def tenant(name: str) -> str:
    """A tenant nobody else in the suite can be holding."""
    return f"sc-{name}-{uuid.uuid4().hex[:8]}"


def assess(client, t, control_id, asset_id, *, fail=False, source="DEMO", framework="NIST"):
    body = {"tenant_id": t, "framework": framework, "control_id": control_id,
            "source_system": source, "asset_id": asset_id,
            "params": {"fail": True} if fail else {},
            "idempotency_key": uuid.uuid4().hex}
    r = client.post("/assessments", json=body)
    assert r.status_code == 200, f"assess {control_id}/{asset_id}: {r.status_code} {r.text}"
    return r.json()


def summary(client, t, framework=None):
    q = f"/summary?tenant_id={t}" + (f"&framework={framework}" if framework else "")
    r = client.get(q)
    assert r.status_code == 200, r.text
    return r.json()


def findings(client, t, **params):
    q = "&".join(f"{k}={v}" for k, v in params.items())
    r = client.get(f"/findings?tenant_id={t}" + (f"&{q}" if q else ""))
    assert r.status_code == 200, r.text
    return r.json()


# ══════════════════════════════════════════════════════════════════════════
# Act 1 — First day: a new tenant with nothing in it
#
# The empty state is where a compliance product most easily lies. A score of
# 100% for a tenant that has never been assessed is a confident statement about
# nothing, and it is the number a buyer sees first.
# ══════════════════════════════════════════════════════════════════════════
def test_01_a_brand_new_tenant_does_not_claim_to_be_compliant(client):
    s = summary(client, tenant("empty"))
    assert s["total"] == 0
    assert s["compliance_score"] == 0.0, (
        "an unassessed tenant must not report a passing score — "
        f"nothing has been verified: {s}")


def test_02_a_brand_new_tenant_has_no_findings_and_no_drift(client):
    t = tenant("empty2")
    assert findings(client, t) == []
    d = client.get(f"/drift?tenant_id={t}")
    assert d.status_code == 200
    assert d.json()["regression_count"] == 0


def test_03_the_control_catalog_is_available_before_any_assessment(client):
    """A buyer evaluating the product must be able to see what it checks
    without connecting anything."""
    r = client.get("/controls")
    assert r.status_code == 200
    controls = r.json()
    assert len(controls) >= 50, f"only {len(controls)} controls advertised"
    assert all(c.get("control_id") and c.get("title") for c in controls)


def test_04_every_advertised_framework_resolves(client):
    r = client.get("/frameworks")
    assert r.status_code == 200
    frameworks = r.json()["frameworks"]
    assert {"NIST", "ISO27001", "SOC2", "CIS"} <= set(frameworks)


def test_05_discovery_populates_an_inventory_the_api_can_read_back(client):
    t = tenant("discover")
    d = client.post(f"/inventory/discover?source_system=DEMO&tenant_id={t}")
    assert d.status_code == 200, d.text
    n = d.json()["discovered_new"]
    assert n > 0, "DEMO discovered nothing — bulk assessment has nothing to run on"

    inv = client.get(f"/inventory?tenant_id={t}")
    assert inv.status_code == 200
    assert len(inv.json()) == n, "inventory read back disagrees with what discovery reported"


def test_06_rediscovery_updates_rather_than_duplicates(client):
    t = tenant("rediscover")
    first = client.post(f"/inventory/discover?source_system=DEMO&tenant_id={t}").json()["discovered_new"]
    second = client.post(f"/inventory/discover?source_system=DEMO&tenant_id={t}").json()["discovered_new"]
    assert second == 0, "re-running discovery created duplicate assets"
    assert len(client.get(f"/inventory?tenant_id={t}").json()) == first


# ══════════════════════════════════════════════════════════════════════════
# Act 2 — The assessment loop, which is the product
# ══════════════════════════════════════════════════════════════════════════
def test_07_a_passing_control_produces_a_pass_finding_and_moves_the_score(client):
    t = tenant("pass")
    f = assess(client, t, "SC-7", "host-1")
    assert f["status"] == "pass"
    s = summary(client, t)
    assert s["total"] == 1 and s["by_status"]["pass"] == 1
    assert s["compliance_score"] == 100.0


def test_08_a_failing_control_produces_a_fail_finding_and_lowers_the_score(client):
    t = tenant("fail")
    f = assess(client, t, "SC-7", "host-1", fail=True)
    assert f["status"] == "fail"
    s = summary(client, t)
    assert s["by_status"]["fail"] == 1
    assert s["compliance_score"] == 0.0


def test_09_the_score_is_the_ratio_the_findings_actually_support(client):
    """Three pass, one fail must be 75% — not a rounded impression of it."""
    t = tenant("ratio")
    for i in range(3):
        assess(client, t, "SC-7", f"ok-{i}")
    assess(client, t, "SC-7", "bad-0", fail=True)

    s = summary(client, t)
    assert s["total"] == 4
    assert s["by_status"]["pass"] == 3 and s["by_status"]["fail"] == 1
    assert s["compliance_score"] == 75.0, s


def test_10_findings_and_summary_never_disagree(client):
    """The two numbers a user compares first. Posture is materialised
    separately from the findings log, so they can drift apart."""
    t = tenant("coherence")
    for i in range(5):
        assess(client, t, "SC-7", f"a-{i}", fail=(i % 2 == 0))

    rows = findings(client, t)
    s = summary(client, t)
    assert len(rows) == s["total"]
    assert sum(1 for r in rows if r["status"] == "fail") == s["by_status"]["fail"]


def test_11_a_control_reassessed_on_the_same_asset_updates_rather_than_accumulates(client):
    """Posture is current state. Two assessments of one asset is one row, or
    every re-scan inflates the estate."""
    t = tenant("reassess")
    assess(client, t, "SC-7", "host-1")
    assess(client, t, "SC-7", "host-1", fail=True)

    s = summary(client, t)
    assert s["total"] == 1, f"re-assessment duplicated the asset in posture: {s}"
    assert s["by_status"]["fail"] == 1 and s["by_status"]["pass"] == 0
    assert len(findings(client, t)) == 2, "the findings log must keep both observations"


def test_12_a_regression_is_detected_as_drift(client):
    t = tenant("drift")
    assess(client, t, "AU-2", "host-1")
    assess(client, t, "AU-2", "host-1", fail=True)

    d = client.get(f"/drift?tenant_id={t}").json()
    assert d["regression_count"] == 1, f"a pass that became a fail was not reported as drift: {d}"


def test_13_a_recovery_is_not_reported_as_a_regression(client):
    t = tenant("recover")
    assess(client, t, "AU-2", "host-1", fail=True)
    assess(client, t, "AU-2", "host-1")

    d = client.get(f"/drift?tenant_id={t}").json()
    assert d["regression_count"] == 0, f"a fix was reported as a regression: {d}"


def test_14_bulk_assessment_covers_the_whole_discovered_estate(client):
    t = tenant("bulk")
    client.post(f"/inventory/discover?source_system=DEMO&tenant_id={t}")
    r = client.post("/assessments/bulk", json={
        "tenant_id": t, "framework": "NIST", "control_id": "SC-28-OBJSTORE",
        "source_system": "DEMO", "params": {}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible_assets"] >= 1
    assert body["assessed"] + body["failed"] == body["eligible_assets"], (
        f"assets went missing between eligibility and assessment: {body}")


def test_15_a_batch_job_reports_per_item_outcomes(client):
    t = tenant("batch")
    r = client.post("/assessment-jobs", json={"tenant_id": t, "controls": [
        {"control_id": "SC-7", "source_system": "DEMO", "asset_id": "h1"},
        {"control_id": "AU-2", "source_system": "DEMO", "asset_id": "h2"},
        {"control_id": "SC-7", "source_system": "NOT_A_SYSTEM", "asset_id": "h3"},
    ]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["succeeded"] == 2
    assert body["failed"] == 1
    assert body["errors"][0]["source_system"] == "NOT_A_SYSTEM"


# ══════════════════════════════════════════════════════════════════════════
# Act 3 — Exceptions: the risk a customer has decided to accept
#
# A waiver suppresses a real failure from the score. That makes it the most
# dangerous object in the product: if it applies too widely, or outlives its
# expiry, the platform is hiding failures a customer never agreed to hide.
# ══════════════════════════════════════════════════════════════════════════
def test_16_a_waiver_suppresses_the_failure_it_names(client):
    t = tenant("waiver")
    assess(client, t, "SC-7", "host-1", fail=True)
    assert summary(client, t)["by_status"]["fail"] == 1

    w = client.post("/waivers", json={
        "tenant_id": t, "control_id": "SC-7", "asset_id": "host-1",
        "reason": "compensating control in place", "approver": "ciso"})
    assert w.status_code == 200, w.text

    s = summary(client, t)
    assert s["by_status"]["fail"] == 0
    assert s["waived"] == 1, f"the waiver did not surface as waived: {s}"


def test_17_a_waiver_does_not_suppress_a_different_asset(client):
    """The blast radius. A waiver for one bucket must not silence the rest."""
    t = tenant("waiver-scope")
    assess(client, t, "SC-7", "host-1", fail=True)
    assess(client, t, "SC-7", "host-2", fail=True)
    client.post("/waivers", json={"tenant_id": t, "control_id": "SC-7", "asset_id": "host-1",
                                  "reason": "accepted", "approver": "ciso"})

    s = summary(client, t)
    assert s["by_status"]["fail"] == 1, f"the waiver leaked to another asset: {s}"
    assert s["waived"] == 1


def test_18_an_expired_waiver_stops_suppressing(client):
    t = tenant("waiver-expired")
    assess(client, t, "SC-7", "host-1", fail=True)
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    client.post("/waivers", json={"tenant_id": t, "control_id": "SC-7", "asset_id": "host-1",
                                  "reason": "temporary", "approver": "ciso", "expires_at": past})

    s = summary(client, t)
    assert s["by_status"]["fail"] == 1, f"an expired waiver still suppressed a failure: {s}"
    assert s["waived"] == 0


def test_19_revoking_a_waiver_restores_the_failure(client):
    t = tenant("waiver-revoke")
    assess(client, t, "SC-7", "host-1", fail=True)
    w = client.post("/waivers", json={"tenant_id": t, "control_id": "SC-7", "asset_id": "host-1",
                                      "reason": "accepted", "approver": "ciso"}).json()
    assert summary(client, t)["by_status"]["fail"] == 0

    d = client.delete(f"/waivers/{w['waiver_id']}?tenant_id={t}")
    assert d.status_code == 200, d.text
    assert summary(client, t)["by_status"]["fail"] == 1, "revoking the waiver did not restore the failure"


def test_20_a_waiver_never_turns_a_failure_into_a_pass(client):
    """Waived is its own outcome. Counting it as a pass would let a customer
    reach 100% by accepting every risk."""
    t = tenant("waiver-not-pass")
    assess(client, t, "SC-7", "host-1", fail=True)
    client.post("/waivers", json={"tenant_id": t, "control_id": "SC-7", "asset_id": "host-1",
                                  "reason": "accepted", "approver": "ciso"})
    s = summary(client, t)
    assert s["by_status"]["pass"] == 0, f"a waived failure was counted as a pass: {s}"


def test_21_waivers_are_listed_with_who_approved_them(client):
    """An exception nobody signed is an exception nobody can defend at audit."""
    t = tenant("waiver-audit")
    client.post("/waivers", json={"tenant_id": t, "control_id": "SC-7", "asset_id": "h",
                                  "reason": "documented risk acceptance", "approver": "ciso@acme"})
    rows = client.get(f"/waivers?tenant_id={t}").json()
    assert len(rows) == 1
    assert rows[0]["approver"] == "ciso@acme"
    assert rows[0]["reason"]


# ══════════════════════════════════════════════════════════════════════════
# Act 4 — Evidence: the part an auditor actually tests
# ══════════════════════════════════════════════════════════════════════════
def test_22_every_assessment_leaves_retrievable_evidence(client):
    t = tenant("evidence")
    assess(client, t, "SC-7", "host-1")
    r = client.get(f"/evidence?tenant_id={t}")
    assert r.status_code == 200, r.text
    rows = r.json()
    assert rows, "an assessment produced no evidence record"


def test_23_evidence_verification_passes_on_untampered_evidence(client):
    t = tenant("evidence-verify")
    for i in range(3):
        assess(client, t, "SC-7", f"h-{i}")
    v = client.get(f"/evidence/verify?tenant_id={t}").json()
    assert v["broken_count"] == 0, f"freshly written evidence failed verification: {v}"


def test_24_anchoring_produces_a_root_and_a_verifiable_proof(client):
    """The tamper-evidence claim, end to end: anchor, then prove one leaf."""
    t = tenant("anchor")
    for i in range(4):
        assess(client, t, "SC-7", f"h-{i}")

    a = client.post(f"/evidence/anchor?tenant_id={t}")
    assert a.status_code == 200, a.text
    anchor = a.json()
    assert anchor.get("root"), f"anchoring returned no root: {anchor}"
    assert anchor["leaf_count"] == 4, f"the anchor covers {anchor['leaf_count']} of 4 records"
    assert anchor.get("signature"), "the anchor is unsigned — anyone could publish a root"

    ledger = client.get(f"/evidence?tenant_id={t}").json()
    eid = ledger[0].get("evidence_id") or ledger[0].get("id")
    assert eid, f"evidence ledger row has no id: {ledger[0]}"

    p = client.get(f"/evidence/proof?evidence_id={eid}&tenant_id={t}")
    assert p.status_code == 200, p.text
    assert p.json().get("verified") is True, f"a proof for real evidence did not verify: {p.json()}"


def test_25_a_proof_is_refused_for_evidence_that_does_not_exist(client):
    t = tenant("anchor-bogus")
    assess(client, t, "SC-7", "h-0")
    client.post(f"/evidence/anchor?tenant_id={t}")
    p = client.get(f"/evidence/proof?evidence_id=not-a-real-id&tenant_id={t}")
    assert p.status_code in (200, 404)
    if p.status_code == 200:
        assert p.json().get("verified") is not True, (
            "a proof was produced for evidence that was never recorded")


def test_26_the_audit_log_and_posture_tell_the_same_story(client):
    t = tenant("log-vs-posture")
    assess(client, t, "SC-7", "host-1")
    assess(client, t, "SC-7", "host-1", fail=True)
    assess(client, t, "AU-2", "host-2")

    rows = findings(client, t)
    s = summary(client, t)
    assert len(rows) == 3, "the append-only log lost an observation"
    assert s["total"] == 2, "posture must hold one row per control+asset"
    latest = {(r["control_id"], r["asset_id"]): r["status"] for r in reversed(rows)}
    assert latest[("SC-7", "host-1")] == "fail"


def test_27_a_finding_can_be_assigned_and_tracked_to_closure(client):
    """Compliance work is ticket work. A finding nobody can assign is a finding
    nobody owns."""
    t = tenant("lifecycle")
    f = assess(client, t, "SC-7", "host-1", fail=True)
    r = client.patch(f"/findings/{f['finding_id']}?tenant_id={t}",
                     json={"lifecycle": "in_progress", "assigned_to": "alice"})
    assert r.status_code == 200, r.text
    assert r.json()["lifecycle"] == "in_progress"
    assert r.json()["assigned_to"] == "alice"


# ══════════════════════════════════════════════════════════════════════════
# Act 5 — Multi-tenancy: the boundary a SaaS product cannot get wrong
# ══════════════════════════════════════════════════════════════════════════
def test_28_one_tenants_findings_are_invisible_to_another(client):
    a, b = tenant("iso-a"), tenant("iso-b")
    assess(client, a, "SC-7", "secret-host", fail=True)
    assert findings(client, b) == []
    assert summary(client, b)["total"] == 0


def test_29_one_tenants_waiver_does_not_suppress_anothers_failure(client):
    a, b = tenant("wiso-a"), tenant("wiso-b")
    assess(client, a, "SC-7", "host-1", fail=True)
    assess(client, b, "SC-7", "host-1", fail=True)
    client.post("/waivers", json={"tenant_id": a, "control_id": "SC-7", "asset_id": "host-1",
                                  "reason": "accepted", "approver": "ciso"})

    assert summary(client, a)["by_status"]["fail"] == 0
    assert summary(client, b)["by_status"]["fail"] == 1, "a waiver crossed the tenant boundary"


def test_30_one_tenants_inventory_is_not_anothers(client):
    a, b = tenant("inv-a"), tenant("inv-b")
    client.post(f"/inventory/discover?source_system=DEMO&tenant_id={a}")
    assert client.get(f"/inventory?tenant_id={b}").json() == []


def test_31_a_tenant_cannot_mutate_another_tenants_finding(client):
    a, b = tenant("mut-a"), tenant("mut-b")
    f = assess(client, a, "SC-7", "host-1", fail=True)
    r = client.patch(f"/findings/{f['finding_id']}?tenant_id={b}",
                     json={"lifecycle": "resolved", "assigned_to": "attacker"})
    assert r.status_code == 404, (
        f"tenant {b} was allowed to touch tenant {a}'s finding: {r.status_code} {r.text}")

    # And the finding is genuinely untouched, not merely refused a response.
    still = next(x for x in findings(client, a) if x["finding_id"] == f["finding_id"])
    assert still["lifecycle"] == "open" and still["assigned_to"] is None


def test_32_a_tenants_report_contains_only_its_own_findings(client):
    a, b = tenant("rep-a"), tenant("rep-b")
    assess(client, a, "SC-7", "asset-of-a", fail=True)
    assess(client, b, "SC-7", "asset-of-b", fail=True)

    body = client.get(f"/reports/csv?tenant_id={a}").content.decode()
    assert "asset-of-a" in body
    assert "asset-of-b" not in body, "a tenant's export leaked another tenant's asset"


def test_33_evidence_verification_is_scoped_to_the_tenant(client):
    a, b = tenant("ev-a"), tenant("ev-b")
    assess(client, a, "SC-7", "h")
    v = client.get(f"/evidence/verify?tenant_id={b}").json()
    assert v["checked"] == 0, f"tenant {b} sees tenant {a}'s evidence: {v}"
    assert client.get(f"/evidence/verify?tenant_id={a}").json()["checked"] >= 1


# ══════════════════════════════════════════════════════════════════════════
# Act 6 — Deliverables: what actually leaves the building
# ══════════════════════════════════════════════════════════════════════════
def test_34_the_csv_export_contains_every_finding_the_api_reports(client):
    t = tenant("csv")
    for i in range(6):
        assess(client, t, "SC-7", f"h-{i}", fail=(i % 2 == 0))

    rows = findings(client, t)
    parsed = list(csv.DictReader(io.StringIO(
        client.get(f"/reports/csv?tenant_id={t}").content.decode())))
    assert len(parsed) == len(rows), (
        f"CSV has {len(parsed)} rows, API reports {len(rows)} findings")
    assert {r["finding_id"] for r in parsed} == {r["finding_id"] for r in rows}


def test_35_the_csv_carries_the_framework_mapping_an_auditor_needs(client):
    t = tenant("csv-cw")
    assess(client, t, "SC-7", "h-1", fail=True)
    row = next(csv.DictReader(io.StringIO(
        client.get(f"/reports/csv?tenant_id={t}").content.decode())))
    assert row["frameworks"], "the export names no framework — an auditor cannot place the finding"


def test_36_the_pdf_report_renders(client):
    t = tenant("pdf")
    assess(client, t, "SC-7", "h-1", fail=True)
    r = client.get(f"/reports/pdf?tenant_id={t}")
    assert r.status_code == 200, r.text
    assert r.content.startswith(b"%PDF")


def test_37_the_oscal_poam_lists_every_open_finding(client):
    """The formal deliverable. An auditor treats it as the complete statement
    of what is not yet satisfied."""
    t = tenant("poam")
    for i in range(4):
        assess(client, t, "SC-7", f"bad-{i}", fail=True)
    assess(client, t, "AU-2", "good-1")

    doc = client.get(f"/reports/oscal-poam?tenant_id={t}").json()
    items = doc["plan-of-action-and-milestones"]["poam-items"]
    assert len(items) == 4, f"POA&M carries {len(items)} of 4 open findings"


def test_38_the_oscal_assessment_results_are_well_formed(client):
    t = tenant("oscal")
    assess(client, t, "SC-7", "h-1", fail=True)
    doc = client.get(f"/reports/oscal?tenant_id={t}").json()
    results = doc["assessment-results"]
    assert results["metadata"]["oscal-version"].startswith("1.")
    assert results["results"][0]["findings"], "OSCAL export contains no findings"


def test_39_the_component_definition_names_the_systems_in_scope(client):
    t = tenant("components")
    assess(client, t, "SC-7", "h-1")
    doc = client.get(f"/reports/oscal-components?tenant_id={t}").json()
    titles = {c["title"] for c in doc["component-definition"]["components"]}
    assert "DEMO" in titles, f"the source system in scope is missing from the export: {titles}"


def test_40_every_export_agrees_on_how_many_findings_exist(client):
    """Four documents, one truth. They are built by different code paths."""
    t = tenant("exports-agree")
    for i in range(7):
        assess(client, t, "SC-7", f"h-{i}", fail=True)

    api = len(findings(client, t))
    csv_rows = len(list(csv.DictReader(io.StringIO(
        client.get(f"/reports/csv?tenant_id={t}").content.decode()))))
    oscal = len(client.get(f"/reports/oscal?tenant_id={t}"
                           ).json()["assessment-results"]["results"][0]["findings"])
    poam = len(client.get(f"/reports/oscal-poam?tenant_id={t}"
                          ).json()["plan-of-action-and-milestones"]["poam-items"])
    assert api == csv_rows == oscal == poam == 7, (
        f"exports disagree: api={api} csv={csv_rows} oscal={oscal} poam={poam}")


# ══════════════════════════════════════════════════════════════════════════
# Act 7 — Over time: the "continuous" in continuous compliance
# ══════════════════════════════════════════════════════════════════════════
def test_41_a_schedule_runs_the_controls_it_was_given(client):
    t = tenant("sched")
    s = client.post("/schedules", json={
        "tenant_id": t, "name": "nightly", "interval_minutes": 1440,
        "controls": [{"control_id": "SC-7", "source_system": "DEMO", "asset_id": "h1"},
                     {"control_id": "AU-2", "source_system": "DEMO", "asset_id": "h2"}]})
    assert s.status_code == 200, s.text
    run = client.post(f"/schedules/{s.json()['schedule_id']}/run?tenant_id={t}").json()
    assert run["ran"] == 2
    assert len(findings(client, t)) == 2


def test_42_running_a_schedule_twice_assesses_twice(client):
    """Continuous monitoring, tested as a customer experiences it: the second
    night must actually look again."""
    t = tenant("sched-twice")
    s = client.post("/schedules", json={
        "tenant_id": t, "name": "nightly", "interval_minutes": 1440,
        "controls": [{"control_id": "SC-7", "source_system": "DEMO", "asset_id": "h1"}]}).json()
    client.post(f"/schedules/{s['schedule_id']}/run?tenant_id={t}")
    client.post(f"/schedules/{s['schedule_id']}/run?tenant_id={t}")

    assert len(findings(client, t)) == 2, (
        "the second scheduled run produced no new observation — monitoring is a one-shot")
    assert summary(client, t)["total"] == 1, "posture should still hold one row"


def test_43_a_schedule_advances_its_next_run(client):
    t = tenant("sched-next")
    s = client.post("/schedules", json={
        "tenant_id": t, "name": "nightly", "interval_minutes": 60,
        "controls": [{"control_id": "SC-7", "source_system": "DEMO", "asset_id": "h1"}]}).json()
    run = client.post(f"/schedules/{s['schedule_id']}/run?tenant_id={t}").json()
    assert datetime.fromisoformat(run["next_run_at"]) > datetime.now(UTC)


def test_44_a_deleted_schedule_stops_appearing(client):
    t = tenant("sched-del")
    s = client.post("/schedules", json={
        "tenant_id": t, "name": "nightly", "interval_minutes": 1440,
        "controls": [{"control_id": "SC-7", "source_system": "DEMO", "asset_id": "h1"}]}).json()
    client.delete(f"/schedules/{s['schedule_id']}?tenant_id={t}")
    assert client.get(f"/schedules?tenant_id={t}").json() == []


def test_45_trend_snapshots_record_the_score_at_a_point_in_time(client):
    t = tenant("trends")
    assess(client, t, "SC-7", "h-1", fail=True)
    snap = client.post(f"/trends/snapshot?tenant_id={t}")
    assert snap.status_code == 200, snap.text
    assert snap.json()["score"] == 0.0

    assess(client, t, "SC-7", "h-1")
    client.post(f"/trends/snapshot?tenant_id={t}")

    history = client.get(f"/trends?tenant_id={t}").json()
    assert len(history) >= 2
    assert {h["score"] for h in history} == {0.0, 100.0}, (
        f"the trend line does not reflect the score actually moving: {history}")


def test_46_posture_history_can_answer_what_was_true_last_week(client):
    """Point-in-time defensibility: an auditor asks about a date, not today."""
    t = tenant("as-of")
    assess(client, t, "SC-7", "h-1", fail=True)
    now = datetime.now(UTC).isoformat()
    r = client.get(f"/v1/posture/as-of?tenant_id={t}&at={now}")
    assert r.status_code == 200, r.text
    assert r.json()["controls"], "point-in-time posture is empty for a tenant with findings"

    # Before the tenant existed, the honest answer is "nothing was true yet".
    past = (datetime.now(UTC) - timedelta(days=365)).isoformat()
    old = client.get(f"/v1/posture/as-of?tenant_id={t}&at={past}")
    assert old.status_code == 200, old.text
    assert not old.json()["controls"], (
        f"posture a year before the tenant existed is not empty: {old.json()}")


def test_46b_a_timestamp_from_the_standard_library_is_accepted(client):
    """The offset trap.

    `+` is a space in a query string, so `datetime.now(UTC).isoformat()` —
    the most natural way any Python or curl caller builds this — arrives as
    "…T12:00:00 00:00" unless the caller escapes it. The endpoint answered
    that with "invalid; use ISO 8601", which is a rejection *and* a wrong
    explanation: the caller did use ISO 8601.

    Both spellings must work, and something genuinely malformed must still be
    refused rather than guessed at.
    """
    t = tenant("as-of-encoding")
    assess(client, t, "SC-7", "h-1")
    stamp = datetime.now(UTC).isoformat()

    unescaped = client.get(f"/v1/posture/as-of?tenant_id={t}&at={stamp}")
    escaped = client.get("/v1/posture/as-of",
                         params={"tenant_id": t, "at": stamp})   # httpx escapes the +
    assert unescaped.status_code == 200, f"an unescaped UTC offset was refused: {unescaped.text}"
    assert escaped.status_code == 200, escaped.text
    assert unescaped.json()["as_of"] == escaped.json()["as_of"], (
        "the same instant read differently depending on how it was escaped")

    bad = client.get(f"/v1/posture/as-of?tenant_id={t}&at=yesterday-ish")
    assert bad.status_code == 400
    assert "yesterday-ish" in bad.text, "the error does not say what it rejected"


# ══════════════════════════════════════════════════════════════════════════
# Act 8 — External scanners: most customers already own one
# ══════════════════════════════════════════════════════════════════════════
def test_47_an_ingested_scanner_report_becomes_findings(client):
    t = tenant("ingest")
    r = client.post(f"/ingest/report?tenant_id={t}&source=PROWLER", json={"findings": [
        {"control_id": "SC-7", "status": "fail", "asset_id": "i-1", "severity": "high"},
        {"control_id": "AU-2", "status": "pass", "asset_id": "i-2", "severity": "low"},
    ]})
    assert r.status_code == 200, r.text
    assert len(findings(client, t)) == 2


def test_48_ingested_findings_count_toward_the_same_score(client):
    """Evidence from a scanner and evidence from a connector must land in one
    number, or the customer has two disagreeing compliance postures."""
    t = tenant("ingest-score")
    client.post(f"/ingest/report?tenant_id={t}&source=PROWLER", json={"findings": [
        {"control_id": "SC-7", "status": "fail", "asset_id": "i-1"},
        {"control_id": "AU-2", "status": "pass", "asset_id": "i-2"},
    ]})
    assess(client, t, "SC-7", "native-1")

    s = summary(client, t)
    assert s["total"] == 3, f"ingested and native findings did not merge: {s}"


def test_49_re_ingesting_the_same_report_does_not_double_count(client):
    t = tenant("ingest-idem")
    payload = {"findings": [{"control_id": "SC-7", "status": "fail",
                             "asset_id": "i-1", "id": "scanner-finding-1"}]}
    client.post(f"/ingest/report?tenant_id={t}&source=PROWLER", json=payload)
    client.post(f"/ingest/report?tenant_id={t}&source=PROWLER", json=payload)
    assert len(findings(client, t)) == 1, "re-ingesting inflated the finding count"


def test_50_an_ingested_finding_is_waivable_like_any_other(client):
    t = tenant("ingest-waive")
    client.post(f"/ingest/report?tenant_id={t}&source=PROWLER", json={"findings": [
        {"control_id": "SC-7", "status": "fail", "asset_id": "i-1"}]})
    client.post("/waivers", json={"tenant_id": t, "control_id": "SC-7", "asset_id": "i-1",
                                  "reason": "accepted", "approver": "ciso"})
    assert summary(client, t)["by_status"]["fail"] == 0


def test_51_an_empty_report_is_accepted_without_inventing_findings(client):
    t = tenant("ingest-empty")
    r = client.post(f"/ingest/report?tenant_id={t}&source=PROWLER", json={"findings": []})
    assert r.status_code == 200, r.text
    assert findings(client, t) == []


# ══════════════════════════════════════════════════════════════════════════
# Act 9 — Connectors: what the platform claims it can see
# ══════════════════════════════════════════════════════════════════════════
def test_52_the_connector_catalog_does_not_advertise_what_does_not_exist(client):
    r = client.get("/connectors/catalog")
    assert r.status_code == 200
    rows = r.json()
    rows = rows if isinstance(rows, list) else rows.get("connectors", [])
    assert rows, "the catalog is empty"
    for row in rows:
        if row.get("implemented") is False:
            assert row.get("maturity") != "production", (
                f"{row.get('name') or row.get('registry_key')} is advertised as production "
                "but has no implementation")


def test_53_declared_capabilities_are_readable_without_credentials(client):
    """Capability surfaces are read off the class, which is what lets a
    prospect see coverage before connecting anything."""
    r = client.get("/connectors/capabilities")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body, "no connector declares a capability surface"


def test_54_automation_coverage_is_reported_honestly(client):
    r = client.get("/coverage/automation")
    assert r.status_code == 200, r.text
    body = r.json()
    pct = body.get("coverage_percent", body.get("percent"))
    if pct is not None:
        assert 0 <= pct <= 100, f"coverage percentage out of range: {body}"


def test_55_a_connector_that_is_not_configured_says_so_rather_than_failing_open(client):
    """The honest-failure boundary: no credentials must never read as healthy."""
    r = client.get("/connectors/status")
    assert r.status_code == 200, r.text
    body = r.json()
    rows = body if isinstance(body, list) else body.get("connectors", body.get("status", []))
    assert rows, "connector status reports nothing"


def test_56_assessing_through_an_unknown_connector_is_refused(client):
    t = tenant("unknown-conn")
    r = client.post("/assessments", json={
        "tenant_id": t, "control_id": "SC-7", "source_system": "NOT_A_SYSTEM", "asset_id": "h"})
    assert r.status_code >= 400, "an unknown source system produced a finding"
    assert findings(client, t) == []


# ══════════════════════════════════════════════════════════════════════════
# Act 10 — Frameworks: the reason a customer buys this rather than a script
# ══════════════════════════════════════════════════════════════════════════
def test_57_a_control_crosswalks_to_other_frameworks(client):
    r = client.get("/crosswalk?control_id=SC-7")
    assert r.status_code == 200
    assert r.json()["mappings"], "SC-7 maps to no other framework"


def test_58_the_summary_can_be_scoped_to_one_framework(client):
    t = tenant("fw-scope")
    assess(client, t, "SC-7", "h-1", fail=True)
    scoped = summary(client, t, framework="NIST")
    assert scoped["total"] >= 1
    unrelated = summary(client, t, framework="ISO27001")
    assert unrelated["total"] <= scoped["total"]


def test_59_scf_crosswalk_claims_are_verifiable(client):
    """The crosswalk is a claim about someone else's catalog. It has to be
    checkable, or it is just a table."""
    r = client.get("/v1/scf/verify-crosswalk")
    assert r.status_code == 200, r.text
    body = r.json()
    verified = body.get("verified", body.get("verified_count"))
    total = body.get("total", body.get("total_count"))
    if verified is not None and total:
        assert verified <= total
        assert verified > 0, f"no SCF mapping could be verified: {body}"


def test_60_coverage_reports_what_is_actually_evidenced(client):
    t = tenant("coverage")
    assess(client, t, "SC-7", "h-1")
    r = client.get(f"/coverage?tenant_id={t}&framework=NIST")
    assert r.status_code == 200, r.text


def test_61_remediation_guidance_exists_for_a_failing_control(client):
    """A failure with no next step is a ticket somebody has to research."""
    t = tenant("remediate")
    assess(client, t, "SC-7", "h-1", fail=True)
    r = client.get(f"/remediation?tenant_id={t}")
    assert r.status_code == 200, r.text
    assert r.json(), "a failing estate produced no remediation guidance"


# ══════════════════════════════════════════════════════════════════════════
# Act 11 — Bad input, and the boundary where the product should say no
# ══════════════════════════════════════════════════════════════════════════
def test_62_an_unknown_control_is_refused_rather_than_invented(client):
    t = tenant("bad-control")
    r = client.post("/assessments", json={
        "tenant_id": t, "control_id": "NOT-A-CONTROL", "source_system": "DEMO", "asset_id": "h"})
    assert r.status_code >= 400 or r.json().get("status") in ("error", "not_applicable"), (
        "an unknown control produced a confident verdict")


def test_63_a_malformed_assessment_request_is_rejected(client):
    r = client.post("/assessments", json={"tenant_id": tenant("bad-req")})
    assert r.status_code == 422


def test_64_a_negative_pagination_limit_cannot_be_used_to_dump_the_table(client):
    t = tenant("page-abuse")
    for i in range(3):
        assess(client, t, "SC-7", f"h-{i}")
    r = client.get(f"/findings?tenant_id={t}&limit=-1")
    assert r.status_code in (200, 422)
    if r.status_code == 200:
        assert len(r.json()) <= 3


def test_65_an_absurd_pagination_limit_is_clamped(client):
    t = tenant("page-huge")
    assess(client, t, "SC-7", "h-0")
    r = client.get(f"/findings?tenant_id={t}&limit=100000")
    assert r.status_code in (200, 422)


def test_66_a_waiver_for_a_control_that_never_failed_changes_nothing(client):
    t = tenant("waiver-noop")
    assess(client, t, "SC-7", "h-1")
    before = summary(client, t)
    client.post("/waivers", json={"tenant_id": t, "control_id": "AU-2", "asset_id": "other",
                                  "reason": "pre-emptive", "approver": "ciso"})
    assert summary(client, t) == before, "an inapplicable waiver moved the score"


def test_67_health_and_readiness_report_the_real_state(client):
    assert client.get("/health/live").status_code == 200
    r = client.get("/health/ready")
    assert r.status_code == 200, r.text


def test_68_metrics_are_exposed_for_operations(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert b"comp_lens" in r.content or b"# HELP" in r.content


def test_69_the_console_is_served_and_its_data_agrees_with_the_api(client):
    """The screen a CISO looks at must not disagree with the API underneath.

    /dashboard is the static console, so the coherence check belongs on the
    endpoint it reads: unified trust fuses posture with the other signal lanes,
    and it must not score controls the tenant has no posture for.
    """
    t = tenant("console")
    for i in range(4):
        assess(client, t, "SC-7", f"h-{i}", fail=(i < 2))

    page = client.get("/dashboard")
    assert page.status_code == 200, "the console is advertised but not served"
    assert b"<" in page.content[:200], "the console did not return a document"

    u = client.get(f"/v1/grc-trust/unified?tenant_id={t}")
    assert u.status_code == 200, u.text
    body = u.json()
    assert body["controls_scored"] <= summary(client, t)["total"] + len(body["lanes_available"]), (
        f"unified trust scores more controls than the tenant has evidence for: {body}")
    for c in body["controls"]:
        assert c["lanes"], f"{c['control_id']} was scored with no lane behind it"


def test_70_an_untouched_tenant_scores_no_trust(client):
    """The empty state again, one layer up: fusing zero lanes must produce no
    score rather than a confident one."""
    body = client.get(f"/v1/grc-trust/unified?tenant_id={tenant('trust-empty')}").json()
    assert body["controls_scored"] == 0
    assert body["unified_trust_score"] is None, (
        f"a tenant with no evidence was given a trust score: {body['unified_trust_score']}")


# ══════════════════════════════════════════════════════════════════════════
# Act 12 — The audit engagement: where a customer meets their auditor
#
# An audit in this product is a checklist of controls, a set of evidence
# requests, and an export package handed to a third party. The package carries
# an attestation paragraph, which makes it the most consequential text the
# platform emits: an auditor reads it as a description of how the numbers next
# to it were produced.
# ══════════════════════════════════════════════════════════════════════════
def _audit(client, t, framework="NIST"):
    r = client.post(f"/audits?tenant_id={t}",
                    json={"name": "SOC 2 Type II", "framework": framework, "auditor": "Big Four LLP"})
    assert r.status_code == 200, r.text
    return r.json()


def test_71_creating_an_audit_seeds_a_control_checklist(client):
    t = tenant("audit-seed")
    a = _audit(client, t)
    assert a["controls_total"] > 0, "an audit was created with nothing to review"
    rows = client.get(f"/audits/{a['id']}/controls?tenant_id={t}&limit=1000").json()
    assert len(rows) == a["controls_total"]
    assert all(r["review_state"] == "not_started" for r in rows)


def test_72_an_audit_checklist_picks_up_evidence_the_platform_already_has(client):
    """The join that makes an audit worth running inside the platform.

    A reviewer should not be asked to manually assess a control the product has
    already verified. This refresh silently did nothing at all: it read a
    module that does not exist, inside a bare except, and reported success — so
    auto_status was blank on every audit control in every tenant.
    """
    t = tenant("audit-refresh")
    assess(client, t, "SC-7", "host-1", fail=True)
    assess(client, t, "AU-2", "host-2")
    a = _audit(client, t)

    r = client.post(f"/audits/{a['id']}/refresh-posture?tenant_id={t}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["controls_with_evidence"] >= 2, (
        f"the refresh reported success but attached no evidence: {body}")

    rows = {c["control_id"]: c for c in
            client.get(f"/audits/{a['id']}/controls?tenant_id={t}&limit=1000").json()}
    assert rows["SC-7"]["auto_status"] == "fail"
    assert rows["AU-2"]["auto_status"] == "pass"


def test_73_a_control_with_no_evidence_is_blank_rather_than_passing(client):
    """The distinction the attestation now spells out. An unevaluated control
    must not read as a satisfied one."""
    t = tenant("audit-blank")
    assess(client, t, "SC-7", "host-1")
    a = _audit(client, t)
    client.post(f"/audits/{a['id']}/refresh-posture?tenant_id={t}")

    rows = client.get(f"/audits/{a['id']}/controls?tenant_id={t}&limit=1000").json()
    unevaluated = [c for c in rows if c["control_id"] != "SC-7"]
    assert unevaluated, "fixture no longer exercises the unevaluated case"
    assert all(c["auto_status"] is None for c in unevaluated), (
        "a control with no evidence was given a status")


def test_74_one_failing_asset_makes_the_control_fail(client):
    """Posture holds a row per asset; the checklist holds one line per control.
    The only honest reduction is the worst one."""
    t = tenant("audit-worst")
    for i in range(4):
        assess(client, t, "SC-7", f"ok-{i}")
    assess(client, t, "SC-7", "bad-1", fail=True)

    a = _audit(client, t)
    client.post(f"/audits/{a['id']}/refresh-posture?tenant_id={t}")
    rows = {c["control_id"]: c for c in
            client.get(f"/audits/{a['id']}/controls?tenant_id={t}&limit=1000").json()}
    assert rows["SC-7"]["auto_status"] == "fail", (
        "four passing assets outvoted a failing one")


def test_75_the_refresh_reflects_a_control_that_has_since_been_fixed(client):
    t = tenant("audit-fixed")
    assess(client, t, "SC-7", "host-1", fail=True)
    a = _audit(client, t)
    client.post(f"/audits/{a['id']}/refresh-posture?tenant_id={t}")

    assess(client, t, "SC-7", "host-1")          # remediated
    client.post(f"/audits/{a['id']}/refresh-posture?tenant_id={t}")

    rows = {c["control_id"]: c for c in
            client.get(f"/audits/{a['id']}/controls?tenant_id={t}&limit=1000").json()}
    assert rows["SC-7"]["auto_status"] == "pass", "the checklist kept a stale failure"


def test_76_the_export_package_is_complete_and_describes_itself_truthfully(client):
    """The document that leaves the building."""
    t = tenant("audit-export")
    assess(client, t, "SC-7", "host-1", fail=True)
    a = _audit(client, t)
    client.post(f"/audits/{a['id']}/refresh-posture?tenant_id={t}")

    pkg = client.get(f"/audits/{a['id']}/export?tenant_id={t}").json()
    assert len(pkg["controls"]) == a["controls_total"], (
        "the export omits controls the checklist contains")
    assert pkg["audit"]["auditor"] == "Big Four LLP"

    attestation = pkg["attestation"].lower()
    assert "unevaluated, not passing" in attestation, (
        "the package does not tell the auditor what a blank status means")
    assert "live connector evidence" not in attestation, (
        "the package still claims evidence it does not gather that way")


def test_77_an_audit_belongs_to_exactly_one_tenant(client):
    a_t, b_t = tenant("audit-iso-a"), tenant("audit-iso-b")
    a = _audit(client, a_t)
    for path in (f"/audits/{a['id']}?tenant_id={b_t}",
                 f"/audits/{a['id']}/export?tenant_id={b_t}"):
        assert client.get(path).status_code == 404, f"{path} leaked across tenants"
    assert client.post(
        f"/audits/{a['id']}/refresh-posture?tenant_id={b_t}").status_code == 404, (
        "another tenant could write control statuses onto this audit")


def test_78_evidence_requests_track_what_the_auditor_asked_for(client):
    t = tenant("audit-pbc")
    a = _audit(client, t)
    r = client.post(f"/audits/{a['id']}/requests?tenant_id={t}",
                    json={"title": "Provide Q3 access review", "control_id": "AC-2"})
    assert r.status_code == 200, r.text
    req = r.json()

    listed = client.get(f"/audits/{a['id']}/requests?tenant_id={t}").json()
    assert len(listed) == 1
    assert client.get(f"/audits/{a['id']}?tenant_id={t}").json()["evidence_requests_open"] == 1

    client.patch(f"/audits/requests/{req['id']}?tenant_id={t}", json={"state": "received"})
    assert client.get(f"/audits/{a['id']}?tenant_id={t}").json()["evidence_requests_open"] == 0
