"""Integration coherence: the joins between subsystems, not the subsystems.

Every component of Comp-Lens worked in isolation while the seams between them
did not, because the platform names controls twice — internally (`AC-2-7`,
`IA-2-ROOT-MFA`) and canonically (`AC-2(7)`, `IA-2(1)`) — and names frameworks
twice (`NIST` vs `NIST_800_53`). The crosswalk that translates between them was
correct and simply not applied at the join points, so:

  * the catalogue marked 5 of 45 genuinely-covered NIST controls automated,
    and 0 of 93 ISO controls;
  * the audit-readiness number counted findings for 5 of 56 automated controls;
  * /coverage?framework=NIST returned an empty report rather than failing.

These tests pin the joins, not the parts.
"""
from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_integ.db")
os.environ.setdefault("EVIDENCE_LOCAL_PATH", "./test_integ_evidence")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import init_db  # noqa: E402


@pytest.fixture(scope="module")
def client():
    init_db()
    from app.main import app
    with TestClient(app) as c:
        yield c


# ──────────────────────────────────────────────────────────────────────────
# The internal <-> canonical pivot
# ──────────────────────────────────────────────────────────────────────────
def test_framework_names_resolve_across_both_vocabularies():
    from app.services.control_identity import ISO, NIST, normalize_framework

    for name in ("NIST", "nist", "NIST_800_53", "nist-800-53", "800-53"):
        assert normalize_framework(name) == NIST, name
    for name in ("ISO27001", "ISO_27001_2022", "iso 27001", "iso-27001"):
        assert normalize_framework(name) == ISO, name
    # frameworks that are crosswalk targets only have no catalogue
    assert normalize_framework("SOC2") is None
    assert normalize_framework(None) is None


def test_enhancement_refs_resolve_to_the_catalogue():
    """A crosswalk pointing at AC-6(5) must reach the catalogue's AC-6(5)."""
    from app.services.control_identity import NIST, canonical_ids_for

    covered = canonical_ids_for("IA-2-ROOT-MFA", NIST)
    assert "IA-2(1)" in covered
    assert "AC-6(5)" in covered


def test_catalogue_automation_flag_uses_the_crosswalk():
    """Marking automation by string-matching internal ids against catalogue ids
    under-reported the product's own coverage roughly ninefold."""
    from app.services import framework_catalog as catalog

    nist = catalog.controls("NIST_800_53")
    automated = [c for c in nist if c["automated"]]
    assert len(nist) == 1196
    assert len(automated) >= 40, (
        f"only {len(automated)} NIST controls marked automated; the crosswalk "
        "join is not being applied")

    # controls reached only through the crosswalk, never by id equality
    ids = {c["id"] for c in automated}
    assert "IA-2(1)" in ids        # via IA-2-ROOT-MFA
    assert "AC-2(7)" in ids        # via AC-2-7
    assert "SC-12" in ids          # via SC-12-KMS-ROTATION


def test_iso_controls_are_annotated_too():
    """ISO showed 0 of 93 automated despite every check carrying ISO mappings."""
    from app.services import framework_catalog as catalog

    iso = catalog.controls("ISO_27001_2022")
    automated = [c for c in iso if c["automated"]]
    assert len(automated) > 0, "no ISO 27001 control is marked automated"
    assert "A.8.24" in {c["id"] for c in automated}   # via SC-28-OBJSTORE-KMS


def test_catalogue_accepts_the_name_the_rest_of_the_api_uses():
    from app.services import framework_catalog as catalog

    assert len(catalog.controls("NIST")) == len(catalog.controls("NIST_800_53")) == 1196
    assert len(catalog.controls("ISO27001")) == len(catalog.controls("ISO_27001_2022")) == 93


# ──────────────────────────────────────────────────────────────────────────
# Audit readiness — the number the product leads with
# ──────────────────────────────────────────────────────────────────────────
def test_audit_readiness_counts_declarative_findings(client):
    """A finding written against an internal id must count toward the canonical
    control it evidences. Previously 51 of 56 automated controls' findings were
    silently dropped from this number."""
    r = client.post("/assessments", json={
        "tenant_id": "cov-1", "framework": "NIST", "control_id": "IA-2-ROOT-MFA",
        "source_system": "DEMO", "asset_id": "acct-1"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "pass"

    cov = client.get("/coverage?framework=NIST&tenant_id=cov-1")
    assert cov.status_code == 200, cov.text
    body = cov.json()
    assert body["total"] == 1196, "the NIST catalogue did not resolve"
    assert body["assessed"] >= 1, (
        "a passing assessment of IA-2-ROOT-MFA did not register against any "
        "NIST control — the internal->canonical join is missing")
    assert body["compliant"] >= 1


def test_coverage_accepts_the_short_framework_name(client):
    """/coverage?framework=NIST used to return an empty catalogue silently."""
    a = client.get("/coverage?framework=NIST&tenant_id=cov-2").json()
    b = client.get("/coverage?framework=NIST_800_53&tenant_id=cov-2").json()
    assert a["total"] == b["total"] == 1196
    assert a["automated_controls"] == b["automated_controls"] > 0


# ──────────────────────────────────────────────────────────────────────────
# The declarative controls must be reachable end to end
# ──────────────────────────────────────────────────────────────────────────
def test_every_declarative_control_is_demoable():
    """The DEMO connector backs the dashboard's whole demo mode. If it cannot
    serve the declarative controls, the product demonstrates a fraction of the
    coverage it advertises."""
    from app.connectors.mock import MockConnector
    from app.services import control_checks

    surface = MockConnector.surface()
    unsatisfiable = [
        cid for cid, c in control_checks.all_checks().items()
        if surface.resolve(c.asset_type, c.requires) is None
    ]
    assert not unsatisfiable, f"DEMO cannot serve: {unsatisfiable}"


def test_demo_serves_both_a_compliant_and_a_failing_estate():
    from app.connectors.mock import MockConnector
    from app.models import ControlStatus
    from app.services import control_checks

    conn = MockConnector()
    for cid, check in control_checks.all_checks().items():
        clean = conn.collect_telemetry(cid, "demo-asset", {})
        assert control_checks.evaluate(check, clean)[0] is ControlStatus.PASS, cid
        broken = conn.collect_telemetry(cid, "demo-asset", {"fail": True})
        assert control_checks.evaluate(check, broken)[0] is ControlStatus.FAIL, cid


def test_legacy_demo_controls_are_unchanged():
    """The hand-written controls must keep their original synthetic telemetry."""
    from app.connectors.mock import MockConnector

    conn = MockConnector()
    assert conn.collect_telemetry("SC-28", "a", {})["encryption_at_rest"] is True
    assert conn.collect_telemetry("SC-28", "a", {"fail": True})["encryption_at_rest"] is False
    assert conn.collect_telemetry("AC-2-3", "a", {"fail": True})["days_since_last_login"] == 120


def test_declarative_control_assessed_through_the_api(client):
    r = client.post("/assessments", json={
        "tenant_id": "decl-1", "framework": "NIST", "control_id": "SC-7-ADMIN-SSH",
        "source_system": "DEMO", "asset_id": "sg-1", "params": {"fail": True}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "fail"
    assert body["severity"] == "critical"
    assert body["evidence_ids"], "no evidence was captured for a declarative control"


# ──────────────────────────────────────────────────────────────────────────
# Discovery and bulk assessment must agree on asset types
# ──────────────────────────────────────────────────────────────────────────
def test_every_probe_asset_type_has_discovery():
    """A probe with no discovery path is a control nobody can enumerate targets
    for — 'continuous monitoring' that monitors nothing."""
    import inspect
    import re

    from app.connectors.aws import AWSConnector

    declared = {p.asset_type for p in AWSConnector.PROBES}
    src = inspect.getsource(AWSConnector.discover_assets)
    discovered = set(re.findall(r'asset_type="([a-z_]+)"', src))
    assert declared <= discovered, f"no discovery for: {sorted(declared - discovered)}"


def test_bulk_assess_only_targets_the_right_asset_type(client):
    """Bulk-assessing an object-storage control must not run it against IAM
    users just because they share a source system."""
    d = client.post("/inventory/discover?source_system=DEMO&tenant_id=bulk-1")
    assert d.status_code == 200, d.text
    assert d.json()["discovered_new"] > 1

    r = client.post("/assessments/bulk", json={
        "tenant_id": "bulk-1", "framework": "NIST",
        "control_id": "SC-28-OBJSTORE-KMS", "source_system": "DEMO", "params": {}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["asset_type"] == "object_storage"
    assert body["eligible_assets"] == 1, (
        f"expected only object_storage assets, got {body['eligible_assets']}")
    assert body["failed"] == 0, "an eligible asset failed assessment"
    assert body["assessed"] == 1


def test_bulk_assess_keeps_legacy_behaviour_for_handwritten_controls(client):
    """Hand-written controls declare no asset type and must still fan out."""
    client.post("/inventory/discover?source_system=DEMO&tenant_id=bulk-2")
    r = client.post("/assessments/bulk", json={
        "tenant_id": "bulk-2", "framework": "NIST", "control_id": "SC-28",
        "source_system": "DEMO", "params": {}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["asset_type"] is None
    assert body["eligible_assets"] > 1


# ──────────────────────────────────────────────────────────────────────────
# The coverage metric is reachable from the product, not just the API
# ──────────────────────────────────────────────────────────────────────────
def test_automation_coverage_endpoint_reports_full_coverage(client):
    from app.services import control_checks

    body = client.get("/coverage/automation").json()
    # Derived from the pack rather than hard-coded: the count is a fact about
    # the check pack, and pinning it as a literal meant every added control
    # broke this test for no reason while telling us nothing about coverage.
    assert body["total_checks"] == len(control_checks.all_checks())
    assert body["uncovered"] == 0, f"unsatisfiable controls: {body['uncovered']}"
    assert body["coverage_pct"] == 100.0


def test_connector_capabilities_endpoint_lists_demo_and_aws(client):
    from app.connectors.registry import registry
    from app.services import control_checks

    body = client.get("/connectors/capabilities").json()
    names = {c["source_system"] for c in body["connectors"]}
    assert {"AWS", "DEMO"} <= names

    counts = {c["source_system"]: c["controls_satisfied_count"] for c in body["connectors"]}

    # DEMO must satisfy everything: it is what demo mode runs on, so any check
    # it cannot serve is coverage the product advertises but cannot show.
    assert counts["DEMO"] == body["total_checks"]

    # AWS is held to the asset types it actually claims. The pack now also
    # covers hosts, code repositories and log indexes — asset types owned by
    # the scanning and SIEM connectors, not by a cloud — and requiring AWS to
    # answer for a Splunk index would assert something false rather than
    # protect anything.
    aws = registry.surface("AWS")
    aws_scope = [c for c in control_checks.all_checks().values()
                 if aws.for_asset_type(c.asset_type)]
    assert counts["AWS"] == len(aws_scope), (
        "AWS does not cover every check for an asset type it declares a probe for")


def test_dashboard_exposes_the_automation_view():
    """The coverage metric was API-only; the product's own UI never showed it."""
    from pathlib import Path

    html = Path("app/static/dashboard.html").read_text()
    assert "RENDER.automation" in html
    assert '["automation","Automation Coverage"]' in html
    assert "/coverage/automation" in html
    assert "/connectors/capabilities" in html
