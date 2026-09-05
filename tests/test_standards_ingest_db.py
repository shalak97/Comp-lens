"""standards_ingest: DB persistence (needs SQLAlchemy — runs in CI via db_session).

Verifies that standard-format evidence actually lands as findings through the
proven record_external_finding sink, that OCSF control refs are crosswalked into
the canonical NIST namespace, and that ingestion is idempotent.
"""
from __future__ import annotations

from sqlalchemy import select


def _ingest(db, tenant, fmt, payload):
    from app.services.standards_ingest import StandardsIngestionService
    out = StandardsIngestionService(db).ingest(tenant, fmt, payload)
    db.commit()
    return out


def _findings(db, tenant):
    from app.models import Finding
    return db.execute(select(Finding).where(Finding.tenant_id == tenant)).scalars().all()


def test_ocsf_compliance_finding_persisted_and_crosswalked(db_session):
    from app.services.ocsf import to_ocsf_compliance_finding
    event = to_ocsf_compliance_finding(control_id="CC6.7", status="fail",
                                       framework="SOC2", severity="high")
    out = _ingest(db_session, "t_ocsf", "ocsf", event)
    assert out["ingested"] == 1

    rows = _findings(db_session, "t_ocsf")
    assert len(rows) == 1
    f = rows[0]
    assert f.control_id == "SC-28"          # CC6.7 (SOC2) crosswalked to NIST SC-28
    assert f.framework == "NIST_800_53"
    assert f.source_system == "COMP-LENS"   # emitted event's product
    assert f.status.value == "fail"


def test_cyclonedx_vuln_persisted_as_ra5(db_session):
    from app.services.cyclonedx import to_cyclonedx, vulnerability
    bom = to_cyclonedx(vulnerabilities=[
        vulnerability(vid="CVE-2023-1", severity="critical", affects_ref="pkg:pypi/x@1"),
        vulnerability(vid="CVE-2023-2", severity="high", affects_ref="pkg:pypi/y@2",
                      vex_state="not_affected"),  # VEX-suppressed -> not persisted
    ])
    out = _ingest(db_session, "t_cdx", "cyclonedx", bom)
    assert out["ingested"] == 1  # only the active vuln

    rows = _findings(db_session, "t_cdx")
    assert [r.control_id for r in rows] == ["RA-5"]
    assert rows[0].status.value == "fail"
    assert rows[0].severity.value == "critical"


def test_ingestion_is_idempotent(db_session):
    # A real vulnerability (carries the vulnerability_management concept, so it
    # persists as an RA-5 finding); re-ingesting the same doc must be a no-op.
    from app.services.cyclonedx import to_cyclonedx, vulnerability
    bom = to_cyclonedx(vulnerabilities=[
        vulnerability(vid="CVE-IDEM-1", severity="high", affects_ref="pkg:pypi/z@1")])
    first = _ingest(db_session, "t_idem", "cyclonedx", bom)
    second = _ingest(db_session, "t_idem", "cyclonedx", bom)
    assert first["ingested"] == 1
    assert second["ingested"] == 0 and second["skipped"] == 1
    assert len(_findings(db_session, "t_idem")) == 1


def test_sarif_security_finding_persisted_as_ra5(db_session):
    # A real code-scanning finding (CWE-tagged) carries vulnerability_management,
    # so it lands as an RA-5 finding with severity from its CVSS score.
    log = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "rules": [
        {"id": "py/sql-injection", "shortDescription": {"text": "SQL injection"},
         "properties": {"security-severity": "9.8", "tags": ["security", "cwe-89"]}}]}},
        "results": [{"ruleId": "py/sql-injection", "level": "error",
                     "message": {"text": "user input reaches a query"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": "app/db.py"}}}]}]}]}
    out = _ingest(db_session, "t_sarif", "sarif", log)
    assert out["ingested"] == 1
    rows = _findings(db_session, "t_sarif")
    assert rows[0].control_id == "RA-5"
    assert rows[0].severity.value == "critical"   # CVSS 9.8
    assert rows[0].source_system == "CODEQL"


def test_provenance_persists_as_pass_attestation(db_session):
    from app.services.intoto import SLSA_PROVENANCE_V1, dsse_encode, to_intoto_statement
    # Signed, because that is what makes it evidence rather than a claim the
    # payload makes about itself. This used to pass a bare statement and expect
    # a PASS finding, which is how an unsigned blob minted supply-chain
    # evidence attributed to whatever builder id it named.
    env = dsse_encode(to_intoto_statement(subject_name="pkg:app@1", sha256="a" * 64,
                                          predicate_type=SLSA_PROVENANCE_V1))
    env["signatures"] = [{"sig": "MEUCIQDx", "keyid": "k1"}]
    out = _ingest(db_session, "t_prov", "intoto", env)
    assert out["ingested"] == 1
    rows = _findings(db_session, "t_prov")
    assert rows[0].control_id == "SR-3"          # supply_chain_security attested
    assert rows[0].status.value == "pass"


def test_unsigned_provenance_persists_nothing(db_session):
    from app.services.intoto import SLSA_PROVENANCE_V1, to_intoto_statement
    stmt = to_intoto_statement(subject_name="pkg:app@2", sha256="b" * 64,
                               predicate_type=SLSA_PROVENANCE_V1)
    out = _ingest(db_session, "t_prov_unsigned", "intoto", stmt)
    assert out["ingested"] == 0
    assert _findings(db_session, "t_prov_unsigned") == []


def test_threat_context_is_observed_not_persisted(db_session):
    # A STIX indicator carries only threat_intelligence — context, not a verdict.
    from app.services.stix import indicator, to_stix_bundle
    bundle = to_stix_bundle([indicator(name="ip", pattern="[ipv4-addr:value='1.1.1.1']")])
    out = _ingest(db_session, "t_ctx", "stix", bundle)
    assert out["ingested"] == 0
    assert out["evidences"] == 1 and out["observed_only"] == 1
    assert _findings(db_session, "t_ctx") == []
