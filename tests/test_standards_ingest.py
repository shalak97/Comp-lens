"""standards_ingest: pure dispatch + planning logic (no DB).

These exercise normalize() and plan_findings() — the decision logic — without a
database, so they run under `python -m unittest` or pytest. DB persistence is
covered separately in test_standards_ingest_db.py (needs SQLAlchemy).
"""
from __future__ import annotations

import unittest

from app.services import cyclonedx, ocsf, stix
from app.services.intoto import SLSA_PROVENANCE_V1, to_intoto_statement
from app.services.standards_ingest import (
    SUPPORTED_FORMATS,
    UnsupportedFormat,
    _concept_nist_control,
    normalize,
    plan_findings,
)


class Dispatch(unittest.TestCase):
    def test_all_seven_formats_supported(self):
        self.assertEqual(SUPPORTED_FORMATS,
                         ["cyclonedx", "intoto", "ocsf", "sarif", "sigstore", "spdx", "stix"])

    def test_unknown_format_raises(self):
        with self.assertRaises(UnsupportedFormat):
            normalize("dogecoin", {})

    def test_normalize_ocsf_single(self):
        ev = ocsf.to_ocsf_compliance_finding(control_id="CC6.7", status="fail",
                                             framework="SOC2", severity="high")
        out = normalize("ocsf", ev)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].controls[0]["control_ref"], "CC6.7")


class Planning(unittest.TestCase):
    def test_concept_maps_to_nist_control(self):
        self.assertEqual(_concept_nist_control().get("vulnerability_management"), "RA-5")

    def test_ocsf_verdict_crosswalked_into_nist(self):
        ev = ocsf.to_ocsf_compliance_finding(control_id="CC6.7", status="fail",
                                             framework="SOC2", severity="high")
        plans = plan_findings(normalize("ocsf", ev))
        self.assertEqual(len(plans), 1)
        p = plans[0]
        self.assertEqual(p.framework, "NIST_800_53")
        self.assertEqual(p.control_id, "SC-28")          # CC6.7 -> SC-28 via STRM crosswalk
        self.assertEqual(p.status, "fail")
        self.assertEqual(p.raw["source_control_ref"], "CC6.7")
        self.assertIn("crosswalk_confidence", p.raw)

    def test_ocsf_unknown_ref_falls_back_to_standard(self):
        ev = ocsf.to_ocsf_compliance_finding(control_id="ZZ9.9", status="pass",
                                             framework="SOC2")
        p = plan_findings(normalize("ocsf", ev))[0]
        self.assertEqual(p.control_id, "ZZ9.9")
        self.assertEqual(p.framework, "SOC2")
        self.assertEqual(p.status, "pass")

    def test_cyclonedx_vuln_becomes_ra5_fail(self):
        bom = cyclonedx.to_cyclonedx(vulnerabilities=[
            cyclonedx.vulnerability(vid="CVE-2023-1", severity="critical", affects_ref="pkg:x")])
        plans = plan_findings(normalize("cyclonedx", bom))
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0].control_id, "RA-5")
        self.assertEqual(plans[0].status, "fail")
        self.assertEqual(plans[0].severity, "critical")
        self.assertEqual(plans[0].external_id, "COMP-LENS:CVE-2023-1")  # emitted BOM's tool name

    def test_stix_vulnerability_planned_indicator_not(self):
        bundle = stix.to_stix_bundle([
            stix.vulnerability(name="X", cve="CVE-9"),
            stix.indicator(name="ip", pattern="[ipv4-addr:value='1.1.1.1']"),
        ])
        plans = plan_findings(normalize("stix", bundle))
        # only the vulnerability object carries the vulnerability_management concept
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0].control_id, "RA-5")

    def test_provenance_and_signatures_are_observed_only(self):
        stmt = to_intoto_statement(subject_name="pkg:app@1", sha256="a" * 64,
                                   predicate_type=SLSA_PROVENANCE_V1)
        self.assertEqual(plan_findings(normalize("intoto", stmt)), [])

    def test_distinct_findings_do_not_collide_on_external_id(self):
        # Two different STIX vulnerabilities that share a name but differ by CVE
        # must produce distinct external ids (else the second is silently dropped).
        bundle = stix.to_stix_bundle([
            stix.vulnerability(name="SAME", cve="CVE-1"),
            stix.vulnerability(name="SAME", cve="CVE-2"),
        ])
        ids = {p.external_id for p in plan_findings(normalize("stix", bundle))}
        self.assertEqual(len(ids), 2, f"distinct vulns collided: {ids}")

    def test_same_sarif_rule_different_location_stays_distinct(self):
        log = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep", "rules": [
            {"id": "py/x", "properties": {"security-severity": "8.0", "tags": ["cwe"]}}]}},
            "results": [
                {"ruleId": "py/x", "level": "error", "message": {"text": "a"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                                                     "region": {"startLine": 1}}}]},
                {"ruleId": "py/x", "level": "error", "message": {"text": "b"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "b.py"},
                                                     "region": {"startLine": 2}}}]},
            ]}]}
        ids = {p.external_id for p in plan_findings(normalize("sarif", log))}
        self.assertEqual(len(ids), 2, f"same-rule findings collided: {ids}")

    def test_observed_only_counts_evidences_without_findings(self):
        # one persisted vuln + one observed-only indicator -> observed_only == 1,
        # robust even though both flatten through the same planner.
        bundle = stix.to_stix_bundle([
            stix.vulnerability(name="V", cve="CVE-9"),
            stix.indicator(name="i", pattern="[ipv4-addr:value='1.1.1.1']"),
        ])
        from app.services.standards_ingest import _yields_finding
        evs = normalize("stix", bundle)
        self.assertEqual(sum(1 for e in evs if not _yields_finding(e)), 1)

    def test_dedup_external_ids_are_stable(self):
        bom = cyclonedx.to_cyclonedx(vulnerabilities=[
            cyclonedx.vulnerability(vid="CVE-1", severity="high", affects_ref="pkg:a")])
        a = plan_findings(normalize("cyclonedx", bom))[0].external_id
        b = plan_findings(normalize("cyclonedx", bom))[0].external_id
        self.assertEqual(a, b)  # same input -> same idempotency key


if __name__ == "__main__":
    unittest.main()
