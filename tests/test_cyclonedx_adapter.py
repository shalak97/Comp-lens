"""CycloneDX adapter: SBOM/VEX ingest, evidence-object bridge, round-trip.

Pure-logic tests (stdlib only) — run under pytest or ``python -m unittest``.
Fixtures mirror what Syft / Trivy / cdxgen emit (CycloneDX 1.6).
"""
from __future__ import annotations

import json
import os
import unittest

from app.grc_platforms.crosswalk import resolve
from app.services import cyclonedx as cdx
from app.services.cyclonedx import (
    component_evidence,
    from_cyclonedx,
    sbom_summary,
    to_cdx_evidence,
    to_cyclonedx,
    vulnerability,
)

_LEXICON = os.path.join(os.path.dirname(__file__), "..", "app", "data", "concept_lexicon.json")


def _bom():
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": "urn:uuid:abc", "version": 1,
        "metadata": {"tools": {"components": [{"name": "Syft"}]}},
        "components": [
            {"bom-ref": "pkg:pypi/requests@2.0.0", "name": "requests", "version": "2.0.0",
             "licenses": [{"license": {"id": "Apache-2.0"}}],
             "evidence": {"identity": [{"field": "purl", "confidence": 0.9,
                          "methods": [{"technique": "manifest-analysis", "confidence": 0.9}]}]}},
            {"bom-ref": "pkg:pypi/urllib3@1.0.0", "name": "urllib3", "version": "1.0.0",
             "licenses": [{"license": {"id": "MIT"}}]},
        ],
        "vulnerabilities": [
            {"id": "CVE-2023-0001", "source": {"name": "NVD"},
             "ratings": [{"severity": "critical", "score": 9.8, "method": "CVSSv31"}],
             "affects": [{"ref": "pkg:pypi/requests@2.0.0"}],
             "recommendation": "Upgrade to 2.31.0"},
            {"id": "CVE-2023-0002",
             "ratings": [{"severity": "high", "score": 7.5, "method": "CVSSv31"}],
             "affects": [{"ref": "pkg:pypi/urllib3@1.0.0"}],
             "analysis": {"state": "not_affected", "justification": "code_not_reachable"}},
        ],
    }


class Ingest(unittest.TestCase):
    def test_vex_suppressed_vuln_excluded(self):
        evs = from_cyclonedx(_bom())
        ids = [e.findings[0]["id"] for e in evs]
        self.assertIn("CVE-2023-0001", ids)
        self.assertNotIn("CVE-2023-0002", ids)  # not_affected -> suppressed

    def test_severity_and_asset(self):
        ev = from_cyclonedx(_bom())[0]
        self.assertEqual(ev.severity, "critical")
        self.assertEqual(ev.asset_id, "pkg:pypi/requests@2.0.0")
        self.assertEqual(ev.source_system, "SYFT")
        self.assertEqual(ev.findings[0]["cvss_method"], "CVSSv31")

    def test_fix_available_adds_patch_concept(self):
        ev = from_cyclonedx(_bom())[0]  # has a recommendation
        self.assertIn("vulnerability_management", ev.concepts)
        self.assertIn("patch_management", ev.concepts)

    def test_severity_from_score_when_word_missing(self):
        bom = {"vulnerabilities": [{"id": "X",
               "ratings": [{"score": 8.1, "method": "CVSSv31"}]}]}
        self.assertEqual(from_cyclonedx(bom)[0].severity, "high")

    def test_highest_rating_wins(self):
        bom = {"vulnerabilities": [{"id": "X", "ratings": [
            {"severity": "low"}, {"severity": "critical"}, {"severity": "medium"}]}]}
        self.assertEqual(from_cyclonedx(bom)[0].severity, "critical")

    def test_non_dict_empty(self):
        self.assertEqual(from_cyclonedx("nope"), [])


class SbomSummary(unittest.TestCase):
    def test_summary_counts_and_policy_field(self):
        s = sbom_summary(_bom())
        self.assertTrue(s["sbom_present"])
        self.assertEqual(s["component_count"], 2)
        self.assertEqual(s["critical_vulnerabilities"], 1)   # RA-5 field; VEX-suppressed excluded
        self.assertEqual(s["total_vulnerabilities"], 1)      # only the active one
        self.assertEqual(s["vulnerable_components"], 1)
        self.assertIn("Apache-2.0", s["licenses"])
        self.assertEqual(s["license_count"], 2)

    def test_summary_absent(self):
        self.assertEqual(sbom_summary("x"), {"sbom_present": False})


class ComponentEvidence(unittest.TestCase):
    def test_reads_identity_confidence_and_technique(self):
        ce = component_evidence(_bom())
        self.assertEqual(len(ce), 1)   # only one component carries evidence
        self.assertEqual(ce[0]["field"], "purl")
        self.assertEqual(ce[0]["confidence"], 0.9)
        self.assertEqual(ce[0]["techniques"], ["manifest-analysis"])


class EvidenceBridge(unittest.TestCase):
    """The headline: express an internal confidence as a CycloneDX evidence
    object with a NAMED identification technique — the primitive the crosswalk
    confidence has lacked."""

    def test_build_evidence_object(self):
        obj = to_cdx_evidence(field="control-mapping", confidence=0.7,
                              technique="attestation", value="SOC2:CC6.1->AC-2")
        idn = obj["identity"]
        self.assertEqual(idn["field"], "control-mapping")
        self.assertEqual(idn["confidence"], 0.7)
        self.assertEqual(idn["methods"][0]["technique"], "attestation")
        self.assertEqual(idn["methods"][0]["value"], "SOC2:CC6.1->AC-2")

    def test_unknown_technique_falls_back_to_other(self):
        obj = to_cdx_evidence(field="x", confidence=2.0, technique="made-up")
        self.assertEqual(obj["identity"]["methods"][0]["technique"], "other")
        self.assertEqual(obj["identity"]["confidence"], 1.0)  # clamped

    def test_bridges_a_real_crosswalk_confidence(self):
        m = resolve("SOC2", "CC6.1")               # confidence 0.95, exact/equivalent
        obj = to_cdx_evidence(field="control-mapping", confidence=m.confidence,
                              technique="manifest-analysis")
        self.assertEqual(obj["identity"]["confidence"], 0.95)
        self.assertEqual(component_evidence(to_cyclonedx(components=[
            {"bom-ref": "x", "evidence": obj}]))[0]["confidence"], 0.95)


class RoundTrip(unittest.TestCase):
    def test_emit_then_ingest_recovers_vuln(self):
        bom = to_cyclonedx(vulnerabilities=[
            vulnerability(vid="CVE-9", severity="critical", affects_ref="pkg:x",
                          description="boom")])
        evs = from_cyclonedx(bom)
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].findings[0]["id"], "CVE-9")
        self.assertEqual(evs[0].severity, "critical")
        self.assertEqual(evs[0].asset_id, "pkg:x")
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.6")

    def test_emitted_vex_suppressed_roundtrips_to_nothing(self):
        bom = to_cyclonedx(vulnerabilities=[
            vulnerability(vid="CVE-8", severity="high", vex_state="false_positive")])
        self.assertEqual(from_cyclonedx(bom), [])


class LexiconIntegrity(unittest.TestCase):
    def test_all_mappable_concepts_are_real(self):
        with open(_LEXICON) as fh:
            ids = {c["id"] for c in json.load(fh)}
        mappable = set(cdx._VULN_CONCEPTS) | {"patch_management"}
        self.assertEqual(mappable - ids, set(), f"unknown concept ids: {mappable - ids}")


if __name__ == "__main__":
    unittest.main()
