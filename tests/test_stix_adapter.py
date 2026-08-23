"""STIX adapter tests (stdlib unittest / pytest)."""
from __future__ import annotations

import json
import os
import unittest

from app.services import stix
from app.services.stix import (
    from_stix,
    indicator,
    stix_summary,
    to_stix_bundle,
    vulnerability,
)

_LEXICON = os.path.join(os.path.dirname(__file__), "..", "app", "data", "concept_lexicon.json")


def _bundle():
    return to_stix_bundle([
        vulnerability(name="Log4Shell", cve="CVE-2021-44228", description="RCE"),
        indicator(name="bad-ip", pattern="[ipv4-addr:value = '1.2.3.4']",
                  labels=["malicious-activity"]),
        {"type": "malware", "id": "malware--1", "name": "Emotet", "is_family": True},
        {"type": "relationship", "id": "relationship--1",  # context, not evidence
         "relationship_type": "indicates", "source_ref": "indicator--1",
         "target_ref": "malware--1"},
    ])


class Ingest(unittest.TestCase):
    def test_intel_objects_become_evidence_relationship_ignored(self):
        evs = from_stix(_bundle())
        types = sorted(e.findings[0]["stix_type"] for e in evs)
        self.assertEqual(types, ["indicator", "malware", "vulnerability"])

    def test_concept_mapping_by_type(self):
        by = {e.findings[0]["stix_type"]: e for e in from_stix(_bundle())}
        self.assertIn("vulnerability_management", by["vulnerability"].concepts)
        self.assertIn("malware_protection", by["malware"].concepts)
        self.assertIn("threat_intelligence", by["indicator"].concepts)

    def test_cve_and_severity(self):
        vuln = next(e for e in from_stix(_bundle())
                    if e.findings[0]["stix_type"] == "vulnerability")
        self.assertEqual(vuln.findings[0]["cve"], "CVE-2021-44228")
        ind = next(e for e in from_stix(_bundle())
                   if e.findings[0]["stix_type"] == "indicator")
        self.assertEqual(ind.severity, "high")  # malicious-activity label

    def test_non_dict_empty(self):
        self.assertEqual(from_stix("x"), [])


class Summary(unittest.TestCase):
    def test_counts_by_type(self):
        s = stix_summary(_bundle())
        self.assertEqual(s["threat_objects"], 3)
        self.assertEqual(s["vulnerabilities"], 1)
        self.assertEqual(s["indicators"], 1)
        self.assertEqual(s["malware"], 1)


class RoundTrip(unittest.TestCase):
    def test_emit_then_ingest(self):
        b = to_stix_bundle([vulnerability(name="X", cve="CVE-9")])
        evs = from_stix(b)
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].findings[0]["cve"], "CVE-9")
        self.assertEqual(b["type"], "bundle")


class LexiconIntegrity(unittest.TestCase):
    def test_concepts_real(self):
        with open(_LEXICON) as fh:
            ids = {c["id"] for c in json.load(fh)}
        mappable = {c for cs in stix._TYPE_CONCEPTS.values() for c in cs}
        self.assertEqual(mappable - ids, set(), f"unknown: {mappable - ids}")


if __name__ == "__main__":
    unittest.main()
