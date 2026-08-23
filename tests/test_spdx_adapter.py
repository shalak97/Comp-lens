"""SPDX adapter tests (stdlib unittest / pytest)."""
from __future__ import annotations

import json
import os
import unittest

from app.services import spdx
from app.services.spdx import from_spdx, package, spdx_summary, to_spdx

_LEXICON = os.path.join(os.path.dirname(__file__), "..", "app", "data", "concept_lexicon.json")


def _doc():
    return to_spdx(packages=[
        package(name="requests", version="2.0.0", license_concluded="Apache-2.0",
                advisories=["https://osv.dev/GHSA-x", "CVE-2023-0001"]),
        package(name="urllib3", version="1.0.0", license_concluded="MIT"),
        package(name="mystery", license_concluded="NOASSERTION"),
    ], creator="Syft")


class Ingest(unittest.TestCase):
    def test_only_packages_with_security_refs_become_findings(self):
        evs = from_spdx(_doc())
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].asset_id, "requests@2.0.0")
        self.assertEqual(evs[0].source_system, "SYFT")
        self.assertIn("CVE-2023-0001", evs[0].findings[0]["advisories"])
        self.assertIn("vulnerability_management", evs[0].concepts)

    def test_non_dict_empty(self):
        self.assertEqual(from_spdx("x"), [])


class Summary(unittest.TestCase):
    def test_inventory_and_licenses(self):
        s = spdx_summary(_doc())
        self.assertTrue(s["sbom_present"])
        self.assertEqual(s["package_count"], 3)
        self.assertEqual(s["packages_with_advisories"], 1)
        self.assertIn("Apache-2.0", s["licenses"])
        self.assertIn("MIT", s["licenses"])
        self.assertNotIn("NOASSERTION", s["licenses"])  # noise excluded
        self.assertEqual(s["license_count"], 2)

    def test_absent(self):
        self.assertEqual(spdx_summary(None), {"sbom_present": False})


class RoundTrip(unittest.TestCase):
    def test_emit_shape(self):
        d = to_spdx(packages=[package(name="x")])
        self.assertEqual(d["spdxVersion"], "SPDX-2.3")
        self.assertEqual(d["SPDXID"], "SPDXRef-DOCUMENT")
        self.assertEqual(d["creationInfo"]["creators"], ["Tool: Comp-Lens"])


class LexiconIntegrity(unittest.TestCase):
    def test_concepts_real(self):
        with open(_LEXICON) as fh:
            ids = {c["id"] for c in json.load(fh)}
        mappable = set(spdx._INVENTORY_CONCEPTS) | set(spdx._SECURITY_CONCEPTS)
        self.assertEqual(mappable - ids, set(), f"unknown: {mappable - ids}")


if __name__ == "__main__":
    unittest.main()
