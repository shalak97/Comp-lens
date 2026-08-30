"""SCF-grounded crosswalk: lookup correctness and internal-crosswalk verification.

Pure-logic tests — app/services/scf_crosswalk.py and its data file
(app/data/scf_crosswalk.json) import only stdlib, so these run under plain
``python -m unittest`` as well as pytest, without a FastAPI/SQLAlchemy stack.

app/data/scf_crosswalk.json is extracted from the Secure Controls Framework's
published workbook (github.com/securecontrolsframework/securecontrolsframework)
via a one-off script, not hand-maintained here — these tests pin the module's
*behavior* against that data (bidirectional lookups, pair-level provenance,
exact-vs-base-control verification granularity) rather than the data's exact
contents, so a routine SCF version bump doesn't break them.
"""
from __future__ import annotations

import unittest

from app.services import scf_crosswalk as scf


class DataLoads(unittest.TestCase):
    def test_version_is_set(self):
        self.assertIsNotNone(scf.version())
        self.assertTrue(scf.version().startswith("scf-"))

    def test_some_controls_loaded(self):
        self.assertGreater(len(scf._load()["controls"]), 0)


class Lookups(unittest.TestCase):
    def test_sc28_links_to_known_iso_controls(self):
        # SC-28 (protection of information at rest) is linked by SCF to at
        # least these Annex A controls, via CRY-05 and END-02.
        iso = scf.iso_for_nist("SC-28")
        for expected in ("A.8.1", "A.8.24", "A.8.5"):
            self.assertIn(expected, iso)

    def test_lookup_is_bidirectional(self):
        # every (nist, iso) pair reachable forward must be reachable backward
        nist_to_iso, iso_to_nist, _ = scf._indices()
        for nist_id, iso_ids in nist_to_iso.items():
            for iso_id in iso_ids:
                self.assertIn(nist_id, iso_to_nist[iso_id],
                              f"{nist_id} -> {iso_id} not reachable in reverse")

    def test_unknown_control_returns_empty_not_error(self):
        self.assertEqual(scf.iso_for_nist("ZZ-999"), [])
        self.assertEqual(scf.nist_for_iso("A.99.99"), [])

    def test_scf_controls_linking_names_real_scf_ids(self):
        linking = scf.scf_controls_linking("SC-28", "A.8.24")
        self.assertIn("CRY-05", linking)


class VerifyLink(unittest.TestCase):
    def test_exact_match_reports_exact_granularity(self):
        result = scf.verify_link("SC-28", "A.8.24")
        self.assertTrue(result["verified"])
        self.assertEqual(result["granularity"], "exact")
        self.assertIn("CRY-05", result["scf_controls"])

    def test_enhancement_falls_back_to_base_control(self):
        # SC-28(1) itself may not appear verbatim in SCF's export, but its
        # base control SC-28 does — verify_link should still corroborate it
        # rather than reporting a spurious mismatch.
        result = scf.verify_link("SC-28(1)", "A.8.24")
        self.assertTrue(result["verified"])
        self.assertIn(result["granularity"], ("exact", "base_control"))

    def test_unrelated_pair_is_not_verified(self):
        result = scf.verify_link("AC-2", "A.99.99")
        self.assertFalse(result["verified"])
        self.assertIsNone(result["granularity"])
        self.assertEqual(result["scf_controls"], [])


class VerifyInternalCrosswalk(unittest.TestCase):
    def test_returns_well_formed_summary(self):
        summary = scf.verify_internal_crosswalk()
        self.assertEqual(summary["scf_version"], scf.version())
        self.assertEqual(
            summary["controls_checked"],
            summary["controls_verified"] + summary["controls_unverified"])
        self.assertEqual(len(summary["results"]), summary["controls_checked"])
        if summary["controls_checked"]:
            self.assertGreaterEqual(summary["verified_pct"], 0.0)
            self.assertLessEqual(summary["verified_pct"], 100.0)

    def test_sc28_control_is_verified(self):
        # AC-2-7/CM-3/etc. aside, SC-28 is one of the hand-written CROSSWALK
        # entries (app/frameworks.py) and is independently corroborated by
        # SCF (see Lookups.test_sc28_links_to_known_iso_controls above), so
        # it must show up verified whenever it's part of the checked set.
        summary = scf.verify_internal_crosswalk()
        by_id = {r["control_id"]: r for r in summary["results"]}
        if "SC-28" in by_id:
            self.assertTrue(by_id["SC-28"]["any_verified"])

    def test_every_result_has_both_refs(self):
        # verify_internal_crosswalk skips controls missing either side; every
        # entry it does return must carry at least one of each.
        summary = scf.verify_internal_crosswalk()
        for r in summary["results"]:
            self.assertTrue(r["nist_refs"])
            self.assertTrue(r["iso_refs"])
            self.assertEqual(len(r["pairs"]), len(r["nist_refs"]) * len(r["iso_refs"]))


if __name__ == "__main__":
    unittest.main()
