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

    def test_denominator_reconciles(self):
        # The load-bearing invariant: nothing may drop out of the report
        # unannounced. Every control in the crosswalk is either checked or
        # explicitly skipped with a reason — never silently absent, which
        # would shrink the denominator and inflate verified_pct.
        summary = scf.verify_internal_crosswalk()
        self.assertEqual(
            summary["controls_checked"] + summary["controls_skipped"],
            summary["controls_in_crosswalk"],
            "checked + skipped must account for every control in the crosswalk")
        self.assertEqual(len(summary["skipped"]), summary["controls_skipped"])

    def test_every_skipped_control_carries_a_reason(self):
        for entry in scf.verify_internal_crosswalk()["skipped"]:
            self.assertTrue(entry["control_id"])
            self.assertIn("reference", entry["reason"])

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


class DegradedRunsAnnounceThemselves(unittest.TestCase):
    """A verification report that quietly narrows its own scope and then
    returns a *better* percentage is worse than no report — it's a false
    assurance in a product whose whole job is not making those. Both ways the
    scope can silently shrink must show up in the payload.
    """

    def _without_reference_data(self):
        """Point the loader at a missing file, restoring state afterwards."""
        from pathlib import Path
        original = scf._PATH
        scf._PATH = Path("/nonexistent/scf_crosswalk.json")
        scf._load.cache_clear()
        scf._indices.cache_clear()

        def restore():
            scf._PATH = original
            scf._load.cache_clear()
            scf._indices.cache_clear()

        self.addCleanup(restore)

    def test_missing_reference_data_is_distinguishable_from_a_wrong_crosswalk(self):
        # Without this signal, an absent scf_crosswalk.json makes every link
        # fail and the report reads "0% verified" — accusing the crosswalk of
        # being wrong when nothing was ever checked against it.
        self._without_reference_data()
        summary = scf.verify_internal_crosswalk()
        self.assertFalse(summary["reference_data"]["loaded"])
        self.assertEqual(summary["reference_data"]["scf_controls"], 0)
        self.assertFalse(summary["scope_complete"],
                         "a run with no reference data must not look complete")

    def test_scope_complete_requires_both_reference_data_and_check_pack(self):
        summary = scf.verify_internal_crosswalk()
        self.assertEqual(
            summary["scope_complete"],
            summary["reference_data"]["loaded"] and summary["declarative_pack"]["loaded"])

    def test_declarative_pack_failure_is_reported_with_a_cause(self):
        # app.frameworks merges the declarative check pack inside a bare
        # `except Exception: return`, so a failure there is invisible: the
        # crosswalk silently shrinks to the hand-written entries. When that
        # happens the report must say so, and say why.
        pack = scf.verify_internal_crosswalk()["declarative_pack"]
        if pack["loaded"]:
            self.assertIsNone(pack["error"])
            self.assertGreater(pack["checks_with_crosswalk"], 0)
        else:
            self.assertTrue(pack["error"], "a failed pack load must name its cause")


if __name__ == "__main__":
    unittest.main()
