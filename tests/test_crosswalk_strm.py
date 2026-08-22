"""STRM-typed crosswalk: relationship type, first-class confidence, backward-compat.

Pure-logic tests — no FastAPI/SQLAlchemy/DB — so they run under either pytest or
plain ``python -m unittest`` (the crosswalk module imports only stdlib).

The load-bearing guarantee here is that adding relationship types and a
``confidence`` property changed *no* existing number: for every mapping that keeps
the default relationship for its quality, ``confidence`` must equal the legacy
``QUALITY_CONFIDENCE[quality]`` exactly, so no downstream trust score moves.
"""
from __future__ import annotations

import unittest

from app.grc_platforms import crosswalk as xw
from app.grc_platforms.crosswalk import Mapping, RelationshipType


class BackwardCompatibility(unittest.TestCase):
    def test_legacy_quality_table_unchanged(self):
        self.assertEqual(xw.QUALITY_CONFIDENCE,
                         {"exact": 0.95, "partial": 0.7, "heuristic": 0.5})

    def test_positional_construction_still_works(self):
        # The old three-arg positional form must still build a valid Mapping.
        m = Mapping("AC-2", "exact", "logical access provisioning")
        self.assertEqual(m.control_id, "AC-2")
        self.assertEqual(m.quality, "exact")
        self.assertEqual(m.note, "logical access provisioning")

    def test_confidence_matches_legacy_for_every_registered_edge(self):
        # Every edge shipped in the registry must keep its legacy confidence,
        # i.e. confidence == QUALITY_CONFIDENCE[quality]. This is the no-regression
        # contract for the trust telemetry that consumes these mappings.
        for fw, table in xw.CROSSWALKS.items():
            for ref, m in table.items():
                legacy = xw.QUALITY_CONFIDENCE[m.quality]
                self.assertEqual(
                    m.confidence, legacy,
                    f"{fw}:{ref} confidence {m.confidence} != legacy {legacy}")


class RelationshipTyping(unittest.TestCase):
    def test_default_relationship_derived_from_quality(self):
        self.assertEqual(Mapping("AC-2", "exact").relationship,
                         RelationshipType.EQUIVALENT)
        self.assertEqual(Mapping("AC-2", "partial").relationship,
                         RelationshipType.INTERSECTS)
        self.assertEqual(Mapping("AC-2", "heuristic").relationship,
                         RelationshipType.INTERSECTS)

    def test_explicit_relationship_accepts_enum_or_string(self):
        self.assertEqual(Mapping("AC-2", "partial", relationship="subset").relationship,
                         RelationshipType.SUBSET)
        self.assertEqual(
            Mapping("AC-2", "partial", relationship=RelationshipType.SUPERSET).relationship,
            RelationshipType.SUPERSET)

    def test_cis_edges_marked_superset(self):
        # CIS safeguards are coarser than the NIST control they map to.
        for ref, m in xw.CROSSWALKS["CIS"].items():
            self.assertEqual(m.relationship, RelationshipType.SUPERSET,
                             f"CIS:{ref} should be SUPERSET")

    def test_not_related_is_zero_confidence(self):
        m = Mapping("AC-2", "exact", relationship=RelationshipType.NOT_RELATED)
        self.assertEqual(m.confidence, 0.0)


class ConfidenceSemantics(unittest.TestCase):
    def test_strength_override_wins_and_clamps(self):
        self.assertEqual(Mapping("AC-2", "exact", strength=0.42).confidence, 0.42)
        self.assertEqual(Mapping("AC-2", "exact", strength=5).confidence, 1.0)
        self.assertEqual(Mapping("AC-2", "exact", strength=-1).confidence, 0.0)

    def test_narrower_relationship_can_only_lower(self):
        base = Mapping("AC-2", "exact").confidence           # equivalent -> 0.95
        narrower = Mapping("AC-2", "exact", relationship="superset").confidence
        self.assertLessEqual(narrower, base)
        self.assertEqual(narrower, 0.75)  # capped by SUPERSET ceiling

    def test_confidence_within_unit_interval(self):
        for table in xw.CROSSWALKS.values():
            for m in table.values():
                self.assertGreaterEqual(m.confidence, 0.0)
                self.assertLessEqual(m.confidence, 1.0)

    def test_compose_is_multiplicative_proxy(self):
        self.assertEqual(xw.compose(0.7, 0.6), 0.42)
        self.assertEqual(xw.compose(1.0, 0.9), 0.9)
        # composing weakens: the chain is never stronger than its weakest link
        self.assertLessEqual(xw.compose(0.8, 0.5), min(0.8, 0.5))


class ResolveBehaviour(unittest.TestCase):
    def test_declared_framework_resolves_directly(self):
        m, fw = xw.resolve_best("CC6.1", ["SOC2"])
        self.assertEqual(m.control_id, "AC-2")
        self.assertEqual(fw, "SOC2")
        self.assertEqual(m.confidence, 0.95)

    def test_inferred_framework_is_downgraded(self):
        # Ref exists in SOC2 but the profile declared the wrong/empty framework:
        # it still resolves, but downgraded to heuristic/intersects (lower confidence).
        m, fw = xw.resolve_best("CC6.1", None)
        self.assertIsNotNone(m)
        self.assertEqual(m.quality, "heuristic")
        self.assertEqual(m.relationship, RelationshipType.INTERSECTS)
        self.assertLess(m.confidence, 0.95)

    def test_unknown_ref_resolves_to_nothing(self):
        m, fw = xw.resolve_best("ZZ9.9", ["SOC2"])
        self.assertIsNone(m)
        self.assertIsNone(fw)

    def test_register_crosswalk_with_meta(self):
        xw.register_crosswalk(
            "PCIDSS",
            {"1.1": Mapping("SC-7", "partial", "network segmentation")},
            meta={"source": "PCI DSS v4.0 ↔ NIST 800-53r5", "revision": "v4.0"})
        try:
            m, fw = xw.resolve_best("1.1", ["PCIDSS"])
            self.assertEqual(m.control_id, "SC-7")
            self.assertEqual(fw, "PCIDSS")
            self.assertEqual(xw.CROSSWALK_META["PCIDSS"]["revision"], "v4.0")
        finally:
            xw.CROSSWALKS.pop("PCIDSS", None)
            xw.CROSSWALK_META.pop("PCIDSS", None)


class Serialisation(unittest.TestCase):
    def test_to_dict_carries_type_and_version(self):
        d = Mapping("AC-2", "partial", "x", relationship="subset").to_dict()
        self.assertEqual(d["control_id"], "AC-2")
        self.assertEqual(d["relationship"], "subset")
        self.assertEqual(d["schema_version"], xw.SCHEMA_VERSION)
        self.assertIn("confidence", d)


if __name__ == "__main__":
    unittest.main()
