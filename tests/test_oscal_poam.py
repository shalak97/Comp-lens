"""OSCAL POA&M + Component Definition builder tests (stdlib unittest / pytest)."""
from __future__ import annotations

import unittest

from app.services.oscal_poam import (
    OSCAL_VERSION,
    build_component_definition,
    build_poam,
)


class Poam(unittest.TestCase):
    def test_only_failing_findings_become_items(self):
        doc = build_poam("t1", [
            {"control_id": "SC-28", "status": "fail", "severity": "high",
             "description": "no encryption", "asset_id": "bucket", "finding_id": "F1"},
            {"control_id": "AU-2", "status": "pass"},          # excluded
            {"control_id": "RA-5", "status": "open"},           # included
        ])
        poam = doc["plan-of-action-and-milestones"]
        self.assertEqual(poam["metadata"]["oscal-version"], OSCAL_VERSION)
        self.assertEqual(len(poam["poam-items"]), 2)
        self.assertEqual(len(poam["observations"]), 2)
        item0 = poam["poam-items"][0]
        self.assertIn("SC-28", item0["title"])
        self.assertEqual(item0["related-findings"], [{"finding-uuid": "F1"}])
        # each item links a real observation
        obs_uuids = {o["uuid"] for o in poam["observations"]}
        self.assertIn(item0["related-observations"][0]["observation-uuid"], obs_uuids)

    def test_empty_findings(self):
        poam = build_poam("t1", [])["plan-of-action-and-milestones"]
        self.assertEqual(poam["poam-items"], [])


class ComponentDefinition(unittest.TestCase):
    def test_control_implementations(self):
        doc = build_component_definition([
            {"name": "api", "type": "software", "controls": ["AC-2", "SC-28"]},
            {"name": "bastion"},  # no controls -> no implementations
        ])
        cd = doc["component-definition"]
        self.assertEqual(cd["metadata"]["oscal-version"], OSCAL_VERSION)
        self.assertEqual(len(cd["components"]), 2)
        api = cd["components"][0]
        reqs = api["control-implementations"][0]["implemented-requirements"]
        self.assertEqual({r["control-id"] for r in reqs}, {"ac-2", "sc-28"})
        self.assertNotIn("control-implementations", cd["components"][1])


if __name__ == "__main__":
    unittest.main()
