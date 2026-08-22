"""OCSF adapter: ingest, emit, round-trip, and lexicon-integrity.

Pure-logic tests — the adapter imports only stdlib — so they run under pytest or
plain ``python -m unittest``. Fixtures mirror the shape real producers (AWS Security
Lake, etc.) emit.
"""
from __future__ import annotations

import json
import os
import unittest
from datetime import UTC, datetime

from app.services import ocsf
from app.services.ocsf import NormalizedEvidence, from_ocsf, to_ocsf_compliance_finding

_LEXICON = os.path.join(os.path.dirname(__file__), "..", "app", "data", "concept_lexicon.json")


def _auth_event(is_mfa=True):
    return {
        "class_uid": ocsf.CLASS_AUTHENTICATION, "category_uid": ocsf.CAT_IAM,
        "activity_id": 1, "time": 1_726_000_000_000, "severity_id": 1,
        "metadata": {"version": "1.4.0", "product": {"name": "Okta", "vendor_name": "Okta"}},
        "actor": {"user": {"uid": "u-42", "name": "ada"}},
        "is_mfa": is_mfa,
    }


def _compliance_event(status="Failed"):
    return {
        "class_uid": ocsf.CLASS_COMPLIANCE_FINDING, "category_uid": ocsf.CAT_FINDINGS,
        "activity_id": 1, "time": 1_726_000_000_000, "severity_id": 4,
        "metadata": {"version": "1.4.0", "product": {"name": "AWS Security Hub"}},
        "resources": [{"uid": "arn:aws:s3:::acme-logs", "type": "AwsS3Bucket"}],
        "compliance": {"status": status, "control": "CC6.7",
                       "standards": ["SOC2", "NIST-800-53"]},
    }


class Ingest(unittest.TestCase):
    def test_authentication_maps_to_mfa_telemetry_and_concept(self):
        ev = from_ocsf(_auth_event(True))
        self.assertIsInstance(ev, NormalizedEvidence)
        self.assertEqual(ev.telemetry.get("mfa_enforced"), True)
        self.assertIn("mfa", ev.concepts)
        self.assertEqual(ev.plane, "identity_access")
        self.assertEqual(ev.source_system, "OKTA")
        self.assertEqual(ev.asset_id, "u-42")

    def test_authentication_mfa_false(self):
        self.assertEqual(from_ocsf(_auth_event(False)).telemetry.get("mfa_enforced"), False)

    def test_compliance_finding_lifts_control_result(self):
        ev = from_ocsf(_compliance_event("Failed"))
        self.assertEqual(ev.plane, "configuration")
        self.assertEqual(len(ev.controls), 1)
        self.assertEqual(ev.controls[0]["control_ref"], "CC6.7")
        self.assertEqual(ev.controls[0]["status"], "fail")
        self.assertIn("SOC2", ev.controls[0]["standards"])
        self.assertEqual(ev.asset_id, "arn:aws:s3:::acme-logs")

    def test_compliance_pass_normalised(self):
        self.assertEqual(from_ocsf(_compliance_event("Passed")).controls[0]["status"], "pass")

    def test_device_inventory_config_signals(self):
        ev = from_ocsf({
            "class_uid": ocsf.CLASS_DEVICE_INVENTORY, "category_uid": ocsf.CAT_DISCOVERY,
            "time": 1_726_000_000_000,
            "metadata": {"product": {"name": "AWS Config"}},
            "device": {"uid": "i-123", "type": "EC2"},
            "unmapped": {"disk_encryption": True, "logging_enabled": "true", "is_public": False},
        })
        self.assertEqual(ev.telemetry.get("disk_encrypted"), True)
        self.assertEqual(ev.telemetry.get("logging_enabled"), True)
        self.assertEqual(ev.telemetry.get("public_access_blocked"), True)  # is_public False -> blocked

    def test_category_inferred_from_class_uid_when_absent(self):
        e = _auth_event()
        e.pop("category_uid")
        self.assertEqual(from_ocsf(e).plane, "identity_access")

    def test_time_variants(self):
        base = _auth_event()
        # epoch seconds get promoted to ms
        base["time"] = 1_726_000_000
        self.assertTrue(from_ocsf(base).observed_at.startswith("20"))
        # missing time -> now (still a valid iso string)
        base.pop("time")
        self.assertIn("T", from_ocsf(base).observed_at)

    def test_non_dict_and_empty(self):
        self.assertIsNone(from_ocsf("not an event"))
        self.assertIsNone(from_ocsf(None))
        ev = from_ocsf({})
        self.assertIsInstance(ev, NormalizedEvidence)
        self.assertEqual(ev.source_system, "OCSF")

    def test_bool_coercion_from_strings(self):
        self.assertEqual(ocsf._as_bool("enabled"), True)
        self.assertEqual(ocsf._as_bool("Disabled"), False)
        self.assertIsNone(ocsf._as_bool("maybe"))


class Emit(unittest.TestCase):
    def test_emit_shape_and_ids(self):
        f = to_ocsf_compliance_finding(control_id="AC-2", status="fail",
                                       framework="NIST-800-53", severity="high",
                                       message="6 dormant accounts")
        self.assertEqual(f["class_uid"], 2003)
        self.assertEqual(f["category_uid"], 2)
        self.assertEqual(f["type_uid"], 200301)          # class*100 + activity
        self.assertEqual(f["metadata"]["version"], ocsf.OCSF_VERSION)
        self.assertEqual(f["metadata"]["product"]["name"], "Comp-Lens")
        self.assertEqual(f["compliance"]["status"], "Fail")
        self.assertEqual(f["compliance"]["control"], "AC-2")
        self.assertIn("NIST-800-53", f["compliance"]["standards"])
        self.assertEqual(f["severity_id"], ocsf.SEVERITY_ID["high"])
        self.assertIsInstance(f["time"], int)

    def test_pass_defaults_to_info_severity(self):
        f = to_ocsf_compliance_finding(control_id="IA-2", status="pass")
        self.assertEqual(f["compliance"]["status"], "Pass")
        self.assertEqual(f["severity_id"], ocsf.SEVERITY_ID["info"])

    def test_emit_time_from_datetime(self):
        f = to_ocsf_compliance_finding(control_id="X", status="pass",
                                       observed_at=datetime(2026, 1, 1, tzinfo=UTC))
        self.assertEqual(f["time"], int(datetime(2026, 1, 1, tzinfo=UTC).timestamp() * 1000))


class RoundTrip(unittest.TestCase):
    def test_emit_then_ingest_recovers_control_and_status(self):
        emitted = to_ocsf_compliance_finding(
            control_id="SC-28", status="fail", framework="SOC2", severity="high")
        back = from_ocsf(emitted)
        self.assertEqual(back.controls[0]["control_ref"], "SC-28")
        self.assertEqual(back.controls[0]["status"], "fail")
        self.assertIn("SOC2", back.controls[0]["standards"])
        self.assertEqual(back.source_system, "COMP-LENS")


class LexiconIntegrity(unittest.TestCase):
    """Every concept the adapter can emit MUST exist in the shipped lexicon, or
    downstream resolution silently drops it."""

    def test_all_emittable_concepts_are_real(self):
        with open(_LEXICON) as fh:
            ids = {c["id"] for c in json.load(fh)}
        emittable = {c for concepts in ocsf._CLASS_CONCEPTS.values() for c in concepts}
        missing = emittable - ids
        self.assertEqual(missing, set(), f"adapter emits unknown concept ids: {missing}")


if __name__ == "__main__":
    unittest.main()
