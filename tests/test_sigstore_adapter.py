"""Sigstore adapter tests (stdlib unittest / pytest)."""
from __future__ import annotations

import json
import os
import unittest

from app.services import sigstore
from app.services.intoto import SLSA_PROVENANCE_V1, dsse_encode, to_intoto_statement
from app.services.sigstore import bundle_metadata, from_sigstore

_LEXICON = os.path.join(os.path.dirname(__file__), "..", "app", "data", "concept_lexicon.json")
_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _bundle():
    stmt = to_intoto_statement(subject_name="pkg:app@1.0", sha256=_SHA,
                               predicate_type=SLSA_PROVENANCE_V1)
    env = dsse_encode(stmt)
    env["signatures"] = [{"sig": "AAAA"}]
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "verificationMaterial": {
            "certificate": {"rawBytes": "MIIB..."},
            "tlogEntries": [{"logIndex": "123456", "integratedTime": "1700000000"}],
        },
        "dsseEnvelope": env,
    }


class Metadata(unittest.TestCase):
    def test_extracts_transparency_and_predicate(self):
        m = bundle_metadata(_bundle())
        self.assertTrue(m["signed"])
        self.assertTrue(m["has_certificate"])
        self.assertTrue(m["in_transparency_log"])
        self.assertEqual(m["rekor_log_index"], "123456")
        self.assertEqual(m["predicate_type"], SLSA_PROVENANCE_V1)

    def test_never_claims_crypto_verification(self):
        # The load-bearing honesty: structural read only, never a crypto verdict.
        self.assertFalse(bundle_metadata(_bundle())["cryptographically_verified"])

    def test_unsigned_bundle(self):
        m = bundle_metadata({"verificationMaterial": {}})
        self.assertFalse(m["signed"])
        self.assertFalse(m["in_transparency_log"])

    def test_non_dict(self):
        self.assertFalse(bundle_metadata("x")["signed"])


class Evidence(unittest.TestCase):
    def test_signature_evidence(self):
        ev = from_sigstore(_bundle())
        self.assertTrue(ev.telemetry["evidence_signed"])
        self.assertTrue(ev.telemetry["in_transparency_log"])
        self.assertEqual(ev.asset_id, "pkg:app@1.0")   # subject lifted from wrapped statement
        self.assertIn("data_integrity", ev.concepts)
        self.assertEqual(ev.source_system, "SIGSTORE")

    def test_none_on_non_dict(self):
        self.assertIsNone(from_sigstore("x"))


class LexiconIntegrity(unittest.TestCase):
    def test_concepts_real(self):
        with open(_LEXICON) as fh:
            ids = {c["id"] for c in json.load(fh)}
        self.assertEqual(set(sigstore._INTEGRITY_CONCEPTS) - ids, set())


if __name__ == "__main__":
    unittest.main()
