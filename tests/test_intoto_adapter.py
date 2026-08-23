"""in-toto / SLSA adapter tests (stdlib unittest / pytest)."""
from __future__ import annotations

import json
import os
import unittest

from app.services import intoto
from app.services.intoto import (
    SLSA_PROVENANCE_V1,
    dsse_decode,
    dsse_encode,
    from_intoto,
    to_intoto_statement,
    verify_subject_digest,
)

_LEXICON = os.path.join(os.path.dirname(__file__), "..", "app", "data", "concept_lexicon.json")

_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _slsa_stmt():
    return to_intoto_statement(
        subject_name="pkg:app@1.0", sha256=_SHA, predicate_type=SLSA_PROVENANCE_V1,
        predicate={"runDetails": {"builder": {"id": "https://github.com/actions/runner"}}})


class Ingest(unittest.TestCase):
    def test_statement_maps_to_provenance_evidence(self):
        ev = from_intoto(_slsa_stmt())
        self.assertTrue(ev.telemetry["build_provenance"])
        self.assertTrue(ev.telemetry["slsa_provenance"])
        self.assertEqual(ev.telemetry["builder_id"], "https://github.com/actions/runner")
        self.assertEqual(ev.asset_id, "pkg:app@1.0")
        self.assertIn("supply_chain_security", ev.concepts)
        self.assertEqual(ev.plane, "change_delivery")

    def test_accepts_dsse_wrapped_statement(self):
        env = dsse_encode(_slsa_stmt())
        ev = from_intoto(env)
        self.assertIsNotNone(ev)
        self.assertTrue(ev.telemetry["slsa_provenance"])

    def test_non_provenance_predicate_still_ingested(self):
        stmt = to_intoto_statement(subject_name="x", sha256=_SHA,
                                   predicate_type="https://example/custom")
        ev = from_intoto(stmt)
        self.assertFalse(ev.telemetry["slsa_provenance"])

    def test_garbage_returns_none(self):
        self.assertIsNone(from_intoto({"not": "a statement"}))
        self.assertIsNone(from_intoto("nope"))


class Dsse(unittest.TestCase):
    def test_encode_decode_roundtrip(self):
        payload = {"_type": "x", "hello": "world"}
        self.assertEqual(dsse_decode(dsse_encode(payload)), payload)

    def test_decode_rejects_non_envelope(self):
        self.assertIsNone(dsse_decode({"no": "payload"}))
        self.assertIsNone(dsse_decode({"payload": "!!!not-base64!!!"}))


class Verify(unittest.TestCase):
    def test_subject_digest_match(self):
        self.assertTrue(verify_subject_digest(_slsa_stmt(), "pkg:app@1.0", _SHA))
        self.assertFalse(verify_subject_digest(_slsa_stmt(), "pkg:app@1.0", "deadbeef"))
        self.assertFalse(verify_subject_digest(_slsa_stmt(), "other", _SHA))


class LexiconIntegrity(unittest.TestCase):
    def test_concepts_real(self):
        with open(_LEXICON) as fh:
            ids = {c["id"] for c in json.load(fh)}
        self.assertEqual(set(intoto._PROVENANCE_CONCEPTS) - ids, set())


if __name__ == "__main__":
    unittest.main()
