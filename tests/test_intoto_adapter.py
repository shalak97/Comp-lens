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


def _signed_slsa_env():
    """A DSSE envelope carrying a signature.

    `build_provenance` now means "provenance exists AND is signed", so the
    positive assertions below need a signed envelope. A bare statement is a
    claim the payload makes about itself.
    """
    env = dsse_encode(_slsa_stmt())
    env["signatures"] = [{"sig": "MEUCIQDx", "keyid": "k1"}]
    return env


class Ingest(unittest.TestCase):
    def test_statement_maps_to_provenance_evidence(self):
        ev = from_intoto(_signed_slsa_env())
        self.assertTrue(ev.telemetry["build_provenance"])
        self.assertTrue(ev.telemetry["slsa_provenance"])
        self.assertEqual(ev.telemetry["builder_id"], "https://github.com/actions/runner")
        self.assertEqual(ev.asset_id, "pkg:app@1.0")
        self.assertIn("supply_chain_security", ev.concepts)
        self.assertEqual(ev.plane, "change_delivery")

    def test_an_unsigned_statement_is_extracted_but_not_trusted(self):
        """This assertion used to read the other way round, which is the bug:
        an unsigned statement set build_provenance and became a PASS finding
        against SR-3, attributed to whatever builder id it named."""
        ev = from_intoto(_slsa_stmt())
        self.assertFalse(ev.telemetry["build_provenance"])
        self.assertTrue(ev.telemetry["build_provenance_unverified"])
        # still extracted, so the missing signature is visible rather than silent
        self.assertEqual(ev.asset_id, "pkg:app@1.0")
        self.assertEqual(ev.telemetry["builder_id"], "https://github.com/actions/runner")

    def test_signature_presence_is_not_signature_verification(self):
        """This module does no cryptography and must not imply that it does."""
        self.assertFalse(from_intoto(_signed_slsa_env()).provenance["signature_verified"])

    def test_accepts_dsse_wrapped_statement(self):
        ev = from_intoto(_signed_slsa_env())
        self.assertIsNotNone(ev)
        self.assertTrue(ev.telemetry["slsa_provenance"])
        # and an unsigned envelope is still decoded, just not trusted
        self.assertIsNotNone(from_intoto(dsse_encode(_slsa_stmt())))

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
