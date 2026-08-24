"""Agent-decision log: pure hash chain (here) + DB behaviour (CI)."""
from __future__ import annotations

import unittest

from app.services.agent_audit import record_hash


class HashChain(unittest.TestCase):
    def test_deterministic_and_order_independent_payload(self):
        p1 = {"a": 1, "b": 2}
        p2 = {"b": 2, "a": 1}
        self.assertEqual(record_hash(None, p1), record_hash(None, p2))

    def test_prev_hash_changes_result(self):
        p = {"action": "x"}
        self.assertNotEqual(record_hash(None, p), record_hash("abc", p))

    def test_payload_change_changes_hash(self):
        self.assertNotEqual(record_hash("h", {"action": "a"}),
                            record_hash("h", {"action": "b"}))


if __name__ == "__main__":
    unittest.main()
