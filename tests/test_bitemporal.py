"""bitemporal TemporalLog tests (stdlib unittest / pytest)."""
from __future__ import annotations

import unittest
from datetime import UTC, datetime

from app.services.bitemporal import TemporalLog


def _d(y, m, day):
    return datetime(y, m, day, tzinfo=UTC)


class AsOf(unittest.TestCase):
    def setUp(self):
        self.log = TemporalLog()
        # AC-2 failed on Jan 1, remediated (pass) on Feb 1
        self.log.put("AC-2", "fail", valid_from=_d(2026, 1, 1))
        self.log.put("AC-2", "pass", valid_from=_d(2026, 2, 1))
        # SC-28 passed from Jan 15
        self.log.put("SC-28", "pass", valid_from=_d(2026, 1, 15))

    def test_reconstruct_snapshot_before_remediation(self):
        snap = self.log.as_of(_d(2026, 1, 20))
        self.assertEqual(snap, {"AC-2": "fail", "SC-28": "pass"})

    def test_reconstruct_snapshot_after_remediation(self):
        snap = self.log.as_of(_d(2026, 2, 10))
        self.assertEqual(snap["AC-2"], "pass")

    def test_snapshot_before_control_existed(self):
        snap = self.log.as_of(_d(2026, 1, 10))
        self.assertEqual(snap, {"AC-2": "fail"})   # SC-28 not yet valid

    def test_value_at(self):
        self.assertEqual(self.log.value_at("AC-2", _d(2026, 1, 5)), "fail")
        self.assertEqual(self.log.value_at("AC-2", _d(2026, 3, 1)), "pass")
        self.assertIsNone(self.log.value_at("AC-2", _d(2025, 12, 1)))

    def test_history_closes_intervals(self):
        hist = self.log.history("AC-2")
        self.assertEqual(len(hist), 2)
        self.assertEqual(hist[0].value, "fail")
        self.assertEqual(hist[0].valid_to, _d(2026, 2, 1))   # closed when pass began
        self.assertIsNone(hist[1].valid_to)                  # still open

    def test_current_reads_latest(self):
        cur = self.log.current()
        self.assertEqual(cur["AC-2"], "pass")
        self.assertEqual(cur["SC-28"], "pass")


if __name__ == "__main__":
    unittest.main()
