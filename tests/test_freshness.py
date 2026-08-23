"""freshness primitive tests (stdlib unittest / pytest)."""
from __future__ import annotations

import unittest
from datetime import UTC, datetime

from app.services.freshness import (
    cadence_days,
    freshness,
    is_stale,
    next_validation,
)


class NextValidation(unittest.TestCase):
    def test_named_cadence(self):
        self.assertEqual(next_validation("2026-01-01T00:00:00Z", "monthly"),
                         "2026-01-31T00:00:00+00:00")
        self.assertEqual(next_validation("2026-01-01T00:00:00+00:00", "weekly"),
                         "2026-01-08T00:00:00+00:00")

    def test_integer_cadence_days(self):
        self.assertEqual(cadence_days(5), 5)
        self.assertEqual(next_validation("2026-01-01T00:00:00Z", 5),
                         "2026-01-06T00:00:00+00:00")

    def test_unknown_cadence_falls_back_to_default(self):
        self.assertEqual(cadence_days("nonsense"), 30)  # monthly default

    def test_unparseable_returns_none(self):
        self.assertIsNone(next_validation("not-a-date"))
        self.assertIsNone(next_validation(None))


class Freshness(unittest.TestCase):
    def test_fresh_claim(self):
        f = freshness("2026-01-01T00:00:00Z", "monthly",
                      now=datetime(2026, 1, 15, tzinfo=UTC))
        self.assertFalse(f["is_stale"])
        self.assertEqual(f["next_validation"], "2026-01-31T00:00:00+00:00")
        self.assertAlmostEqual(f["age_days"], 14.0, places=1)
        self.assertGreater(f["ttl_days"], 0)

    def test_stale_claim(self):
        f = freshness("2026-01-01T00:00:00Z", "monthly",
                      now=datetime(2026, 3, 1, tzinfo=UTC))
        self.assertTrue(f["is_stale"])
        self.assertLess(f["ttl_days"], 0)

    def test_absent_last_validated_is_stale(self):
        f = freshness(None)
        self.assertTrue(f["is_stale"])
        self.assertIsNone(f["next_validation"])

    def test_is_stale_helper(self):
        self.assertTrue(is_stale("2026-01-01T00:00:00Z", "daily",
                                 now=datetime(2026, 1, 5, tzinfo=UTC)))
        self.assertFalse(is_stale("2026-01-01T00:00:00Z", "annual",
                                  now=datetime(2026, 2, 1, tzinfo=UTC)))


if __name__ == "__main__":
    unittest.main()
