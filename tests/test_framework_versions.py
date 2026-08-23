"""framework_versions registry tests (pure) + the pinned column (DB, CI)."""
from __future__ import annotations

import unittest

from app.services.framework_versions import DEFAULT_VERSION, version_of


class Registry(unittest.TestCase):
    def test_canonical_names(self):
        self.assertEqual(version_of("NIST_800_53"), "rev5")
        self.assertEqual(version_of("ISO_27001_2022"), "2022")
        self.assertEqual(version_of("SOC2"), "2017")
        self.assertEqual(version_of("CIS"), "v8")

    def test_aliases_and_spellings(self):
        self.assertEqual(version_of("NIST"), "rev5")
        self.assertEqual(version_of("nist-800-53"), "rev5")
        self.assertEqual(version_of("ISO27001"), "2022")
        self.assertEqual(version_of("SOC 2"), "2017")

    def test_unknown_is_unversioned(self):
        self.assertEqual(version_of("MADE_UP"), DEFAULT_VERSION)
        self.assertEqual(version_of(""), DEFAULT_VERSION)


if __name__ == "__main__":
    unittest.main()
