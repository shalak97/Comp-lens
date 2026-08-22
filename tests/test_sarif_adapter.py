"""SARIF adapter: ingest, rollup, emit, round-trip, lexicon-integrity.

Pure-logic tests (stdlib only) — run under pytest or ``python -m unittest``.
Fixtures mirror what CodeQL / Semgrep / GitHub code scanning emit.
"""
from __future__ import annotations

import json
import os
import unittest

from app.services import sarif
from app.services.sarif import from_sarif, sarif_rollup, to_sarif

_LEXICON = os.path.join(os.path.dirname(__file__), "..", "app", "data", "concept_lexicon.json")


def _codeql_log():
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "CodeQL", "version": "2.15.0",
                "rules": [
                    {"id": "py/sql-injection",
                     "shortDescription": {"text": "SQL injection"},
                     "properties": {"security-severity": "9.8", "tags": ["security", "cwe-89"]}},
                    {"id": "py/weak-hash",
                     "shortDescription": {"text": "Weak hashing"},
                     "properties": {"security-severity": "5.9", "tags": ["security"]}},
                    {"id": "py/hardcoded-credential",
                     "shortDescription": {"text": "Hardcoded secret"},
                     "properties": {"security-severity": "8.6", "tags": ["security", "secret"]}},
                ],
            }},
            "results": [
                {"ruleId": "py/sql-injection", "level": "error",
                 "message": {"text": "User input flows to a SQL query."},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "app/db.py"}, "region": {"startLine": 42}}}],
                 "partialFingerprints": {"primaryLocationLineHash": "abc123"}},
                {"ruleId": "py/weak-hash", "level": "warning",
                 "message": {"text": "MD5 used."},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "app/hash.py"}, "region": {"startLine": 7}}}]},
                {"ruleId": "py/hardcoded-credential", "level": "error",
                 "message": {"text": "Hardcoded AWS key."}},
                # a passing result must be ignored
                {"ruleId": "py/weak-hash", "kind": "pass", "level": "none",
                 "message": {"text": "ok"}},
            ],
        }],
    }


class Ingest(unittest.TestCase):
    def test_one_evidence_per_failing_result(self):
        evs = from_sarif(_codeql_log())
        self.assertEqual(len(evs), 3)  # the pass result is dropped

    def test_cvss_drives_severity_over_level(self):
        evs = {e.findings[0]["rule_id"]: e for e in from_sarif(_codeql_log())}
        self.assertEqual(evs["py/sql-injection"].severity, "critical")   # 9.8
        self.assertEqual(evs["py/weak-hash"].severity, "medium")         # 5.9
        self.assertEqual(evs["py/hardcoded-credential"].severity, "high")  # 8.6

    def test_finding_carries_location_and_fingerprint(self):
        ev = next(e for e in from_sarif(_codeql_log())
                  if e.findings[0]["rule_id"] == "py/sql-injection")
        self.assertEqual(ev.asset_id, "app/db.py")
        self.assertEqual(ev.findings[0]["line"], 42)
        self.assertEqual(ev.findings[0]["fingerprint"], "abc123")
        self.assertEqual(ev.source_system, "CODEQL")
        self.assertEqual(ev.plane, "vulnerability_threat")

    def test_concepts_base_plus_tag_specific(self):
        ev = next(e for e in from_sarif(_codeql_log())
                  if e.findings[0]["rule_id"] == "py/sql-injection")
        self.assertIn("security_testing", ev.concepts)          # base
        self.assertIn("vulnerability_management", ev.concepts)  # cwe tag
        secret = next(e for e in from_sarif(_codeql_log())
                      if e.findings[0]["rule_id"] == "py/hardcoded-credential")
        self.assertIn("secure_coding", secret.concepts)         # secret tag

    def test_level_fallback_without_cvss(self):
        log = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep"}},
               "results": [{"ruleId": "r1", "level": "warning", "message": {"text": "x"}}]}]}
        self.assertEqual(from_sarif(log)[0].severity, "medium")

    def test_non_dict_returns_empty(self):
        self.assertEqual(from_sarif("nope"), [])
        self.assertEqual(from_sarif(None), [])


class Rollup(unittest.TestCase):
    def test_rollup_histogram_and_policy_field(self):
        roll = sarif_rollup(_codeql_log())
        self.assertEqual(roll["critical_vulnerabilities"], 1)  # the RA-5 policy field
        self.assertEqual(roll["high_findings"], 1)
        self.assertEqual(roll["medium_findings"], 1)
        self.assertEqual(roll["total_findings"], 3)
        self.assertIn("CODEQL", roll["tools"])


class Emit(unittest.TestCase):
    def test_emit_valid_sarif_shape(self):
        log = to_sarif([
            {"control_id": "RA-5", "status": "fail", "severity": "critical",
             "message": "1 critical CVE unpatched", "location": "app/api.py", "line": 10},
            {"control_id": "SA-15-BRANCH", "status": "fail", "severity": "high"},
            {"control_id": "IA-2", "status": "pass"},  # dropped
        ])
        self.assertEqual(log["version"], "2.1.0")
        run = log["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "Comp-Lens")
        self.assertEqual(len(run["results"]), 2)  # pass dropped
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 2)
        r0 = run["results"][0]
        self.assertEqual(r0["ruleId"], "RA-5")
        self.assertEqual(r0["level"], "error")  # critical -> error
        self.assertEqual(r0["locations"][0]["physicalLocation"]["region"]["startLine"], 10)

    def test_ruleindex_points_at_the_right_rule(self):
        log = to_sarif([{"control_id": "A", "status": "fail"},
                        {"control_id": "B", "status": "fail"},
                        {"control_id": "A", "status": "fail"}])
        rules = log["runs"][0]["tool"]["driver"]["rules"]
        for res in log["runs"][0]["results"]:
            self.assertEqual(rules[res["ruleIndex"]]["id"], res["ruleId"])


class RoundTrip(unittest.TestCase):
    def test_emit_then_ingest_recovers_rule_and_severity(self):
        log = to_sarif([{"control_id": "RA-5", "status": "fail", "severity": "critical",
                         "message": "unpatched CVE"}])
        evs = from_sarif(log)
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].findings[0]["rule_id"], "RA-5")
        self.assertEqual(evs[0].severity, "critical")  # via emitted security-severity 9.5
        self.assertEqual(evs[0].source_system, "COMP-LENS")


class LexiconIntegrity(unittest.TestCase):
    def test_all_mappable_concepts_are_real(self):
        with open(_LEXICON) as fh:
            ids = {c["id"] for c in json.load(fh)}
        mappable = set(sarif._TAG_CONCEPTS.values()) | {sarif._BASE_CONCEPT}
        missing = mappable - ids
        self.assertEqual(missing, set(), f"SARIF maps to unknown concept ids: {missing}")


if __name__ == "__main__":
    unittest.main()
