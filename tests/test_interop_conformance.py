"""The open-standard adapters mean what the standards say they mean.

Six adapters speak published formats, and the argument for using them rather
than a bespoke shape is that a customer or auditor can look up what a document
means. That argument only holds while these agree with the specs.

The recurring failure here is the same one as everywhere else in this codebase:
a claim stronger than the evidence supports.

    SARIF        a formally accepted risk (result.suppressions) counted as a
                 live critical, though the CycloneDX adapter honours the exact
                 same concept in VEX
    SARIF        a control the platform could not evaluate exported to GitHub
                 code scanning as `kind: "fail"`
    in-toto      an UNSIGNED, self-asserted build attestation became a PASS
                 finding against SR-3, attributed to whatever builder id the
                 payload claimed
    CycloneDX    a vulnerability affecting five components was attributed to
                 one, leaving four looking clean
    SPDX         emitted documents did not validate
"""
from __future__ import annotations

import re

import pytest

from app.services import cyclonedx, intoto, sarif, spdx
from app.services.standards_ingest import plan_for_evidence


def _sarif_log(result, rule_id="py/sql-injection"):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": [
            {"id": rule_id, "properties": {"security-severity": "9.8"}}]}},
        "results": [{"ruleId": rule_id, "level": "error",
                     "message": {"text": "SQL injection"}, **result}]}]}


# ── #12 SARIF suppressions ──
@pytest.mark.parametrize("suppression", [
    {"suppressions": [{"kind": "external", "justification": "accepted, SEC-441"}]},
    {"suppressions": [{"kind": "external", "status": "accepted"}]},
    {"suppressions": [{"kind": "inSource"}]},          # status defaults to accepted
    {"suppressions": [{"kind": "external", "status": "underReview"}]},
    {"baselineState": "absent"},                       # no longer present as of this run
])
def test_a_suppressed_result_is_not_an_open_finding(suppression):
    """A `# nosec`, a baseline entry or a dismissed alert is a decision someone
    made and signed. Counting it drove RA-5 to FAIL on accepted risk and filled
    the POA&M with remediation work nobody had agreed to do."""
    assert sarif.from_sarif(_sarif_log(suppression)) == []


def test_a_rejected_suppression_does_not_suppress():
    """Someone reviewed the suppression request and said no."""
    log = _sarif_log({"suppressions": [{"kind": "external", "status": "rejected"}]})
    assert len(sarif.from_sarif(log)) == 1


def test_a_live_finding_still_reaches_the_vulnerability_control():
    """The guard must not have swallowed real findings."""
    evs = sarif.from_sarif(_sarif_log({}))
    assert len(evs) == 1
    plans = [p for e in evs for p in plan_for_evidence(e)]
    assert [(p.control_id, p.status) for p in plans] == [("RA-5", "fail")]


def test_sarif_and_cyclonedx_answer_the_suppression_question_the_same_way():
    """The bug was an inconsistency, so this is the assertion that names it."""
    suppressed_sarif = sarif.from_sarif(
        _sarif_log({"suppressions": [{"kind": "external"}]}))
    suppressed_vex = cyclonedx.from_cyclonedx(cyclonedx.to_cyclonedx(
        vulnerabilities=[cyclonedx.vulnerability(vid="CVE-1", severity="critical",
                                                 vex_state="not_affected")]))
    assert suppressed_sarif == [] and suppressed_vex == []


# ── #14 SARIF emit ──
def test_an_unevaluated_control_is_not_exported_as_a_failure():
    """SARIF has `kind: "open"` and `kind: "notApplicable"`. Emitting both as
    `fail` uploaded them to GitHub code scanning as alerts asserting the control
    was not satisfied — in the export most likely to leave the company."""
    out = sarif.to_sarif([
        {"control_id": "AC-2", "status": "fail", "severity": "high"},
        {"control_id": "AU-6", "status": "error", "severity": "high"},
        {"control_id": "SC-7", "status": "not_applicable", "severity": "medium"},
    ])
    kinds = {r["ruleId"]: r["kind"] for r in out["runs"][0]["results"]}
    assert kinds == {"AC-2": "fail", "AU-6": "open", "SC-7": "notApplicable"}


def test_no_result_claims_to_fail_at_level_none():
    """SARIF defines level `none` as "evaluated, no problem found", so pairing
    it with kind `fail` is self-contradictory — and GitHub code scanning raises
    no alert at that level, so every INFO-severity failure vanished on upload."""
    out = sarif.to_sarif([{"control_id": f"C-{sev}", "status": "fail", "severity": sev}
                          for sev in ("critical", "high", "medium", "low", "info",
                                      "unknown")])
    for r in out["runs"][0]["results"]:
        assert not (r["kind"] == "fail" and r["level"] == "none"), r
    # and the converse constraint the spec does impose
    for r in out["runs"][0]["results"]:
        if r["kind"] != "fail":
            assert r["level"] == "none", r


def test_passing_controls_are_still_omitted():
    out = sarif.to_sarif([{"control_id": "IA-2", "status": "pass", "severity": "high"}])
    assert out["runs"][0]["results"] == []


def test_rule_indexes_still_line_up_with_the_rule_table():
    out = sarif.to_sarif([{"control_id": "AC-2", "status": "fail"},
                          {"control_id": "AU-6", "status": "error"},
                          {"control_id": "AC-2", "status": "fail"}])
    run = out["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    for r in run["results"]:
        assert rules[r["ruleIndex"]]["id"] == r["ruleId"]


# ── #11 in-toto: an unsigned claim is not evidence ──
def _statement(signed: bool):
    env = intoto.dsse_encode({
        "_type": intoto.STATEMENT_TYPE_V1,
        "predicateType": intoto.SLSA_PROVENANCE_V1,
        "subject": [{"name": "artifact.tar.gz", "digest": {"sha256": "0" * 64}}],
        "predicate": {"runDetails": {"builder": {"id": "https://github.com/actions/runner"}}},
    })
    if signed:
        env["signatures"] = [{"sig": "MEUCIQDx...", "keyid": "k1"}]
    return env


def test_an_unsigned_attestation_does_not_become_a_passing_control():
    """`signatures: []` is anyone's assertion about themselves. This produced
    `SR-3 / PASS`, attributed to GitHub Actions, for a JSON blob."""
    ev = intoto.from_intoto(_statement(signed=False))
    assert ev.telemetry["build_provenance"] is False
    assert ev.telemetry["build_provenance_unverified"] is True
    assert plan_for_evidence(ev) == [], "an unsigned statement minted a PASS finding"


def test_an_unsigned_attestation_is_still_reported_rather_than_discarded():
    """A build that shipped without provenance signing is worth seeing. It is
    just not evidence that the control holds."""
    ev = intoto.from_intoto(_statement(signed=False))
    assert ev.provenance["signed"] is False
    assert ev.asset_id == "artifact.tar.gz"


def test_a_signed_attestation_still_evidences_the_supply_chain_control():
    ev = intoto.from_intoto(_statement(signed=True))
    assert ev.telemetry["build_provenance"] is True
    assert [(p.control_id, p.status) for p in plan_for_evidence(ev)] == [("SR-3", "pass")]


def test_signature_presence_is_never_reported_as_verification():
    """This module does no cryptography and must not imply that it does."""
    ev = intoto.from_intoto(_statement(signed=True))
    assert ev.provenance["signature_verified"] is False


# ── #20 digest comparison ──
def test_a_digest_matches_regardless_of_hex_case():
    """Tools write hex in both cases; returning False read as "not covered"."""
    digest = "a" * 64
    stmt = intoto.to_intoto_statement(subject_name="app.tgz", sha256=digest)
    assert intoto.verify_subject_digest(stmt, "app.tgz", digest.upper())
    assert intoto.verify_subject_digest(stmt, "app.tgz", digest)


def test_a_statement_using_another_algorithm_can_be_verified():
    stmt = {"_type": intoto.STATEMENT_TYPE_V1, "predicateType": "x", "predicate": {},
            "subject": [{"name": "app.tgz", "digest": {"sha512": "F" * 128}}]}
    assert intoto.verify_subject_digest(stmt, "app.tgz", "f" * 128, "sha512")
    assert not intoto.verify_subject_digest(stmt, "app.tgz", "f" * 128, "sha256")


def test_a_wrong_digest_still_fails():
    stmt = intoto.to_intoto_statement(subject_name="app.tgz", sha256="a" * 64)
    assert not intoto.verify_subject_digest(stmt, "app.tgz", "b" * 64)
    assert not intoto.verify_subject_digest(stmt, "other.tgz", "a" * 64)


# ── #19 CycloneDX attribution ──
def test_a_vulnerability_is_attributed_to_every_component_it_affects():
    """Only `affects[0]` became the asset, so four of five components looked
    clean and `vulnerable_components` reported 1 of 5."""
    bom = cyclonedx.to_cyclonedx(
        components=[{"bom-ref": f"pkg:{c}", "name": c} for c in "abc"],
        vulnerabilities=[{"id": "CVE-2024-1", "ratings": [{"severity": "critical"}],
                          "affects": [{"ref": "pkg:a"}, {"ref": "pkg:b"},
                                      {"ref": "pkg:c"}]}])
    assert {e.asset_id for e in cyclonedx.from_cyclonedx(bom)} == {"pkg:a", "pkg:b", "pkg:c"}
    assert cyclonedx.sbom_summary(bom)["vulnerable_components"] == 3


def test_severity_counters_stay_per_vulnerability_not_per_component():
    """`critical_vulnerabilities` is the RA-5 policy field. Fanning it out by
    affected component would silently change what the control measures."""
    bom = cyclonedx.to_cyclonedx(
        components=[{"bom-ref": f"pkg:{c}", "name": c} for c in "abc"],
        vulnerabilities=[{"id": "CVE-2024-1", "ratings": [{"severity": "critical"}],
                          "affects": [{"ref": "pkg:a"}, {"ref": "pkg:b"},
                                      {"ref": "pkg:c"}]}])
    s = cyclonedx.sbom_summary(bom)
    assert s["critical_vulnerabilities"] == 1
    assert s["total_vulnerabilities"] == 1


def test_a_vulnerability_naming_no_component_is_not_dropped():
    bom = cyclonedx.to_cyclonedx(
        vulnerabilities=[{"id": "CVE-X", "ratings": [{"severity": "high"}]}])
    evs = cyclonedx.from_cyclonedx(bom)
    assert len(evs) == 1 and evs[0].asset_id is None


# ── #18 SPDX validity ──
SPDX_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SPDX_ID = re.compile(r"^SPDXRef-[A-Za-z0-9.\-]+$")


def test_the_creation_timestamp_is_in_the_form_spdx_requires():
    """`isoformat()` gives `+00:00` and microseconds; SPDX 2.3 wants a `Z` and
    second precision. Every document this emitted failed validation on its
    first field."""
    created = spdx.to_spdx()["creationInfo"]["created"]
    assert SPDX_DATE.match(created), created


@pytest.mark.parametrize("name", [
    "@babel/core",          # any scoped npm package
    "my_package",           # underscore
    "some package v2",      # space
    "café",                 # non-ascii
])
def test_every_element_id_conforms_to_the_spdx_charset(name):
    """SPDX element ids allow only letters, digits, `.` and `-`."""
    doc = spdx.to_spdx(packages=[spdx.package(name=name)])
    assert SPDX_ID.match(doc["packages"][0]["SPDXID"]), doc["packages"][0]["SPDXID"]
    assert SPDX_ID.match(doc["SPDXID"])


def test_element_ids_stay_unique_when_names_normalise_alike():
    doc = spdx.to_spdx(packages=[spdx.package(name="a/b", seq=0),
                                 spdx.package(name="a_b", seq=1)])
    ids = [p["SPDXID"] for p in doc["packages"]]
    assert len(set(ids)) == len(ids), ids


def test_the_document_declares_what_it_describes():
    """SPDX 2.3 requires a DESCRIBES relationship or documentDescribes; this
    emitted neither, so the document said nothing about its own subject."""
    doc = spdx.to_spdx(packages=[spdx.package(name="left-pad", version="1.0.0")])
    pkg_id = doc["packages"][0]["SPDXID"]
    assert doc["documentDescribes"] == [pkg_id]
    assert {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
            "relatedSpdxElement": pkg_id} in doc["relationships"]


def test_an_emitted_document_still_round_trips_through_the_reader():
    doc = spdx.to_spdx(packages=[
        spdx.package(name="left-pad", version="1.0.0", advisories=["CVE-2024-9"])])
    assert spdx.spdx_summary(doc)["package_count"] == 1
    assert spdx.spdx_summary(doc)["packages_with_advisories"] == 1
    assert len(spdx.from_spdx(doc)) == 1
