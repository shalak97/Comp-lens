"""What the OSCAL export is allowed to assert.

This is the highest-consequence boundary in the product. From 2026-09-30
FedRAMP requires machine-readable packages, so this document stops being a
convenience export and becomes the thing a federal agency reads.

The defect this file exists to prevent was live: the export mapped every
non-satisfied policy decision to OSCAL ``state: "not-satisfied"``.

    "status": {"state": "satisfied" if decision["satisfied"] else "not-satisfied"}

`evidence_policy.evaluate()` has exactly three outcomes, and **two of them mean
"we do not know"**:

    compliant             satisfied=True    a determination
    insufficient_evidence satisfied=False   evidence examined, below threshold
    not_assessed          satisfied=False   nothing on record at all

There is no outcome meaning "assessed and genuinely failing", so every
``not-satisfied`` the export produced was a claim the evidence did not support
— and for `not_assessed`, a claim about a control nobody had looked at.

The same defect class as the rest of this codebase — absence collapsed into
observation — but here the output is a regulatory submission rather than a
dashboard number, and it points the wrong way: it reports your own controls as
failing when you simply have not assessed them.

OSCAL gives ``objective-status.state`` only two values, so there is no
"unknown" to emit. The honest move is therefore not to assert a finding at all
for an unassessed control, and to say so explicitly in the result's scope.
"""
from __future__ import annotations

import pytest

from app.services import evidence_policy, oscal_export

FRAMEWORK = "NIST_800_53"

DECISIONS = {
    "AC-2": {"status": "compliant", "satisfied": True,
             "reason": "Evidence satisfies control via: mfa_enforced"},
    "SC-28": {"status": "insufficient_evidence", "satisfied": False,
              "reason": "Evidence and/or attestation exist but do not meet policy thresholds."},
    "AU-2": {"status": "not_assessed", "satisfied": False,
             "reason": "No evidence or attestation on record."},
}


class _Attestation:
    def __init__(self, control_id: str) -> None:
        self.control_id = control_id


class _Session:
    """Enough Session to drive the export: docs, hits, then attestations."""

    def __init__(self, attestations: list[str]) -> None:
        self._attestations = [_Attestation(c) for c in attestations]
        self._calls = 0

    def execute(self, _stmt):
        self._calls += 1
        rows = self._attestations if self._calls == 3 else []

        class _Result:
            def scalars(self):
                return self

            def all(self):
                return rows

        return _Result()


@pytest.fixture
def export(monkeypatch):
    def _run(controls):
        monkeypatch.setattr(evidence_policy, "evaluate",
                            lambda db, t, fw, cid: DECISIONS[cid])
        doc = oscal_export.export_assessment_results(
            _Session(controls), "tenant-1", FRAMEWORK)
        return doc["assessment-results"]["results"][0]
    return _run


def _finding_for(result, control_id: str):
    want = control_id.lower()
    return next((f for f in result["findings"]
                 if f["target"]["target-id"] == want), None)


# ── the regression ──
def test_no_finding_is_emitted_for_a_control_nobody_assessed(export):
    result = export(["AU-2"])
    assert _finding_for(result, "AU-2") is None, (
        "an OSCAL finding is an assertion, and `state` admits only satisfied "
        "or not-satisfied — so a control with no evidence must produce no "
        "finding rather than a fabricated failure")
    assert result["findings"] == []


def test_the_unassessed_control_is_reported_rather_than_hidden(export):
    """Suppressing the false claim must not also suppress the gap — silence
    would read as 'nothing to say here'."""
    result = export(["AU-2"])
    gaps = [p for p in result["props"] if p["name"] == "unassessed-control"]
    assert [p["value"] for p in gaps] == ["au-2"]
    assert "No evidence or attestation on record." in gaps[0]["remarks"]


def test_an_unassessed_control_is_outside_the_reviewed_scope(export):
    """`reviewed-controls` states what the result speaks to. A control we did
    not assess must not appear there, or the document claims coverage it does
    not have."""
    result = export(["AC-2", "AU-2"])
    selection = result["reviewed-controls"]["control-selections"][0]
    included = [c["control-id"] for c in selection.get("include-controls", [])]
    assert "ac-2" in included
    assert "au-2" not in included


# ── what must still be asserted ──
def test_a_satisfied_control_still_says_so(export):
    result = export(["AC-2"])
    finding = _finding_for(result, "AC-2")
    assert finding is not None
    assert finding["target"]["status"]["state"] == "satisfied"


def test_evidence_examined_and_found_wanting_is_still_not_satisfied(export):
    """The half an over-correction would break. `insufficient_evidence` IS a
    determination — an assessor looked and was not satisfied — so suppressing
    it too would hide real failures behind the same reasoning that justified
    hiding the unassessed ones."""
    result = export(["SC-28"])
    finding = _finding_for(result, "SC-28")
    assert finding is not None
    assert finding["target"]["status"]["state"] == "not-satisfied"


def test_a_not_satisfied_finding_says_what_it_is_based_on(export):
    """"Evidence on record was too weak" and "we tested the control and it is
    broken" are different claims. OSCAL's state cannot distinguish them, so
    the basis is carried explicitly for whoever reads this."""
    finding = _finding_for(export(["SC-28"]), "SC-28")
    basis = [p for p in finding["target"]["props"]
             if p["name"] == "determination-basis"]
    assert basis and basis[0]["value"] == "evidence-examined-below-threshold"


def test_a_satisfied_finding_carries_no_determination_basis_caveat(export):
    finding = _finding_for(export(["AC-2"]), "AC-2")
    assert not [p for p in finding["target"]["props"]
                if p["name"] == "determination-basis"]


# ── shape ──
def test_the_result_declares_the_scope_it_speaks_to(export):
    """`reviewed-controls` is required on a result by the model, and was
    missing entirely — so the document did not validate and, worse, never
    stated which controls it covered."""
    result = export(["AC-2"])
    assert "reviewed-controls" in result
    assert result["reviewed-controls"]["control-selections"]


def test_scope_is_never_an_empty_include_list(export):
    """An empty `include-controls` would be rejected by a validator, and a
    reader could take it for "all controls". When nothing was assessed the
    selection carries a sentence instead."""
    result = export(["AU-2"])
    selection = result["reviewed-controls"]["control-selections"][0]
    assert selection.get("include-controls") != []
    assert "No control reached a determination" in selection["description"]


@pytest.mark.parametrize("key", ["uuid", "title", "description", "start",
                                 "reviewed-controls"])
def test_result_carries_its_required_fields(export, key):
    assert key in export(["AC-2"])


def test_findings_and_scope_agree(export):
    """Every control with a finding is in scope, and vice versa — a document
    that asserts a finding outside its own declared scope is incoherent."""
    result = export(["AC-2", "SC-28", "AU-2"])
    selection = result["reviewed-controls"]["control-selections"][0]
    scope = {c["control-id"] for c in selection.get("include-controls", [])}
    asserted = {f["target"]["target-id"] for f in result["findings"]}
    assert scope == asserted


# ── the POA&M, checked for the same defect ──
def test_the_poam_does_not_plan_remediation_for_unassessed_controls():
    """A POA&M item says "here is our plan to fix this weakness". Raising one
    for a control nobody assessed would commit to remediating an unknown."""
    from app.services import oscal_poam

    doc = oscal_poam.build_poam("tenant-1", [
        {"control_id": "AC-2", "status": "fail"},
        {"control_id": "AU-2", "status": "not_applicable"},
        {"control_id": "SC-7", "status": "pass"},
        {"control_id": "IA-5", "status": "not_assessed"},
    ])
    body = doc.get("plan-of-action-and-milestones", doc)
    items = body.get("poam-items", [])
    titles = " ".join(str(i.get("title", "")) + str(i.get("description", ""))
                      for i in items)
    assert "AU-2" not in titles
    assert "IA-5" not in titles
