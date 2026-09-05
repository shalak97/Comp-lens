"""Absence is not compliance.

Four subsystems independently read "we have no evidence" as "the control is
satisfied". They are unrelated modules written at different times, which is why
the pattern is worth a file of its own rather than four scattered assertions:
it is the failure this product is built to not commit.

    ai_governance      obligations it cannot check leave the denominator, so a
                       PROHIBITED AI system reports 100% compliant, no gaps
    assessment         risk_weighted_score returns 100.0 when nothing has been
                       weighed at all
    policy_as_code     a YAML policy evaluated against {} returns "pass"
    policy_as_code     `requires: [X]` is satisfied by X having no policy

The declarative check pack got this right from the start (control_checks.evaluate
returns NOT_APPLICABLE for an absent signal, and says why in its docstring). The
YAML engine, its sibling, did not. Same question, opposite answers.
"""
from __future__ import annotations

import pytest

from app.policy_as_code.engine import PolicyEngine, load_policy
from app.services.ai_governance import ai_act_obligations


# ── #1 EU AI Act: an obligation nobody checked is not an obligation met ──
@pytest.mark.parametrize("tier", ["prohibited", "limited", "minimal"])
def test_a_tier_whose_obligations_are_not_modelled_never_reports_full_compliance(tier):
    """`applicable = [o for o in obligations if o in coverage]` dropped every
    unmodelled obligation from BOTH the percentage and the gap list. The
    prohibited tier — the Act's "must not be deployed" category — reported
    100% compliant with zero gaps and no governance at all."""
    r = ai_act_obligations(tier, {})
    assert r["compliance_pct"] != 100, (
        f"{tier} reports {r['compliance_pct']}% with no governance in place")
    assert r["unassessed"], "an unassessable obligation must be named, not dropped"
    assert len(r["unassessed"]) + r["assessable"] == len(r["obligations"])


def test_high_risk_with_every_checkable_box_ticked_is_not_100_percent():
    """Six of the eight high-risk obligations have a coverage signal. Ticking
    all six reported 100% while *Conformity assessment* and *Technical
    documentation* had never been assessed."""
    all_ticked = {"impact_assessment": True, "data_governance": True,
                  "human_oversight": True, "accuracy_tested": True,
                  "logging_enabled": True, "transparency_notice": True}
    r = ai_act_obligations("high", all_ticked)

    assert r["compliance_pct"] == 75, r          # 6 of 8, not 6 of 6
    assert not r["gaps"], "nothing assessed is failing"
    assert set(r["unassessed"]) == {"Conformity assessment", "Technical documentation"}


def test_the_ai_act_score_still_moves_with_real_governance():
    """The guard must not have flattened the metric."""
    none_ = ai_act_obligations("high", {})
    some = ai_act_obligations("high", {"impact_assessment": True, "data_governance": True})
    assert none_["compliance_pct"] < some["compliance_pct"] < 100


def test_an_unrecognised_tier_says_so_instead_of_quietly_becoming_limited():
    r = ai_act_obligations("banana", {})
    assert r["tier_recognised"] is False
    assert r["tier"] == "unrecognised"


# ── #9 a policy with no evidence is not a passing policy ──
def _bucket_policy():
    return load_policy({
        "control": "SC-13-BUCKET-ENC",
        "severity": "high",
        "pass_when": 'all(buckets, "encryption_enabled == true")',
        "fail_reason": "an unencrypted bucket exists",
    }, source="test.yaml")


def test_a_policy_evaluated_against_no_evidence_is_not_applicable():
    """The regression. `all(...)` over a missing field is vacuously true, so
    this returned "pass / all rules satisfied" for a tenant whose connector had
    never run."""
    d = _bucket_policy().evaluate({})
    assert d.status == "not_applicable", f"got {d.status}: {d.reason}"
    assert "buckets" in d.reason


@pytest.mark.parametrize(("expr", "field"), [
    ('all(buckets, "encryption == true")', "buckets"),
    ('count(users, "mfa == false") == 0', "users"),
    ("len(admin_users_without_mfa) == 0", "admin_users_without_mfa"),
    ("len(open_ports) <= 2", "open_ports"),
    ("sum(costs) == 0", "costs"),
    ("not backdoor_present", "backdoor_present"),
    ("critical_vulnerabilities != 0", "critical_vulnerabilities"),
])
def test_every_vacuously_true_phrasing_is_caught(expr, field):
    """Seven of nine natural "no bad things exist" phrasings returned True over
    an empty context. Each is the obvious way to write the rule, which is what
    made this dangerous rather than obscure."""
    pol = load_policy({"control": "T", "pass_when": expr}, source="t.yaml")
    assert field in pol.signals, f"{field} was not inferred as a required signal"
    assert pol.evaluate({}).status == "not_applicable"


def test_signals_are_inferred_so_an_author_cannot_forget_to_declare_them():
    pol = load_policy({
        "control": "T2",
        "params": {"max_age": 30},
        "pass_when": "scan_age_days <= max_age and encryption_enabled == true",
    }, source="t.yaml")
    # params are thresholds, not evidence
    assert set(pol.signals) == {"scan_age_days", "encryption_enabled"}


def test_an_explicit_signal_list_wins_over_inference():
    """A policy may legitimately want a field to be optional."""
    pol = load_policy({"control": "T3", "signals": ["a"],
                       "pass_when": "a == true and b != 1"}, source="t.yaml")
    assert pol.signals == ["a"]
    assert pol.evaluate({"a": True}).status == "pass"


def test_evidence_that_is_present_still_decides_normally():
    """The guard must not have turned every verdict into not_applicable."""
    pol = _bucket_policy()
    assert pol.evaluate({"buckets": [{"encryption_enabled": True}]}).status == "pass"
    assert pol.evaluate({"buckets": [{"encryption_enabled": True},
                                     {"encryption_enabled": False}]}).status == "fail"
    # A genuinely empty inventory is an observation, not an absence: zero
    # buckets really are all encrypted.
    assert pol.evaluate({"buckets": []}).status == "pass"


def test_evaluate_all_does_not_substitute_an_empty_dict_for_missing_evidence():
    """`evidence_by_control.get(cid, {})` made the no-evidence path the DEFAULT
    path, not an edge case."""
    eng = PolicyEngine({"SC-13-BUCKET-ENC": _bucket_policy()})
    assert [d.status for d in eng.evaluate_all({})] == ["not_applicable"]


# ── #21 a dependency that does not exist has not passed ──
def test_a_required_control_with_no_policy_does_not_count_as_passing():
    """`dep_status.get(c, "pass")` — absence read as compliance, one line."""
    pol = load_policy({"control": "AU-6", "pass_when": "log_review_enabled == true",
                       "requires": ["AU-2-DOES-NOT-EXIST"]}, source="t.yaml")
    d = pol.evaluate({"log_review_enabled": True}, dep_status={"SOMETHING-ELSE": "pass"})
    assert d.status == "fail"
    assert "AU-2-DOES-NOT-EXIST" in d.reason


def test_a_composite_whose_dependencies_were_never_assessed_is_not_a_failure():
    """not_applicable propagates as not_applicable. Calling it a failure would
    be the mirror-image error: claiming knowledge of a breach we don't have."""
    pol = load_policy({"control": "CC-X", "pass_when": "true",
                       "requires": ["AC-2"]}, source="t.yaml")
    d = pol.evaluate({}, dep_status={"AC-2": "not_applicable"})
    assert d.status == "not_applicable"
    assert "AC-2" in d.reason


def test_a_failing_dependency_is_still_a_failure():
    pol = load_policy({"control": "CC-Y", "pass_when": "true",
                       "requires": ["AC-2"]}, source="t.yaml")
    assert pol.evaluate({}, dep_status={"AC-2": "fail"}).status == "fail"


def test_the_shipped_policies_still_behave():
    """The repository's own policies and their embedded tests — the guard
    against a fix that only satisfies the tests written for it."""
    eng = PolicyEngine.from_dir("policies")
    assert eng.policies, "no policies loaded"
    result = eng.run_tests()
    assert result["failed"] == 0, result["results"]
    assert result["passed"] == result["total"] > 0
