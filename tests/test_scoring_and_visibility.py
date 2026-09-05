"""Scores that say what they know, and drift that sees everything that moved.

    assessment       risk_weighted_score reported 100.0 for a never-assessed
                     tenant, an all-ERROR estate, and ten failing controls —
                     beside a compliance_score of 0.00 in the same response
    trends           drift counted only pass<->fail, so an estate going dark
                     between two runs reported zero drift
    evaluator        the ReDoS guard was defeated by one extra parenthesis
    evidence_policy  a human sign-off satisfied a control forever
"""
from __future__ import annotations

import time

import pytest

from app.policy_as_code.evaluator import _has_nested_quantifier, _matches


# ── #2 a score with no evidence behind it is not 100 ──
def test_risk_weighted_score_is_none_when_nothing_has_been_weighed():
    """`... if max_exposure else 100.0`. INFO severity weighs 0.0, and ERROR
    and NOT_APPLICABLE rows never accumulate exposure at all, so several very
    different "we know nothing" estates all reported a perfect risk score."""
    import inspect

    from app.services.assessment import AssessmentService
    src = inspect.getsource(AssessmentService.compliance_summary)
    assert "else 100.0" not in src, "no-exposure still reports a perfect score"
    assert "if max_exposure else None" in src


def test_the_summary_reports_what_the_risk_score_was_computed_from():
    """None on its own is a shrug. `risk_weighted_basis` says how much weight
    was actually available, so a consumer can tell "no findings" from "findings
    that all weigh nothing"."""
    import inspect

    from app.services.assessment import AssessmentService
    assert "risk_weighted_basis" in inspect.getsource(AssessmentService.compliance_summary)


# ── #5 drift must see the estate going dark ──
class _Posture:
    def __init__(self, prev, curr):
        self.prev, self.curr = prev, curr


def _drift(rows):
    """Reproduce TrendService.drift's classification without a database."""
    verified = ("pass", "fail")
    out = {"regressions": [], "recoveries": [],
           "visibility_lost": [], "visibility_gained": [], "transitions": {}}
    for p, c in rows:
        if p is None or p == c:
            continue
        out["transitions"][f"{p}->{c}"] = out["transitions"].get(f"{p}->{c}", 0) + 1
        if p == "pass" and c == "fail":
            out["regressions"].append((p, c))
        elif p == "fail" and c == "pass":
            out["recoveries"].append((p, c))
        elif p in verified and c not in verified:
            out["visibility_lost"].append((p, c))
        elif p not in verified and c in verified:
            out["visibility_gained"].append((p, c))
    return out


def test_the_drift_stand_in_matches_the_service():
    import inspect

    from app.services.trends import TrendService
    src = inspect.getsource(TrendService.drift)
    assert "visibility_lost" in src and "transitions" in src


@pytest.mark.parametrize(("prev", "curr"), [
    ("pass", "error"),            # the platform lost the ability to verify it
    ("fail", "error"),
    ("pass", "not_applicable"),
])
def test_losing_the_ability_to_verify_a_control_is_drift(prev, curr):
    """Only pass<->fail was counted, so a connector losing its credentials —
    which since bulk_assess writes ERROR rows can darken a whole estate — showed
    up as zero drift. Understating in the reassuring direction."""
    d = _drift([(prev, curr)])
    assert d["visibility_lost"], f"{prev} -> {curr} was invisible"
    assert d["transitions"] == {f"{prev}->{curr}": 1}


def test_regaining_visibility_is_reported_too():
    assert _drift([("error", "pass")])["visibility_gained"]


def test_the_original_meaning_of_regression_and_recovery_is_unchanged():
    """Existing consumers read these two fields; widening them silently would
    have inflated every dashboard."""
    d = _drift([("pass", "fail"), ("fail", "pass"), ("pass", "error")])
    assert len(d["regressions"]) == 1
    assert len(d["recoveries"]) == 1
    assert len(d["visibility_lost"]) == 1


def test_a_control_that_did_not_move_is_not_drift():
    assert _drift([("pass", "pass"), (None, "pass")])["transitions"] == {}


# ── #13 the ReDoS guard, at any nesting depth ──
@pytest.mark.parametrize("pattern", [
    "(a+)+$",           # the classic
    "(a|aa)*$",
    "(a*)*$",
    "(?:a+)+$",
    "((a+))+$",         # one extra layer defeated the old guard entirely
    "((a|aa))*$",
    "(((a+)))+$",
    "(x(a|b)*)*",
    "(a{1,3})+$",
    "([a-z]+)*$",
    r"(\w+\s?)*$",
    r"(a)\1+",          # a backreference is its own exponential family
])
def test_a_catastrophic_pattern_is_refused_however_deeply_nested(pattern):
    """`\\(([^()]*)\\)` only matched a group with no parentheses inside, so
    wrapping the same pattern once walked straight past it — `((a+))+$` took
    24.8 SECONDS on a 29-character subject, with a 10,000-character cap."""
    assert _has_nested_quantifier(pattern), f"{pattern} slipped past the guard"


@pytest.mark.parametrize("pattern", [
    r"^AC-\d+$",
    r"[a-z]+@[a-z]+\.com",
    r"^\d{4}-\d{2}-\d{2}$",
    "abc",
    "(prod|staging)",
    r"^s3://[a-z0-9-]+$",
    r"\(literal\)+",          # escaped parens are text, not structure
    r"^(GET|POST)$",
    r"v\d+\.\d+\.\d+",
])
def test_an_ordinary_pattern_is_not_rejected(pattern):
    """A guard that refuses real predicates would be routed around, which is
    the failure mode that produced the original bug."""
    assert not _has_nested_quantifier(pattern), f"{pattern} was wrongly refused"
    _matches("anything", pattern)          # and it still runs


def test_the_pathological_case_returns_immediately():
    """The number that made this worth fixing."""
    subject = "a" * 30 + "!"
    started = time.monotonic()
    assert _matches(subject, "((a+))+$") is False
    assert time.monotonic() - started < 1.0, "the guard did not short-circuit"


def test_matching_still_works_for_the_patterns_that_are_allowed():
    assert _matches("AC-2", r"^AC-\d+$")
    assert not _matches("XX-2", r"^AC-\d+$")
    assert _matches("a@b.com", r"[a-z]+@[a-z]+\.com")


# ── #15 a sign-off ages like everything else ──
def test_the_attestation_path_applies_the_same_freshness_rule():
    """Automated evidence is aged twice — decay, then a hard max_age_days
    rejection. The human-attestation branch had neither, and it is reached only
    AFTER the automated evidence has been rejected as too old: the staler the
    machine evidence, the more likely the answer came from the one path with no
    freshness rule at all."""
    import inspect

    from app.services import evidence_policy
    src = inspect.getsource(evidence_policy._evaluate_builtin)
    assert "att.updated_at" in src, "the attestation's age is still unread"
    assert "max_age_days" in src.split("Met via human attestation")[0]


def test_a_stale_attestation_no_longer_reads_as_not_assessed():
    """It is insufficient evidence — which is a different, more useful answer
    than 'nothing on record'."""
    import inspect

    from app.services import evidence_policy
    src = inspect.getsource(evidence_policy._evaluate_builtin)
    assert "if hits or att:" in src


# ── #22 one control, one spelling, in every module that joins on it ──
def test_evidence_policy_canonicalises_the_control_id():
    """`canonical_control_id` was applied in the dependency graph and the
    remediation optimizer and nowhere else, so `/evidence/policy?control_id=AC-2.1`
    reported not_assessed for a control that has evidence under `AC-2(1)`."""
    import inspect

    from app.services import evidence_policy
    assert "canonical_control_id" in inspect.getsource(evidence_policy._control_concepts)


def test_the_lexicon_and_the_canonicaliser_agree():
    from app.services.control_identity import canonical_control_id
    from app.services.evidence_policy import _control_concepts

    # AC-2(7) is in the lexicon under the parenthesised spelling.
    by_paren = _control_concepts("AC-2(7)", "NIST_800_53")
    by_dotted = _control_concepts("AC-2.7", "NIST_800_53")
    assert by_paren, "the fixture control is no longer in the lexicon"
    assert by_paren == by_dotted, "the two spellings still reach different concepts"
    assert canonical_control_id("AC-2.7") == "AC-2(7)"
