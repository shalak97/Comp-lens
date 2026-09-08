"""The headline number must not claim to know something it does not.

Iteration 3 of a fault-finding sweep, instrument: property-based testing of
every score and rollup, rather than pinning examples.

The finding it produced is two adjacent lines in `compliance_summary`:

    score = round(by_status["pass"] / applicable * 100, 2) if applicable else 0.0
    # ... No weighed rows at all is NOT that — it is "no evidence" ...
    risk_weighted = (... if max_exposure else None)

The comment explaining why `risk_weighted` must be None sat directly below a
line doing precisely what it condemns — for the more prominent metric. So
`compliance_score` was 0.0 in two completely different situations:

    "we assessed everything and nothing passed"      a real, terrible result
    "there is nothing here to assess"                we know nothing at all

A tenant that had just cloned the repo and never run an assessment opened the
dashboard on a headline reading **0% compliant**, with the gauge needle pinned
at the bottom of the dial — the most alarming picture the product can draw, for
the one state where it has no information. The same 0.0 was written into every
trend snapshot, so a estate going dark drew a line crashing to zero rather than
stopping.

The distinction that has to survive: a genuine 0% — assessed, nothing passed —
is still 0.0 and still renders as 0.0. Only the unknown became None.
"""
from __future__ import annotations

import itertools
import random

import pytest

from app.models import ControlStatus, Posture, Severity
from app.services.assessment import AssessmentService

TENANT = "score-invariants"

STATUSES = [ControlStatus.PASS, ControlStatus.FAIL, ControlStatus.ERROR,
            ControlStatus.NOT_APPLICABLE]
SEVERITIES = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
              Severity.INFO]


def _finding(db, i: int, status: ControlStatus, severity: Severity) -> None:
    """Add one posture cell.

    `compliance_summary` reads POSTURE, not findings — current state bounded by
    distinct (asset x control), rather than the whole findings history. An
    earlier version of this file created Finding rows, which contribute nothing
    to the summary, so every score came back None and the tests "passed" the
    empty-tenant assertion for entirely the wrong reason.
    """
    db.add(Posture(
        tenant_id=TENANT, control_id=f"AC-{i}", source_system="AWS",
        asset_id=f"a{i}", asset_key=f"a{i}", status=status, severity=severity,
        last_finding_id=f"f{i}"))


def _summary(db, rows: list[tuple[ControlStatus, Severity]]) -> dict:
    for i, (status, severity) in enumerate(rows):
        _finding(db, i, status, severity)
    db.commit()
    return AssessmentService(db).compliance_summary(TENANT)


# ── the regression ──
def test_a_tenant_that_has_assessed_nothing_has_no_score(db_session):
    """Not 0%. Nothing."""
    summary = AssessmentService(db_session).compliance_summary(TENANT)
    assert summary["compliance_score"] is None, (
        "an unassessed tenant reported a compliance score, and 0.0 is the most "
        "alarming value the scale has")
    assert summary["total"] == 0


def test_an_entirely_not_applicable_estate_has_no_score(db_session):
    """`applicable` is total minus not_applicable, so this reaches the same
    branch as an empty tenant while looking, in the database, like real work."""
    summary = _summary(db_session, [(ControlStatus.NOT_APPLICABLE, Severity.HIGH)] * 5)
    assert summary["compliance_score"] is None
    assert summary["total"] == 5


def test_a_genuine_zero_is_still_reported_as_zero(db_session):
    """The half a careless fix would break. Everything assessed, nothing
    passed, is a real and important 0% — suppressing it would hide a total
    failure behind the same word used for 'not assessed'."""
    summary = _summary(db_session, [(ControlStatus.FAIL, Severity.HIGH)] * 4)
    assert summary["compliance_score"] == 0.0


def test_an_all_error_estate_has_no_score_rather_than_zero(db_session):
    """ERROR means the platform could not verify the control. A whole estate
    the connectors could not read is not a compliance failure."""
    summary = _summary(db_session, [(ControlStatus.ERROR, Severity.HIGH)] * 6)
    assert summary["compliance_score"] is None


# ── the properties, over random estates ──
@pytest.mark.parametrize("seed", range(12))
def test_score_invariants_hold_for_any_estate(db_session, seed):
    rng = random.Random(seed)
    rows = [(rng.choice(STATUSES), rng.choice(SEVERITIES))
            for _ in range(rng.randint(1, 25))]
    summary = _summary(db_session, rows)

    score = summary["compliance_score"]
    risk = summary["risk_weighted_score"]
    applicable = summary["total"] - summary["by_status"]["not_applicable"]

    if score is not None:
        assert 0.0 <= score <= 100.0, f"score out of range: {score}"
        assert score == score, "score is NaN"
        assert applicable > 0, "a score was reported with nothing applicable"
    else:
        assert applicable == 0, "no score reported despite applicable controls"

    if risk is not None:
        assert 0.0 <= risk <= 100.0, f"risk_weighted out of range: {risk}"
        assert risk == risk, "risk_weighted is NaN"
        assert summary["risk_weighted_basis"] > 0

    assert summary["total"] == sum(summary["by_status"].values())
    assert summary["risk_exposure"] >= 0


@pytest.mark.parametrize(("passes", "fails"), list(itertools.product([0, 1, 5], [0, 1, 5])))
def test_score_is_exactly_the_pass_ratio(db_session, passes, fails):
    rows = ([(ControlStatus.PASS, Severity.MEDIUM)] * passes
            + [(ControlStatus.FAIL, Severity.MEDIUM)] * fails)
    if not rows:
        pytest.skip("covered by the empty-tenant test")
    summary = _summary(db_session, rows)
    assert summary["compliance_score"] == pytest.approx(
        round(passes / (passes + fails) * 100, 2))


def test_adding_a_passing_control_never_lowers_the_score(db_session):
    """Monotonicity: the number has to move the way a reader expects, or the
    trend line means nothing."""
    before = _summary(db_session, [(ControlStatus.PASS, Severity.HIGH),
                                   (ControlStatus.FAIL, Severity.HIGH)])
    _finding(db_session, 99, ControlStatus.PASS, Severity.HIGH)
    db_session.commit()
    after = AssessmentService(db_session).compliance_summary(TENANT)
    assert after["compliance_score"] >= before["compliance_score"]


# ── everything downstream of the score ──
def test_a_snapshot_can_record_that_nothing_was_assessable(db_session):
    """compliance_snapshots.score was NOT NULL, so the honest value could not
    be stored at all — the fix needed a migration, not just a expression."""
    from app.services.trends import TrendService

    summary = AssessmentService(db_session).compliance_summary(TENANT)
    snap = TrendService(db_session).snapshot(TENANT, summary)
    assert snap.score is None


def test_the_forecast_ignores_snapshots_with_no_score(db_session):
    """float(None) raises, and a null score is not a data point on a trend —
    fitting a line through it would read as a collapse to zero."""
    from app.services.forecast import ForecastService
    from app.services.trends import TrendService

    trends = TrendService(db_session)
    trends.snapshot(TENANT, {"compliance_score": None, "total": 0,
                             "by_status": {"pass": 0, "fail": 0}})
    trends.snapshot(TENANT, {"compliance_score": 80.0, "total": 2,
                             "by_status": {"pass": 1, "fail": 1}})
    db_session.commit()
    result = ForecastService(db_session).forecast(TENANT)
    # One usable point is not enough to fit a line, and that is the honest answer.
    assert result.get("insufficient_data") is True
    assert result["snapshots"] == 1


def test_the_report_says_not_assessed_rather_than_none_percent(db_session):
    """"None%" in an audit report would be worse than the 0% it replaces."""
    import inspect

    from app.services import reporting
    src = inspect.getsource(reporting)
    assert "not assessed" in src
    assert "compliance_score']}%" not in src, (
        "the score is still interpolated unconditionally, so a null renders "
        "as 'None%'")
