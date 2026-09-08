"""Time handling, checked with an instrument rather than by reading.

Iteration 2 of a fault-finding sweep. The headline is a negative result, which
is worth recording as carefully as a positive one: **this codebase handles time
well.** All 33 datetime columns are DateTime(timezone=True), every clock source
is aware (no datetime.utcnow(), no bare datetime.now()), `_age_days` normalises
a naive value before subtracting, and the one Python-side comparison of stored
timestamps (`TemporalLog`) normalises through `_utc` on every entry point.

That mattered to check, because SQLite — the default DATABASE_URL and the test
backend — does not preserve timezone: a column declared timezone=True comes
back NAIVE from it, and comparing that to an aware now() raises TypeError. The
scheduler carries a comment about being bitten by exactly this. The sweep found
no second instance.

The schedule interval is also sound: `ge=1` on the request model rules out the
zero interval that would make a schedule permanently due and re-run forever,
and the Integer column caps the value below the range where
`last_run_at + timedelta(minutes=...)` could overflow.

What the fuzzer did find is in `freshness()`, and honesty requires saying it
was NOT reachable: only `cadence_days` and `DEFAULT_CADENCE` are imported by
application code, and the crashing inputs cannot arrive through them. It is
hardened anyway because the module exports these as public API and the next
caller — a posture endpoint, or the Setup page — would have hit them.
"""
from __future__ import annotations

import datetime as dtm
import itertools
import pathlib
import re

import pytest

from app.services.freshness import (
    MAX_CADENCE_DAYS,
    cadence_days,
    freshness,
    is_stale,
    next_validation,
)

UTC = dtm.UTC
NOW = dtm.datetime.now(UTC)

#: Everything a producer, a clock or a config file can plausibly hand us.
HOSTILE_TIMES = [
    None, "", "   ", "not-a-date", 0, -1, 1e309, float("nan"), [], {}, True,
    "2026-01-01", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00+05:30",
    dtm.datetime(2026, 1, 1),                       # naive, as SQLite returns
    dtm.datetime(2026, 1, 1, tzinfo=UTC),
    NOW + dtm.timedelta(days=365),                  # future: clock skew
    dtm.datetime(1, 1, 1, tzinfo=UTC),              # datetime.min
    dtm.datetime(9999, 12, 31, tzinfo=UTC),         # datetime.max
    "0001-01-01T00:00:00Z", "+10000-01-01",
]
HOSTILE_CADENCES = ["monthly", "quarterly", "weekly", "", None, 0, -5, True,
                    False, 10**9, 10**18, "nonsense", 1.5]


# ── the property ──
@pytest.mark.parametrize("fn", [freshness, is_stale, next_validation])
def test_no_timestamp_or_cadence_makes_a_freshness_call_raise(fn):
    """273 combinations per function. A raise here would be an HTTP 500 caused
    by a date in a document somebody uploaded."""
    for ts, cadence in itertools.product(HOSTILE_TIMES, HOSTILE_CADENCES):
        try:
            fn(ts, cadence)
        except Exception as exc:  # noqa: BLE001 — that is the assertion
            pytest.fail(f"{fn.__name__}({ts!r}, {cadence!r}) raised "
                        f"{type(exc).__name__}: {exc}")


def test_a_date_near_the_end_of_time_reports_unknown_not_stale():
    """`base + timedelta` raises OverflowError near datetime.max — reachable
    from a malformed document, since the adapters accept any shape a producer
    sends. A next-validation that cannot be represented is unknown; it is
    certainly not overdue, and claiming stale would be a verdict nothing
    supports."""
    result = freshness(dtm.datetime(9999, 12, 31, tzinfo=UTC), "monthly")
    assert result["next_validation"] is None
    assert result["ttl_days"] is None
    assert result["is_stale"] is False
    assert result["age_days"] is not None, "the age is still knowable"


# ── cadence ──
def test_a_bool_cadence_is_not_one_day():
    """isinstance(True, int) is True in Python, so a cadence of True was
    returned AS True — a bool where an int is declared, quietly meaning a
    one-day revalidation period."""
    assert cadence_days(True) == cadence_days("monthly")
    assert type(cadence_days(True)) is int


def test_an_absurd_cadence_is_clamped_rather_than_overflowing():
    assert cadence_days(10**18) == MAX_CADENCE_DAYS
    assert next_validation("2026-01-01T00:00:00Z", 10**18) is not None


@pytest.mark.parametrize("cadence", [0, -5, "", None, "nonsense", 1.5])
def test_a_meaningless_cadence_falls_back_to_the_default(cadence):
    assert cadence_days(cadence) == cadence_days("monthly")


def test_a_real_integer_cadence_is_still_honoured():
    assert cadence_days(7) == 7
    assert cadence_days(1) == 1


# ── behaviour that must not have changed ──
def test_ordinary_freshness_is_unchanged():
    fresh = freshness(NOW - dtm.timedelta(days=5), "monthly")
    assert fresh["is_stale"] is False and fresh["ttl_days"] == 25.0
    stale = freshness(NOW - dtm.timedelta(days=45), "monthly")
    assert stale["is_stale"] is True and stale["ttl_days"] == -15.0


def test_an_unreadable_timestamp_is_stale_not_fresh():
    """Fail closed: if we cannot tell when this was last validated, we cannot
    claim it is current."""
    for bad in (None, "", "not-a-date", []):
        assert freshness(bad, "monthly")["is_stale"] is True


def test_a_naive_timestamp_is_treated_as_utc_not_rejected():
    """SQLite returns naive datetimes from timezone=True columns, so this is
    the normal path on the default database, not an edge case."""
    naive = NOW.replace(tzinfo=None) - dtm.timedelta(days=5)
    assert freshness(naive, "monthly")["is_stale"] is False


# ── the discipline the rest of the codebase keeps ──
ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_no_naive_clock_source_is_introduced():
    """A naive now() compared against a value normalised to UTC raises
    TypeError at runtime — and only on the code path that compares them, so it
    survives review and fails in production."""
    offenders = []
    for path in (ROOT / "app").rglob("*.py"):
        if "__pycache__" in str(path):
            continue
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if re.search(r"datetime\.utcnow\(\)", line):
                offenders.append(f"{path.relative_to(ROOT)}:{i} datetime.utcnow()")
            elif re.search(r"datetime\.now\(\s*\)", line):
                offenders.append(f"{path.relative_to(ROOT)}:{i} datetime.now()")
    assert not offenders, (
        "these produce NAIVE datetimes; use datetime.now(UTC):\n  "
        + "\n  ".join(offenders))


def test_every_stored_timestamp_column_is_timezone_aware():
    """A bare DateTime() column loses the offset on PostgreSQL too, not just
    SQLite — and silently, as a wrong time rather than an error."""
    bare = []
    for name in ("models.py", "policy_models.py", "audit_models.py",
                 "crawler_models.py", "ai_governance_models.py", "grc_tprm_models.py"):
        path = ROOT / "app" / name
        if not path.exists():
            continue
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if re.search(r"mapped_column\(\s*DateTime\s*[,)]", line):
                bare.append(f"{name}:{i}")
    assert not bare, f"DateTime columns without timezone=True: {bare}"


def test_a_schedule_cannot_be_configured_to_run_continuously():
    """interval_minutes=0 would leave next_run_at == last_run_at, so the
    schedule is due again the instant it finishes and the background runner
    re-runs it every tick, forever."""
    import pydantic

    from app.models import ScheduleRequest

    for bad in (0, -1, -1440):
        with pytest.raises(pydantic.ValidationError):
            ScheduleRequest(name="s", interval_minutes=bad, controls=[])
    # and a real interval still works
    assert ScheduleRequest(name="s", interval_minutes=1, controls=[]).interval_minutes == 1
