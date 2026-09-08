"""Control-claim freshness — the `next_validation` / expiry primitive.

A control *status* is a point-in-time observation; a control *claim* carries an
explicit freshness guarantee — when it must be re-validated before it can still be
asserted. The architecture review calls this out as the property that turns a status
into a claim with an expiry (the KSI `next_validation` field). This module is the pure
primitive; wiring it onto stored posture/trust rows is the model-touching follow-up.

Pure, stdlib only — unit-testable.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

# Named validation cadences -> their period in days.
CADENCE_DAYS: dict[str, int] = {
    "continuous": 1, "daily": 1, "weekly": 7, "biweekly": 14, "monthly": 30,
    "quarterly": 90, "semiannual": 182, "annual": 365,
}
DEFAULT_CADENCE = "monthly"


def _parse(ts: Any) -> datetime | None:
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=UTC)
    if not isinstance(ts, str) or not ts.strip():
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


#: Longest cadence that can still be added to a date without overflowing.
#: timedelta tops out near 1e9 days; a century is already far past any real
#: validation policy, and anything larger is a typo or a hostile value.
MAX_CADENCE_DAYS = 36_600


def cadence_days(cadence: str | int) -> int:
    """Days between validations. Always a usable, in-range int.

    `bool` is excluded explicitly because isinstance(True, int) is True in
    Python, so a cadence of True would have been returned AS True — a bool
    where an int is declared, silently meaning "one day".
    """
    if isinstance(cadence, int) and not isinstance(cadence, bool) and cadence > 0:
        return min(int(cadence), MAX_CADENCE_DAYS)
    return CADENCE_DAYS.get(str(cadence or "").lower(), CADENCE_DAYS[DEFAULT_CADENCE])


def _add_days(base: datetime, days: int) -> datetime | None:
    """`base + days`, or None when that falls outside the representable range.

    A timestamp near datetime.max — year 9999 from a malformed document, or a
    connector reporting nonsense — makes this addition raise OverflowError.
    Adapters already accept any shape a producer sends, so such a date reaches
    here as data, not as an attack, and a date arithmetic error is not a reason
    to fail the request that carried it.
    """
    try:
        return base + timedelta(days=days)
    except (OverflowError, OSError, ValueError):
        return None


def next_validation(last_validated: Any, cadence: str | int = DEFAULT_CADENCE) -> str | None:
    """When a claim validated at `last_validated` must be re-validated. ISO 8601."""
    base = _parse(last_validated)
    if base is None:
        return None
    nxt = _add_days(base, cadence_days(cadence))
    return nxt.isoformat() if nxt else None


def freshness(last_validated: Any, cadence: str | int = DEFAULT_CADENCE,
              now: datetime | None = None) -> dict[str, Any]:
    """A claim's full freshness state.

    Returns last_validated, cadence period, next_validation, age in days, remaining
    ttl in days (negative once overdue), and is_stale. An unparseable/absent
    last_validated is treated as stale with no next_validation.
    """
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    days = cadence_days(cadence)
    base = _parse(last_validated)
    if base is None:
        return {"last_validated": None, "cadence_days": days, "next_validation": None,
                "age_days": None, "ttl_days": None, "is_stale": True}
    nxt = _add_days(base, days)
    age = (now - base).total_seconds() / 86400.0
    if nxt is None:
        # A date so far out that the next validation is not representable. It
        # cannot be overdue, so reporting it stale would be a claim nothing
        # supports — the same tri-state rule the rest of the platform follows:
        # say "unknown", not "bad".
        return {"last_validated": base.isoformat(), "cadence_days": days,
                "next_validation": None, "age_days": round(age, 3),
                "ttl_days": None, "is_stale": False}
    ttl = (nxt - now).total_seconds() / 86400.0
    return {
        "last_validated": base.isoformat(),
        "cadence_days": days,
        "next_validation": nxt.isoformat(),
        "age_days": round(age, 3),
        "ttl_days": round(ttl, 3),
        "is_stale": now >= nxt,
    }


def is_stale(last_validated: Any, cadence: str | int = DEFAULT_CADENCE,
             now: datetime | None = None) -> bool:
    return freshness(last_validated, cadence, now)["is_stale"]


__all__ = ["CADENCE_DAYS", "DEFAULT_CADENCE", "cadence_days",
           "next_validation", "freshness", "is_stale"]
