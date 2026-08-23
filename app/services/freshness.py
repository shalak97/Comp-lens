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


def cadence_days(cadence: str | int) -> int:
    if isinstance(cadence, int) and cadence > 0:
        return cadence
    return CADENCE_DAYS.get(str(cadence or "").lower(), CADENCE_DAYS[DEFAULT_CADENCE])


def next_validation(last_validated: Any, cadence: str | int = DEFAULT_CADENCE) -> str | None:
    """When a claim validated at `last_validated` must be re-validated. ISO 8601."""
    base = _parse(last_validated)
    if base is None:
        return None
    return (base + timedelta(days=cadence_days(cadence))).isoformat()


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
    nxt = base + timedelta(days=days)
    age = (now - base).total_seconds() / 86400.0
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
