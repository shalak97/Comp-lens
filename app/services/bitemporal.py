"""Bitemporal control-status log — the as-of reconstruction algorithm.

The architecture review's deepest spine gap: an SSP that asserts compliance "as of"
a date must be reconstructable as the control graph *stood then*, but the ORM only
keeps a single mutable current-state row (`updated_at` overwritten in place). This
module is the pure algorithm that fixes that — an append-only, valid-time interval
log with a system/transaction timestamp on every record, supporting point-in-time
reconstruction. Adopting it in SQLAlchemy (columns + an Alembic migration + writing
history instead of overwriting) is the model-touching follow-up; the algorithm here
is verified independently so that migration is a mechanical port, not a redesign.

Pure, stdlib only — unit-testable.
"""
from __future__ import annotations

from bisect import insort
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def _utc(dt: datetime | None) -> datetime:
    if dt is None:
        return datetime.now(UTC)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


@dataclass(order=True)
class Interval:
    """One valid-time interval for a key: [valid_from, valid_to) with the value
    that held over it, plus recorded_at (when the system learned it)."""
    valid_from: datetime
    valid_to: datetime | None = field(compare=False, default=None)
    key: str = field(compare=False, default="")
    value: Any = field(compare=False, default=None)
    recorded_at: datetime = field(compare=False, default_factory=lambda: datetime.now(UTC))


class TemporalLog:
    """Append-only valid-time log. `put` closes the open interval for a key and
    opens a new one; nothing is ever mutated destructively except the `valid_to`
    of the interval being superseded (standard slowly-changing-dimension type 2)."""

    def __init__(self) -> None:
        self._by_key: dict[str, list[Interval]] = {}

    def put(self, key: str, value: Any, valid_from: datetime | None = None,
            recorded_at: datetime | None = None) -> Interval:
        vf = _utc(valid_from)
        rows = self._by_key.setdefault(key, [])
        # close any still-open interval whose validity starts at/before the new one
        for r in rows:
            if r.valid_to is None and r.valid_from <= vf:
                r.valid_to = vf
        iv = Interval(valid_from=vf, valid_to=None, key=key, value=value,
                      recorded_at=_utc(recorded_at))
        insort(rows, iv)
        return iv

    def as_of(self, valid_time: datetime) -> dict[str, Any]:
        """The value of every key that held at `valid_time` — the snapshot needed to
        reconstruct posture 'as of' a date."""
        vt = _utc(valid_time)
        out: dict[str, Any] = {}
        for key, rows in self._by_key.items():
            for r in rows:
                if r.valid_from <= vt and (r.valid_to is None or vt < r.valid_to):
                    out[key] = r.value
                    break
        return out

    def value_at(self, key: str, valid_time: datetime) -> Any:
        vt = _utc(valid_time)
        for r in self._by_key.get(key, []):
            if r.valid_from <= vt and (r.valid_to is None or vt < r.valid_to):
                return r.value
        return None

    def current(self) -> dict[str, Any]:
        return self.as_of(datetime.now(UTC))

    def history(self, key: str) -> list[Interval]:
        return list(self._by_key.get(key, []))


__all__ = ["Interval", "TemporalLog"]
