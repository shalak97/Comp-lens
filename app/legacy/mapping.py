"""Normalize a raw legacy record into the flat telemetry fields the policy
engine expects (mfa_enforced, days_since_last_login, encryption_at_rest, ...).

A field_map entry is either a plain source key:
    "mfa_enforced": "mfa_flag"
or a spec with a coercion:
    "mfa_enforced": {"from": "mfa_flag", "coerce": "bool", "truthy": ["Y","1"]}

Supported coercions: bool, int, float, str, days_since (parse a date/datetime
and return whole days since then).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

_DEFAULT_TRUTHY = {"y", "yes", "true", "1", "t", "enabled", "on"}


def _to_bool(val: Any, truthy) -> bool:
    if isinstance(val, bool):
        return val
    if val is None:
        return False
    s = str(val).strip().lower()
    allowed = {str(t).lower() for t in truthy} if truthy else _DEFAULT_TRUTHY
    return s in allowed


def _days_since(val: Any):
    if val is None:
        return None
    if isinstance(val, datetime):
        dt = val
    else:
        s = str(val).strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            # try common epoch (seconds) integer
            try:
                dt = datetime.fromtimestamp(float(s), tz=timezone.utc)
            except (ValueError, OSError):
                return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def normalize(raw: Dict[str, Any], field_map: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for norm_field, spec in field_map.items():
        if isinstance(spec, str):
            src_key, coerce, truthy = spec, None, None
        else:
            src_key = spec.get("from")
            coerce = spec.get("coerce")
            truthy = spec.get("truthy")
        val = raw.get(src_key)
        if coerce == "bool":
            val = _to_bool(val, truthy)
        elif coerce == "int":
            val = int(val) if val not in (None, "") else None
        elif coerce == "float":
            val = float(val) if val not in (None, "") else None
        elif coerce == "str":
            val = None if val is None else str(val)
        elif coerce == "days_since":
            val = _days_since(val)
        out[norm_field] = val
    return out
