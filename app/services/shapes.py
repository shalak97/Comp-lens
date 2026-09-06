"""Read a shape out of an untrusted document without trusting its shape.

The standards adapters parse documents that arrive over `POST /v1/ingest/standard`
— a SARIF log from someone's scanner, a CycloneDX BOM from a build. They are
JSON, so any field can be any type, and the idiom they all reached for handles
only two of the three ways a field can be wrong:

    for run in log.get("runs") or []:

That copes with `runs` missing and with `runs: null`. It does not cope with
`runs: 5`, which sails through `or []` and raises `TypeError: 'int' object is
not iterable` from inside the adapter. Fuzzing the seven adapters produced 33
distinct crashes of that family, every one turning a malformed document into an
HTTP 500 where 400 is the honest answer — and a stack trace in the logs for what
is really a bad request.

`as_list` and `as_dict` say what the caller actually needs: a value of this
shape, or an empty one. A wrong-typed field is treated exactly like an absent
one, which is the correct reading — a `runs` that is not an array carries no
runs.
"""
from __future__ import annotations

from typing import Any


def as_list(value: Any) -> list:
    """The value if it is a list, else an empty list.

    A string is deliberately NOT split into characters: `"objects": "abc"` means
    the producer sent something wrong, not three objects.
    """
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict:
    """The value if it is a dict, else an empty dict."""
    return value if isinstance(value, dict) else {}


def as_dicts(value: Any) -> list[dict]:
    """The dict members of a list, skipping anything else.

    The common shape: a list of objects where a hostile or buggy producer has
    put a scalar among them.
    """
    return [v for v in as_list(value) if isinstance(v, dict)]


def as_text(value: Any, limit: int | None = None) -> str:
    """A string, with no exception for exotic input, optionally truncated."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    return text[:limit] if limit else text


__all__ = ["as_dict", "as_dicts", "as_list", "as_text"]
