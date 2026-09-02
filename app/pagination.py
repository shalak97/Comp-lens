"""Bounded list reads.

Most list endpoints used to answer with every row a tenant had. That is fine
at demo scale and a problem at audit scale: a tenant with 50k findings, assets
or evidence documents got the whole table serialised into one response, with
the memory spike on the server and the parse cost on the client.

The rule here, and the reason this is not just a `[:100]` slice in the route:

    A compliance list that is cut short must say so.

Silently truncating a list of controls or findings is the same defect as a
verification report that quietly narrows its own scope — the caller reads a
partial answer as a complete one, and in this product that means an auditor
reads "12 open waivers" when there are 400. So the bound is pushed into the
SQL (`LIMIT`/`OFFSET`, so the rows are never loaded), and every bounded
response carries headers describing the window it represents.

Response headers set on every paginated endpoint:

    X-Limit      the maximum rows this response could contain
    X-Offset     how many rows were skipped
    X-Returned   how many rows are actually in the body

A response where ``X-Returned == X-Limit`` is a full page and there may be
more: request the next window with ``offset=X-Offset + X-Limit``. That test
can say "maybe more" on an exactly-full final page, which is deliberate — it
costs no extra query, and erring toward "there may be more" over-warns rather
than under-reports. Understating truncation is the failure that matters.

The response body stays a bare JSON array. Wrapping it in
``{"items": [...], "total": n}`` would be a cleaner envelope but breaks every
existing caller including the dashboard, and the headers carry the same
information without the churn.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import Query, Response

#: Rows returned when the caller does not ask for a specific window. Large
#: enough that ordinary tenants never notice a page boundary, small enough
#: that a pathological one cannot exhaust memory.
DEFAULT_LIMIT = 100

#: Hard ceiling. A caller may ask for more than the default but not for
#: everything — "unbounded on request" is still unbounded.
MAX_LIMIT = 1000


@dataclass(frozen=True)
class Page:
    """One requested window over a list."""

    limit: int
    offset: int


def page_params(
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT,
                       description="Maximum rows to return."),
    offset: int = Query(0, ge=0, description="Rows to skip before returning."),
) -> Page:
    """FastAPI dependency giving every list endpoint the same two parameters."""
    return Page(limit=limit, offset=offset)


def apply(stmt: Any, limit: int | None = None, offset: int = 0) -> Any:
    """Apply a window to a SQLAlchemy select.

    Bounding happens in SQL rather than by slicing the result, so the rows
    outside the window are never fetched or instantiated — slicing afterwards
    would bound the response while leaving the memory cost untouched.

    ``limit=None`` means unbounded, which the service-layer defaults keep so
    internal callers that genuinely need every row (exports, the scheduler's
    own scans) are unaffected by the API's default.
    """
    if offset:
        stmt = stmt.offset(offset)
    if limit is not None:
        stmt = stmt.limit(limit)
    return stmt


def describe(response: Response, page: Page, returned: int) -> None:
    """Attach the window headers to a bounded response."""
    response.headers["X-Limit"] = str(page.limit)
    response.headers["X-Offset"] = str(page.offset)
    response.headers["X-Returned"] = str(returned)


__all__ = ["DEFAULT_LIMIT", "MAX_LIMIT", "Page", "apply", "describe", "page_params"]
