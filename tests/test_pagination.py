"""List endpoints are bounded, and say so.

Two things are being protected here.

The bound itself: these endpoints used to return every row a tenant had, so a
tenant with 50k assets or findings serialised the whole table into one
response. The window is applied in SQL, not by slicing afterwards, so the rows
outside it are never loaded.

And the honesty about it: a compliance list that is cut short must say it was
cut short. Silently returning the first 100 of 400 waivers is the same defect
as a verification report that quietly narrows its own scope — the reader takes
a partial answer for a complete one. Every bounded response carries X-Limit,
X-Offset and X-Returned so a caller (and the dashboard) can tell.
"""
from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_pagination.db")
os.environ.setdefault("EVIDENCE_LOCAL_PATH", "./test_pagination_ev")

import pytest
from fastapi.testclient import TestClient

from app.database import init_db
from app.pagination import DEFAULT_LIMIT, MAX_LIMIT


@pytest.fixture(scope="module")
def client():
    init_db()
    from app.main import app
    with TestClient(app) as c:
        yield c


PAGINATED_GET = [
    "/waivers", "/inventory", "/schedules", "/ai-systems", "/attestations",
    "/evidence/documents", "/resolve/decisions", "/grc/risks", "/tprm/vendors",
    "/audits", "/evidence/anchors",
]


@pytest.mark.parametrize("path", PAGINATED_GET)
def test_every_list_endpoint_describes_its_window(client, path):
    r = client.get(path, params={"tenant_id": "pg"})
    assert r.status_code == 200, r.text
    assert r.headers.get("X-Limit") == str(DEFAULT_LIMIT)
    assert r.headers.get("X-Offset") == "0"
    assert r.headers["X-Returned"] == str(len(r.json()))


@pytest.mark.parametrize("path", PAGINATED_GET)
def test_limit_and_offset_are_accepted_and_bounded(client, path):
    r = client.get(path, params={"tenant_id": "pg", "limit": 5, "offset": 2})
    assert r.status_code == 200, r.text
    assert r.headers["X-Limit"] == "5"
    assert r.headers["X-Offset"] == "2"
    assert len(r.json()) <= 5

    # the ceiling is enforced: "unbounded on request" is still unbounded
    assert client.get(path, params={"tenant_id": "pg", "limit": MAX_LIMIT + 1}).status_code == 422
    assert client.get(path, params={"tenant_id": "pg", "limit": 0}).status_code == 422
    assert client.get(path, params={"tenant_id": "pg", "offset": -1}).status_code == 422


def _make_risks(client, tenant: str, n: int) -> None:
    for i in range(n):
        r = client.post("/grc/risks", params={"tenant_id": tenant},
                        json={"title": f"risk-{i:02d}",
                              # ascending severity, so the ranking is unambiguous
                              "likelihood": (i % 5) + 1, "impact": (i % 5) + 1})
        assert r.status_code == 200, r.text


def test_pages_do_not_repeat_or_drop_rows(client):
    """The reason every paginated query got an explicit tie-breaker column.

    With a non-deterministic ORDER BY the database may return a row on one
    page and again on the next, or skip it entirely — so paging would quietly
    corrupt the list it was meant to make safe.
    """
    _make_risks(client, "pg-walk", 12)
    seen: list[str] = []
    for offset in range(0, 12, 4):
        page = client.get("/grc/risks", params={"tenant_id": "pg-walk",
                                                "limit": 4, "offset": offset}).json()
        seen.extend(x["id"] for x in page)
    assert len(seen) == 12
    assert len(set(seen)) == 12, "a row appeared on more than one page"


def test_risk_register_ranks_by_score_across_the_whole_table(client):
    """Ordering had to move into SQL to survive pagination.

    The risk list is ranked worst-first. That sort used to happen in Python
    after fetching every row; with a window it would have ranked only the rows
    inside the window, so page 1 would show the worst of the oldest 100 risks
    rather than the worst 100 risks. On a risk register that ordering is the
    whole point of the view.
    """
    _make_risks(client, "pg-rank", 10)
    top = client.get("/grc/risks", params={"tenant_id": "pg-rank", "limit": 3}).json()
    everything = client.get("/grc/risks", params={"tenant_id": "pg-rank", "limit": 1000}).json()

    def score(r):
        return r["likelihood"] * r["impact"]

    assert [score(x) for x in top] == sorted((score(x) for x in everything), reverse=True)[:3]
    # and the page is genuinely ordered worst-first
    assert [score(x) for x in top] == sorted((score(x) for x in top), reverse=True)


def test_a_full_page_is_how_a_caller_detects_more(client):
    _make_risks(client, "pg-full", 6)
    r = client.get("/grc/risks", params={"tenant_id": "pg-full", "limit": 3})
    assert r.headers["X-Returned"] == r.headers["X-Limit"] == "3"

    rest = client.get("/grc/risks", params={"tenant_id": "pg-full", "limit": 100, "offset": 3})
    assert int(rest.headers["X-Returned"]) < int(rest.headers["X-Limit"])


def test_offset_past_the_end_is_an_empty_page_not_an_error(client):
    r = client.get("/grc/risks", params={"tenant_id": "pg-rank", "limit": 10, "offset": 10_000})
    assert r.status_code == 200
    assert r.json() == []
    assert r.headers["X-Returned"] == "0"


def test_pagination_headers_are_exposed_to_cross_origin_callers():
    """The dashboard's API base is configurable, so it is often cross-origin.
    A browser hides response headers from JS unless the server lists them, and
    the partial-list warning is driven entirely by these headers — unexposed,
    it would silently never fire."""
    from app.main import app
    cors = [m for m in app.user_middleware if "CORS" in str(m)]
    assert cors, "CORS middleware is not installed"
    # Starlette has moved this attribute between releases (options -> kwargs),
    # so read whichever this version provides rather than pinning to one.
    opts = getattr(cors[0], "kwargs", None) or getattr(cors[0], "options", None) or {}
    exposed = opts.get("expose_headers") or []
    if not exposed:  # last resort for a future rename: the repr still shows it
        exposed = str(cors[0])
    for h in ("X-Limit", "X-Offset", "X-Returned"):
        assert h in exposed, f"{h} is not exposed to cross-origin callers"


def test_internal_callers_still_get_everything(client):
    """Services default to unbounded so exports and the scheduler's own scans
    are unaffected by the API's default window."""
    from app.database import SessionLocal
    from app.services.grc_tprm import RiskService
    db = SessionLocal()
    try:
        assert len(RiskService(db).list("pg-walk")) == 12
    finally:
        db.close()
