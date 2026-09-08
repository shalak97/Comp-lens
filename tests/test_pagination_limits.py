"""A partial inventory must never look like a whole one.

Iteration 6 of a fault-finding sweep, instrument: error paths and resource
limits.

`ResilientClient.get_all_pages` is the good version of this and was already
right: it follows the RFC 5988 cursor, detects a self-referential next link,
applies the caller's params to the first request only, and — the part that
matters — RAISES when it hits its page cap rather than returning a short list.
A connector that enumerates a slice of an estate and reports on it as though it
were the estate is the failure this platform exists to catch, committed by the
platform itself.

Two things this iteration changed.

**`paginate()` is gone.** It was a second pagination helper in the same module
that followed body cursors and stopped at 20 pages by returning what it had,
silently. It had no callers — Okta and GitHub both use get_all_pages — so this
removes dead code rather than changing behaviour. It is deleted rather than
fixed because two helpers side by side, one of which quietly truncates, is a
trap: the next connector author picks by name, and `paginate` is the friendlier
name.

**`get_all_pages` gained a wall-clock budget.** The page cap alone did not
bound it. Every individual request is bounded — 15s timeout, four attempts, a
breaker that opens after five failures — but the composition was not, and the
breaker only helps when calls FAIL. A server that answers slowly and
successfully trips nothing: 200 pages at 15s each is fifty minutes holding one
of FastAPI's ~40 threadpool slots, with no error anywhere to show for it.

Both limits raise. That is the same choice made consistently: a compliance
verdict computed over a truncated estate is worse than a sync that failed and
said so.
"""
from __future__ import annotations

import inspect
import pathlib

import pytest

from app.connectors import http_client
from app.connectors.http_client import ConnectorError, ResilientClient

ROOT = pathlib.Path(__file__).resolve().parent.parent


# ── the helper that truncated silently is gone ──
def test_the_silently_truncating_pagination_helper_is_gone():
    assert not hasattr(http_client, "paginate"), (
        "paginate() returned a short list when it hit its page cap, with "
        "nothing in the result saying so — the exact failure get_all_pages "
        "exists to refuse. Two helpers, one of which truncates quietly, is a "
        "trap for whoever writes the next connector.")


def test_no_connector_grew_a_replacement_that_truncates_quietly():
    """The class rather than the instance: any pagination loop that stops at a
    cap must raise, not return what it happens to have."""
    offenders = []
    for path in (ROOT / "app" / "connectors").glob("*.py"):
        src = path.read_text()
        if "max_pages" not in src:
            continue
        # every function mentioning a page cap must also refuse to truncate
        if "refusing to return a partial inventory" not in src:
            offenders.append(path.name)
    assert not offenders, (
        f"these cap pagination without refusing to truncate: {offenders}")


# ── the budget ──
def test_get_all_pages_takes_a_wall_clock_budget():
    sig = inspect.signature(ResilientClient.get_all_pages)
    assert "max_seconds" in sig.parameters
    assert sig.parameters["max_seconds"].default > 0


def test_a_slow_but_successful_server_cannot_hold_a_worker_indefinitely(monkeypatch):
    """The case the circuit breaker does not cover. It opens on FAILURES; a
    server that answers slowly and correctly trips nothing, so only a deadline
    bounds the loop."""
    client = ResilientClient("SLOWCORP", timeout=1)
    clock = {"t": 0.0}
    monkeypatch.setattr(http_client.time, "monotonic", lambda: clock["t"])
    page_no = iter(range(10_000))

    class _Resp:
        status_code = 200

        def __init__(self):
            # A DISTINCT next link each time, so the loop genuinely advances
            # and the deadline is what stops it. An earlier version of this
            # test reused one URL and tripped the cycle detector instead —
            # proving that guard works, and nothing about this one.
            self.headers = {"Link": f'<https://x/p{next(page_no)}>; rel="next"'}

        @staticmethod
        def json():
            clock["t"] += 20.0        # each page takes 20 seconds
            return [{"id": 1}]

    monkeypatch.setattr(client, "_send", lambda *a, **kw: _Resp())
    with pytest.raises(ConnectorError) as excinfo:
        client.get_all_pages("https://x/start", max_pages=200, max_seconds=60)
    message = str(excinfo.value)
    assert "partial inventory" in message
    assert "still paging" in message


def test_the_page_cap_still_refuses_rather_than_truncating(monkeypatch):
    """The behaviour that was already correct, pinned so the budget did not
    quietly replace it."""
    client = ResilientClient("LOOPY", timeout=1)
    pages = iter(range(10_000))

    class _Resp:
        status_code = 200

        def __init__(self):
            self.headers = {"Link": f'<https://x/p{next(pages)}>; rel="next"'}

        @staticmethod
        def json():
            return [{"id": 1}]

    monkeypatch.setattr(client, "_send", lambda *a, **kw: _Resp())
    with pytest.raises(ConnectorError) as excinfo:
        client.get_all_pages("https://x/start", max_pages=3, max_seconds=3600)
    assert "partial inventory" in str(excinfo.value)


def test_a_normal_collection_is_unaffected(monkeypatch):
    """Limits that fire on ordinary use would be worse than the bug."""
    client = ResilientClient("FINE", timeout=1)
    seq = [
        ({"Link": '<https://x/p2>; rel="next"'}, [{"id": 1}, {"id": 2}]),
        ({}, [{"id": 3}]),
    ]
    calls = {"n": 0}

    class _Resp:
        def __init__(self):
            self.headers, self._body = seq[calls["n"]]
            calls["n"] += 1
            self.status_code = 200

        def json(self):
            return self._body

    monkeypatch.setattr(client, "_send", lambda *a, **kw: _Resp())
    assert client.get_all_pages("https://x/p1") == [{"id": 1}, {"id": 2}, {"id": 3}]


def test_a_pagination_loop_is_still_detected(monkeypatch):
    client = ResilientClient("LOOP", timeout=1)

    class _Resp:
        status_code = 200
        headers = {"Link": '<https://x/same>; rel="next"'}

        @staticmethod
        def json():
            return [{"id": 1}]

    monkeypatch.setattr(client, "_send", lambda *a, **kw: _Resp())
    with pytest.raises(ConnectorError) as excinfo:
        client.get_all_pages("https://x/same")
    assert "pagination loop" in str(excinfo.value)


# ── what was checked and found sound ──
def test_every_outbound_call_carries_a_timeout():
    """Swept in this iteration: one apparent exception turned out to be a call
    through ResilientClient, which applies its own. Pinned so a raw
    requests.get cannot appear later."""
    import ast
    import re

    offenders = []
    for path in (ROOT / "app").rglob("*.py"):
        if "__pycache__" in str(path):
            continue
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = ast.unparse(node.func)
            if not re.fullmatch(r"(requests|session|self\.session)\."
                                r"(get|post|put|patch|delete|request)", func):
                continue
            if "timeout" not in {k.arg for k in node.keywords}:
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} {func}")
    assert not offenders, (
        "an outbound call with no timeout can hold a worker forever:\n  "
        + "\n  ".join(offenders))
