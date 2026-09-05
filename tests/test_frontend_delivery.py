"""The dashboard is delivered efficiently, and correctly.

Three things were costing every page load, none of them visible in the code:

  * Nothing compressed anything. The dashboard is one 262 KB HTML file and
    gzips to 74 KB — 188 KB on every cold load — and the JSON list endpoints
    compress comparably, a page of findings being highly repetitive.
  * The Google Fonts stylesheet was render-blocking: a third-party round trip
    completed before a single pixel appeared.
  * /dashboard sent no Cache-Control, so browsers applied heuristic freshness
    and could keep serving the previous dashboard against a new API after a
    deploy, for an interval nobody chose.

The compression tests drive the middleware as plain ASGI rather than through
the app, because what needs pinning is the skip logic — a response that is
already compressed, already encoded, streaming, or too small must come back
byte-identical, and only the app-level test would not tell us which.
"""
from __future__ import annotations

import asyncio
import gzip
import pathlib
import re

import pytest

from app.hardening import CompressibleGZipMiddleware

STATIC = pathlib.Path(__file__).resolve().parent.parent / "app" / "static"
DASHBOARD = STATIC / "dashboard.html"

BIG_JSON = b'{"findings":[' + b'{"control_id":"AC-2","status":"fail"},' * 400 + b"]}"


def _app(body, ctype="application/json", extra=None, chunks=None):
    async def app(scope, receive, send):
        headers = [(b"content-type", ctype.encode()),
                   (b"content-length", str(len(body)).encode())]
        headers += (extra or [])
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        for i, chunk in enumerate(chunks or [body]):
            await send({"type": "http.response.body", "body": chunk,
                        "more_body": i < len(chunks or [body]) - 1})
    return app


def _run(app, accept="gzip, deflate", minimum_size=800):
    messages: list[dict] = []

    async def send(m):
        messages.append(m)

    async def receive():
        return {"type": "http.request"}

    scope = {"type": "http",
             "headers": [(b"accept-encoding", accept.encode())] if accept else []}
    asyncio.run(CompressibleGZipMiddleware(app, minimum_size=minimum_size)(
        scope, receive, send))
    start = next(m for m in messages if m["type"] == "http.response.start")
    headers = {k.decode().lower(): v.decode() for k, v in start["headers"]}
    body = b"".join(m.get("body", b"") for m in messages
                    if m["type"] == "http.response.body")
    return headers, body


# ── it compresses what is worth compressing ──
def test_a_large_json_response_is_compressed():
    headers, body = _run(_app(BIG_JSON))
    assert headers["content-encoding"] == "gzip"
    assert gzip.decompress(body) == BIG_JSON, "the body must survive intact"
    assert len(body) < len(BIG_JSON) / 2


def test_the_dashboard_is_compressed_and_the_saving_is_real():
    raw = DASHBOARD.read_bytes()
    headers, body = _run(_app(raw, "text/html"))
    assert headers["content-encoding"] == "gzip"
    assert gzip.decompress(body) == raw
    # It measured 72% when this was written; assert the property, not the number.
    assert len(body) < len(raw) * 0.45, (
        f"dashboard only compressed {len(raw)} -> {len(body)}")


def test_the_declared_length_matches_the_body_actually_sent():
    """A Content-Length left over from the uncompressed body truncates the
    response — the failure mode that makes compression bugs look like data
    corruption."""
    headers, body = _run(_app(BIG_JSON))
    assert int(headers["content-length"]) == len(body)


def test_a_compressed_response_varies_on_accept_encoding():
    """Without this a shared cache can hand a gzipped body to a client that
    never asked for one."""
    headers, _ = _run(_app(BIG_JSON))
    assert headers["vary"] == "Accept-Encoding"


# ── and leaves alone what is not ──
def test_a_client_that_did_not_ask_for_gzip_does_not_get_it():
    headers, body = _run(_app(BIG_JSON), accept="")
    assert "content-encoding" not in headers
    assert body == BIG_JSON


@pytest.mark.parametrize("ctype", [
    "application/gzip",     # /enforcement/bundle serves a .tar.gz
    "application/zip",
    "application/pdf",      # compliance reports
    "image/png",
    "font/woff2",
])
def test_an_already_compressed_media_type_is_passed_through(ctype):
    """Gzipping these spends CPU to make the body very slightly bigger."""
    payload = gzip.compress(b"x" * 5000)
    headers, body = _run(_app(payload, ctype))
    assert "content-encoding" not in headers
    assert body == payload, "an already-compressed body must be byte-identical"


def test_a_response_that_set_its_own_encoding_is_not_re_encoded():
    headers, body = _run(_app(BIG_JSON, extra=[(b"content-encoding", b"br")]))
    assert headers["content-encoding"] == "br"
    assert body == BIG_JSON


def test_a_small_response_is_not_compressed():
    small = b'{"ok":true}'
    headers, body = _run(_app(small))
    assert "content-encoding" not in headers
    assert body == small


def test_a_streaming_response_is_never_buffered():
    """Buffering a streamed response to compress it defeats the reason it was
    streamed. Nothing streams today; this keeps that true if something starts."""
    headers, body = _run(_app(BIG_JSON, chunks=[BIG_JSON[:5000], BIG_JSON[5000:]]))
    assert "content-encoding" not in headers
    assert body == BIG_JSON


def test_a_non_http_scope_is_passed_straight_through():
    seen = []

    async def app(scope, receive, send):
        seen.append(scope["type"])

    async def send(m):
        pass

    async def receive():
        return {}

    asyncio.run(CompressibleGZipMiddleware(app)({"type": "lifespan"}, receive, send))
    assert seen == ["lifespan"]


# ── the dashboard's own delivery ──
def test_the_font_stylesheet_does_not_block_the_first_paint():
    """Two properties, asserted without naming how they are achieved.

    An earlier version of this test looked for the literal `this.media='all'`,
    which pinned the *mechanism* — an inline load handler on the link. When CSP
    made that mechanism illegal and the swap moved into a script, the test
    failed on a change that was strictly an improvement. A test that names an
    implementation goes off the moment the implementation is corrected, which
    is the opposite of what it is for.
    """
    html = DASHBOARD.read_text()
    # Match the whole tag, not a line: the attributes are wrapped across two.
    link = next((m.group(0) for m in re.finditer(r"<link\b[^>]*>", html)
                 if "fonts.googleapis.com/css2" in m.group(0)
                 and "stylesheet" in m.group(0)), None)
    assert link is not None, "the webfont stylesheet link has gone"
    # 1. it must not be a plain render-blocking stylesheet
    assert 'media="print"' in link, (
        f"the Google Fonts stylesheet is render-blocking again: {link.strip()[:120]}")
    # 2. something must promote it, or the fonts never apply at all
    assert 'media="all"' in html or "media='all'" in html or '.media = "all"' in html, (
        "nothing promotes the stylesheet past media=print — the page would "
        "render in fallback faces forever")
    assert "<noscript>" in html, "no fallback for a browser with JS disabled"


def test_every_webfont_family_has_a_real_fallback():
    """The deferred stylesheet is only safe because the first paint uses a
    system face rather than nothing."""
    html = DASHBOARD.read_text()
    for var, fallback in (("--sans", "system-ui"), ("--mono", "ui-monospace")):
        line = next(ln for ln in html.splitlines() if ln.strip().startswith(var + ":"))
        assert fallback in line, f"{var} has no system fallback: {line.strip()}"
    # --grot falls back through --sans, which is checked above.
    assert "--grot:" in html and "var(--sans)" in html


def test_the_font_request_still_asks_for_the_weights_the_css_uses():
    """A trimmed weight silently renders as a synthesised bold or a wrong face."""
    html = DASHBOARD.read_text()
    used = {w for w in ("400", "500", "600", "700")
            if f"font-weight:{w}" in html.replace(" ", "")}
    request = next(ln for ln in html.splitlines() if "fonts.googleapis.com/css2" in ln)
    for weight in used:
        assert weight in request, f"CSS uses font-weight {weight}, not requested"


def test_the_dashboard_is_served_with_explicit_revalidation():
    """With no Cache-Control a browser invents its own freshness window, so a
    deploy does not reliably reach the people already using the dashboard."""
    import inspect

    from app import main
    src = inspect.getsource(main)
    marker = src.index('@app.get("/dashboard"')
    body = src[marker:marker + 1200]
    assert "Cache-Control" in body and "no-cache" in body
