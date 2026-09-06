"""The consoles run under a script policy the browser enforces.

Removing the inline handlers (see test_dashboard_xss) took the data out of code
positions. This is the other half: a policy that makes an injected `<script>`
or an injected event attribute inert rather than merely unlikely.

`script-src` names each inline block by its sha256 and nothing else — no
'unsafe-inline', no 'unsafe-eval'. That choice is what forced every `on*=""`
attribute out first: a hash covers a `<script>` element and never an attribute,
so any handler left behind would simply not run. A dead button is a loud
failure, which is the right way round, but the tests below make sure we never
ship one.

`style-src` keeps 'unsafe-inline', and that is a stated limitation rather than
an oversight — the dashboard carries 283 `style=""` attributes and removing
them is a CSS refactor that buys nothing against script execution.

Verified in real Chromium over HTTP with the header attached: zero
securitypolicyviolation events, every inline script executed (checked by
probing for functions each block defines), and a delegated click dispatched.
CI has no browser, so what CI holds is the shape of the policy and the absence
of anything the policy would kill.
"""
from __future__ import annotations

import base64
import hashlib
import pathlib
import re

import pytest

from app.hardening import csp_for

STATIC = pathlib.Path(__file__).resolve().parent.parent / "app" / "static"
#: The consoles the app serves with a CSP header.
CONSOLES = ["dashboard.html", "evidence-map.html"]

_INLINE_SCRIPT = re.compile(rb"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S)
_EVENT_ATTR = re.compile(r"""\son(?:click|change|load|error|input|submit|focus|blur|
                              mouseover|mouseout|keydown|keyup)\s*=\s*["']""",
                         re.X | re.I)


@pytest.mark.parametrize("name", CONSOLES)
def test_a_console_has_no_inline_event_handlers(name):
    """Under `script-src 'sha256-...'` an event attribute does not run. Any that
    survive are dead controls, and were also the XSS surface."""
    text = (STATIC / name).read_text()
    offenders = []
    for m in _EVENT_ATTR.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        context = text[max(0, m.start() - 120):m.start()]
        if "used to be an onload" in context or "used to carry an inline" in context:
            continue        # prose describing the removal
        offenders.append(f"line {line}: {text[m.start():m.start() + 70]!r}")
    assert not offenders, (
        f"{name} still has inline event handlers, which CSP will refuse to run:\n  "
        + "\n  ".join(offenders))


@pytest.mark.parametrize("name", CONSOLES)
def test_the_policy_hashes_every_inline_script(name):
    """A missed block means a blank console, so this counts them."""
    html = (STATIC / name).read_bytes()
    blocks = _INLINE_SCRIPT.findall(html)
    assert blocks, f"{name} has no inline scripts — has its structure changed?"
    policy = csp_for(html)
    for body in blocks:
        want = base64.b64encode(hashlib.sha256(body).digest()).decode()
        assert f"'sha256-{want}'" in policy, (
            f"{name}: an inline script is not covered by the policy")


@pytest.mark.parametrize("name", CONSOLES)
def test_the_script_policy_admits_nothing_but_those_hashes(name):
    html = (STATIC / name).read_bytes()
    directive = next(d for d in csp_for(html).split("; ") if d.startswith("script-src"))
    for hole in ("'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "*", "http:", "https:"):
        assert hole not in directive, f"{name}: script-src admits {hole}"
    assert directive.count("'sha256-") == len(_INLINE_SCRIPT.findall(html))


def test_a_hash_changes_when_the_script_changes():
    """The policy is computed from the file that is served, so it cannot drift
    from the page. If this ever stopped holding, an edit would silently ship a
    console the browser refuses to run."""
    before = csp_for(b"<html><script>var a=1;</script></html>")
    after = csp_for(b"<html><script>var a=2;</script></html>")
    assert before != after


def test_an_external_script_is_not_hashed():
    """A hash is meaningless for a src= script and would be noise in the header."""
    policy = csp_for(b'<html><script src="/static/x.js"></script></html>')
    assert "'sha256-" not in policy


@pytest.mark.parametrize("directive", [
    "default-src 'none'",
    "base-uri 'none'",        # an injected <base> re-points every relative URL
    "form-action 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
])
def test_the_policy_closes_the_other_common_holes(directive):
    policy = csp_for((STATIC / "dashboard.html").read_bytes())
    assert directive in policy


def test_the_fonts_are_still_reachable_under_the_policy():
    """The dashboard loads its webfonts from Google. A policy that forgot them
    would render in fallback faces forever — and silently, since a blocked
    stylesheet is not a JS error."""
    policy = csp_for((STATIC / "dashboard.html").read_bytes())
    assert "https://fonts.googleapis.com" in policy
    assert "https://fonts.gstatic.com" in policy


def test_style_src_documents_its_own_limitation():
    """'unsafe-inline' for styles is a deliberate trade, so it should not look
    like an accident to the next reader."""
    policy = csp_for((STATIC / "dashboard.html").read_bytes())
    style = next(d for d in policy.split("; ") if d.startswith("style-src"))
    assert "'unsafe-inline'" in style
    assert "unsafe-inline" in csp_for.__doc__, "the trade-off is undocumented"


def test_a_configured_api_origin_reaches_connect_src():
    """The dashboard's API base is user-configurable; pinning connect-src to
    'self' would break a hosted console pointed at its own API."""
    policy = csp_for(b"<html></html>", connect_extra="https://api.example.com")
    connect = next(d for d in policy.split("; ") if d.startswith("connect-src"))
    assert "'self'" in connect and "https://api.example.com" in connect


def test_the_font_stylesheet_is_promoted_by_a_script_not_an_attribute():
    """It was promoted by onload="", which CSP refuses to run — the fonts would
    never load past media="print". The swap moved into a hashed script."""
    text = (STATIC / "dashboard.html").read_text()
    assert 'id="webfonts"' in text
    link = next(ln for ln in text.splitlines() if 'id="webfonts"' in ln)
    assert "onload" not in link, "the font link still relies on an inline handler"
    assert 'l.media="all"' in text or "l.media='all'" in text
