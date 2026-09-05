"""Server data never reaches the dashboard in a code position.

The dashboard built event handlers by interpolating server data into a JS
string inside an HTML attribute:

    onclick="setFindingLifecycle('${esc(f.finding_id)}','resolved')"

26 handlers were built that way. `esc()` escaped & < > " but not ', so a
finding id of

    x');alert(document.domain);//

closed the string and ran as script. Those ids come from connectors — an asset
name, a vendor name, a control id — so anything able to name an object in the
customer's own estate could run script in an operator's browser. Stored XSS in
a compliance tool.

The obvious patch does NOT work, and this is the part worth remembering: a
browser HTML-decodes an event attribute BEFORE parsing it as JavaScript, so
escaping the quote as &#39; still yields a real quote by the time the JS
parser sees it. Verified in Chromium — the payload ran either way. There is no
escaping function that makes data-inside-code safe here.

So the data moved out of the code position entirely: the element names an
action and carries its arguments as JSON in a data attribute, and a delegated
listener reads them with getAttribute + JSON.parse, which cannot execute
anything.

These are static assertions against the file. The behavioural proof needs a
browser, and was run against real Chromium during development: the dashboard
loads with zero JS errors, the injected payload does not execute, and the
hostile string arrives at the handler intact as an argument. CI has no
browser, so what CI guards is that the *pattern* cannot come back.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

DASHBOARD = (pathlib.Path(__file__).resolve().parent.parent
             / "app" / "static" / "dashboard.html")
HTML = DASHBOARD.read_text()

#: `onclick="foo('${bar}')"` — data interpolated inside a quoted JS string in
#: an event attribute. The shape that was exploitable.
_DATA_IN_HANDLER = re.compile(r"""\son(?:click|change|load|input|submit)="[^"]*\$\{""")


def test_no_event_attribute_interpolates_data():
    """The regression itself.

    Every hit here is a place where server data is being written into a
    position the browser will parse as JavaScript.
    """
    offenders = []
    for m in _DATA_IN_HANDLER.finditer(HTML):
        line = HTML.count("\n", 0, m.start()) + 1
        snippet = HTML[m.start():m.start() + 90].replace("\n", " ")
        # The module comment documenting the old bug quotes the pattern.
        if "What was here instead" in HTML[max(0, m.start() - 200):m.start()]:
            continue
        offenders.append(f"line {line}: {snippet}")
    assert not offenders, (
        "server data is being interpolated into an event attribute, which the "
        "browser parses as JavaScript. Use act(name, ...args) instead:\n  "
        + "\n  ".join(offenders))


def test_esc_escapes_every_character_that_can_close_a_quoted_context():
    """esc() alone never made the handlers safe, but it is still what guards
    ordinary attribute values, and it was missing both quote characters."""
    body = re.search(r"function esc\(s\)\{.*?\n.*?\}", HTML, re.S).group(0)
    for ch, entity in (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"),
                       ('"', "&quot;"), ("'", "&#39;"), ("`", "&#96;")):
        assert entity in body, f"esc() does not produce {entity} for {ch!r}"
    charclass = re.search(r"replace\(/\[([^\]]+)\]/g", body).group(1)
    for ch in "&<>\"'`":
        assert ch in charclass, f"esc() does not match {ch!r}"


# ── the delegation contract ──
def _allowlist() -> set[str]:
    block = re.search(r"const ACTION_NAMES = new Set\(\[(.*?)\]\);", HTML, re.S).group(1)
    return set(re.findall(r'"([^"]+)"', block))


def _emitted() -> set[str]:
    return set(re.findall(r'act\(\s*"([A-Za-z_$][\w$]*)"', HTML))


def test_every_emitted_action_is_allowlisted():
    """The router refuses an action it does not know, so an unlisted name is a
    silently dead control rather than a security hole — but dead controls are
    their own bug."""
    stray = _emitted() - _allowlist()
    assert not stray, f"act() emits actions the router will refuse: {sorted(stray)}"


def test_every_allowlisted_action_exists():
    """The mirror: an allowlisted name with no function behind it is a button
    that does nothing when clicked."""
    missing = []
    for name in _allowlist():
        n = re.escape(name)
        if re.search(rf"function\s+{n}\s*\(", HTML):
            continue
        if re.search(rf"(?:const|let|var)\s+{n}\s*=", HTML):
            continue
        if re.search(rf"window\.{n}\s*=", HTML):      # assigned at runtime
            continue
        missing.append(name)
    assert not missing, f"allowlisted actions with no definition: {sorted(missing)}"


def test_the_router_never_evaluates_the_payload():
    """`data-args` must be read and parsed, never executed. eval/Function/
    setTimeout-with-a-string on that value would reintroduce the whole bug."""
    router = HTML[HTML.index('document.addEventListener("click"'):]
    router = router[:router.index("\n});") + 4]
    assert "JSON.parse" in router, "the router no longer parses its arguments"
    for forbidden in ("eval(", "new Function", "innerHTML"):
        assert forbidden not in router, f"router uses {forbidden}"


def test_arguments_survive_the_round_trip_intact():
    """A hostile value must reach the handler unchanged — it is a legitimate,
    if strange, identifier. Mangling it would be a different bug.

    This reproduces what the browser does: esc() on write, HTML-decode on
    read, JSON.parse to recover the arguments.
    """
    import html as html_mod

    hostile = "x');alert(document.domain);//"
    payload = json.dumps([hostile, "resolved"])
    # what esc() writes into the attribute
    written = (payload.replace("&", "&amp;").replace("<", "&lt;")
               .replace(">", "&gt;").replace('"', "&quot;")
               .replace("'", "&#39;").replace("`", "&#96;"))
    # what getAttribute returns, then JSON.parse
    assert json.loads(html_mod.unescape(written)) == [hostile, "resolved"]


def test_drow_takes_attributes_rather_than_a_code_string():
    """drow(html, onclick) took a JS string that two call sites built by
    interpolating a control id into it."""
    sig = re.search(r"function drow\([^)]*\)\{[^\n]*", HTML).group(0)
    assert "onclick" not in sig, f"drow still takes a code string: {sig}"
    for call in re.findall(r"drow\(`[^`]*`\s*,\s*([^)]{0,40})", HTML):
        assert call.strip().startswith("act("), (
            f"drow called with something other than act(...): {call!r}")


@pytest.mark.parametrize("name", [
    "setFindingLifecycle", "createTicket", "instDelete", "syncGrcPlatform",
    "enfSetMode", "openFindingByControl",
])
def test_the_handlers_that_carried_identifiers_are_delegated(name):
    """Spot-check the specific handlers that were exploitable."""
    assert f'act("{name}"' in HTML, f"{name} is no longer wired through act()"
    assert f'onclick="{name}(' not in HTML, f"{name} still has an inline handler"
