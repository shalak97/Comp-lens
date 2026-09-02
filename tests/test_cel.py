"""The CEL evaluator, and the guarantee it exists to provide.

Check expressions are the part of the check pack that carries semantics, so the
language they are written in matters. They used to be parsed by Python's own
parser under an AST allowlist, which made the pack's language "whatever subset
of Python the allowlist permits" — safe, but not something a customer or
auditor can look up. They are now real CEL.

The most load-bearing tests here are in ReDoS. CEL's matches() takes a
user-supplied pattern, and Python's re backtracks, so (a+)+$ against a
non-matching string runs in exponential time. That is why cel-python depends on
google-re2, which is unbuildable here. The property wanted from re2 is
algorithmic rather than linguistic — a Thompson NFA has no backtracking to
exploit — so matches() is implemented that way and the old heuristic that tried
to guess which patterns were dangerous is not needed.
"""
from __future__ import annotations

import time

import pytest

from app.policy_as_code.cel import CELError, evaluate, regex_search


# ── literals, operators, precedence ──
@pytest.mark.parametrize(("expr", "want"), [
    ("1 + 2 * 3", 7),
    ("(1 + 2) * 3", 9),
    ("10 / 3", 3),          # integer division for ints, per the spec
    ("10.0 / 4", 2.5),
    ("7 % 3", 1),
    ("-5 + 2", -3),
    ("true && false", False),
    ("true || false", True),
    ("!true", False),
    ("1 < 2 && 2 <= 2", True),
    ("3 > 4 || 4 >= 4", True),
    ("'a' == 'a'", True),
    ("'a' != 'b'", True),
    ("null == null", True),
    ("true ? 'yes' : 'no'", "yes"),
    ("false ? 'yes' : 'no'", "no"),
])
def test_operators(expr, want):
    assert evaluate(expr, {}) == want


@pytest.mark.parametrize(("expr", "want"), [
    ("size('abcd')", 4),
    ("size([1, 2, 3])", 3),
    ("size({'a': 1})", 1),
    ("[1, 2, 3][1]", 2),
    ("{'k': 'v'}['k']", "v"),
    ("2 in [1, 2, 3]", True),
    ("9 in [1, 2, 3]", False),
    ("'x' in {'x': 1}", True),
    ("'abc'.startsWith('ab')", True),
    ("'abc'.endsWith('bc')", True),
    ("'abc'.contains('b')", True),
    ("'AbC'.lower()", "abc"),
    ("string(true)", "true"),
    ("int('42')", 42),
    ("abs(-5)", 5),
    ("min([3, 1, 2])", 1),
    ("max(4, 9)", 9),
])
def test_standard_functions(expr, want):
    assert evaluate(expr, {}) == want


@pytest.mark.parametrize(("expr", "want"), [
    ("all([1, 2, 3], x, x > 0)", True),
    ("all([1, -2], x, x > 0)", False),
    ("exists([1, -2], x, x < 0)", True),
    ("exists_one([1, -2, -3], x, x < 0)", False),
    ("exists_one([1, -2, 3], x, x < 0)", True),
    ("filter([1, 2, 3, 4], x, x % 2 == 0)", [2, 4]),
    ("map([1, 2, 3], x, x * 2)", [2, 4, 6]),
])
def test_macros(expr, want):
    assert evaluate(expr, {}) == want


def test_field_selection_navigates_maps_not_python_objects():
    assert evaluate("a.b.c", {"a": {"b": {"c": 42}}}) == 42
    assert evaluate("has(a.b)", {"a": {"b": 1}}) is True
    assert evaluate("has(a.z)", {"a": {"b": 1}}) is False


def test_short_circuit():
    """&& and || must not evaluate the far side when the near side decides it,
    or an expression guarding a missing key would raise instead of answering."""
    assert evaluate("false && missing.key == 1", {}) is False
    assert evaluate("true || missing.key == 1", {}) is True


# ── the security boundary ──
@pytest.mark.parametrize("expr", [
    "__import__('os')",
    "().__class__",
    "a.b.__dict__",
    "open('/etc/passwd')",
    "exec('x')",
    "lambda: 1",
    "1 +",
    "[1, 2",
    "'unterminated",
    "1 ; 2",
])
def test_rejects_what_is_not_cel(expr):
    with pytest.raises(CELError):
        evaluate(expr, {"a": {"b": {}}})


def test_unknown_identifier_is_an_error_not_a_silent_false():
    """A typo in a signal name must surface. Treating an unknown name as falsy
    would turn a misspelt check into a permanent, quiet FAIL."""
    with pytest.raises(CELError):
        evaluate("nosuchsignal == true", {"real": True})


def test_non_bool_comparisons_are_rejected():
    with pytest.raises(CELError):
        evaluate("true < false", {})


# ── regex: correctness ──
@pytest.mark.parametrize(("pattern", "text", "want"), [
    ("abc", "xxabcxx", True),
    ("^abc", "abcdef", True),
    ("^abc", "xabc", False),
    ("abc$", "xxabc", True),
    ("abc$", "abcx", False),
    ("a.c", "abc", True),
    ("a.c", "ac", False),
    ("a*b", "b", True),
    ("a+b", "b", False),
    ("colou?r", "color", True),
    ("colou?r", "colour", True),
    ("cat|dog", "hotdog", True),
    ("cat|dog", "bird", False),
    ("[abc]+", "xxbbxx", True),
    ("[^abc]", "abc", False),
    ("[a-z]+[0-9]", "abc7", True),
    (r"\d+", "abc123", True),
    (r"^\d+$", "12345", True),
    (r"^\d+$", "12a45", False),
    (r"\w+@\w+", "a@b", True),
    (r"\s", "a b", True),
    (r"\S+", "   ", False),
    ("^$", "", True),
    ("(ab)+c", "ababc", True),
    ("(a|b)*c", "abbac", True),
])
def test_regex_matches(pattern, text, want):
    assert regex_search(pattern, text) is want


def test_matches_is_reachable_from_cel():
    assert evaluate("'a1'.matches('^[a-z][0-9]$')", {}) is True
    assert evaluate("'ab'.matches('^[a-z][0-9]$')", {}) is False


# ── regex: the ReDoS guarantee ──
@pytest.mark.parametrize("pattern", [
    "(a+)+$",           # the canonical catastrophic pattern
    "^(a|aa)*$",        # ambiguous alternation, anchored so it cannot match
    "(a*)*b",           # nested star
    "(a+)+(b+)+$",      # two of them
])
def test_pathological_patterns_stay_linear(pattern):
    """These are the patterns that make a backtracking engine hang.

    Python's re on "(a+)$" with 40 a's and a trailing '!' does not finish in
    any practical time. A Thompson NFA has no backtracking, so the same input
    is ordinary work. The bound here is generous — the point is that it
    terminates at all, not the exact figure.
    """
    # Each pattern is chosen so it cannot match this text, which is the case a
    # backtracking engine explores exhaustively before giving up. Note the
    # anchoring on the alternation case: "(a|aa)*$" alone *does* match here,
    # because (a|aa)* accepts the empty string and $ is then satisfied at the
    # end — verified against Python's own re, which agrees.
    text = "a" * 60 + "!"
    started = time.monotonic()
    assert regex_search(pattern, text) is False
    assert time.monotonic() - started < 1.0, "pattern did not run in linear time"


def test_long_input_against_a_pathological_pattern():
    """Doubling the input should roughly double the work, not square it."""
    pattern = "(a+)+$"
    short = "a" * 200 + "!"
    long_text = "a" * 400 + "!"

    t0 = time.monotonic()
    regex_search(pattern, short)
    short_time = time.monotonic() - t0

    t0 = time.monotonic()
    regex_search(pattern, long_text)
    long_time = time.monotonic() - t0

    # Linear would be ~2x. Allow generous slack for timer noise on a shared
    # runner; an exponential engine would not return at all.
    assert long_time < max(short_time * 20, 0.5)


def test_absurd_patterns_are_bounded_rather_than_parsed_forever():
    with pytest.raises(CELError):
        regex_search("a" * 1000, "aaa")


# ── the real check pack ──
def test_pack_declares_cel_and_every_expression_parses():
    from app.policy_as_code.cel import parse
    from app.services import control_checks

    assert control_checks.expression_language() == "cel"
    for cid, check in control_checks.all_checks().items():
        try:
            parse(check.expression)
        except CELError as exc:
            pytest.fail(f"{cid} is not valid CEL: {check.expression!r} — {exc}")


def test_no_expression_uses_python_boolean_keywords():
    """`and`/`or`/`not` are Python, not CEL. An expression using them parses as
    an identifier reference and fails at evaluation, so catch it in the pack."""
    import re

    from app.services import control_checks

    offenders = [cid for cid, c in control_checks.all_checks().items()
                 if re.search(r"\b(and|or|not)\b", c.expression)]
    assert not offenders, f"expressions using Python keywords instead of && || !: {offenders}"
