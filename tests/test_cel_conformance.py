"""CEL means what the CEL spec says it means.

The pack is written in CEL rather than a Python subset for one reason: the
language is published, so a customer or auditor can look up what an expression
does and an engineer can check it against any conformant implementation. That
argument only holds while this engine agrees with the spec, and it did not.

The engine evaluated CEL by handing operands to Python's operators, which
differ from CEL's in three ways that all pass unnoticed until someone writes an
expression with a negative number in it:

    -7 / 2   Python floors to -4;  CEL truncates toward zero, so -3.
    -7 % 2   Python takes the divisor's sign and gives 1; CEL takes the
             dividend's and gives -1.
    true + 1 Python makes bool a subclass of int and gives 2; CEL has no such
             overload and it is a type error. Likewise 'a' * 2.

No expression in the current pack does arithmetic, so none of this has produced
a wrong compliance result. It is a latent bug in the part of the system whose
whole justification is that its behaviour is looked-up rather than discovered.
"""
from __future__ import annotations

import pytest

from app.policy_as_code.cel import CELError, evaluate


# ── integer division truncates toward zero ──
@pytest.mark.parametrize(("expr", "want"), [
    ("7 / 2", 3),
    ("-7 / 2", -3),        # Python's // gives -4
    ("7 / -2", -3),
    ("-7 / -2", 3),
    ("1 / 2", 0),
    ("-1 / 2", 0),         # Python's // gives -1
    ("-1 / 10", 0),
])
def test_integer_division_truncates_toward_zero(expr, want):
    assert evaluate(expr, {}) == want


@pytest.mark.parametrize(("expr", "want"), [
    ("7 % 2", 1),
    ("-7 % 2", -1),        # Python's % gives 1
    ("7 % -2", 1),         # Python's % gives -1
    ("-7 % -2", -1),
    ("-1 % 10", -1),       # Python's % gives 9
])
def test_remainder_takes_the_sign_of_the_dividend(expr, want):
    assert evaluate(expr, {}) == want


def test_division_and_remainder_agree_across_every_sign():
    """The identity that makes the pair coherent: a == (a / b) * b + a % b.

    Python's floor division and floor modulo satisfy it too — but at different
    values. Asserting the identity alone would pass on the old behaviour, so
    the truncation direction is pinned separately above.
    """
    for a in range(-25, 26):
        for b in range(-7, 8):
            if b == 0:
                continue
            q = evaluate(f"({a}) / ({b})", {})
            r = evaluate(f"({a}) % ({b})", {})
            assert q * b + r == a, f"{a} / {b} = {q} rem {r}"
            assert q == int(a / b), f"{a} / {b} did not truncate toward zero"
            if r:
                assert (r < 0) == (a < 0), f"{a} % {b} = {r} has the wrong sign"


def test_division_by_zero_is_an_error_not_an_exception():
    for expr in ("1 / 0", "1 % 0", "1.0 / 0"):
        with pytest.raises(CELError):
            evaluate(expr, {})


def test_the_remainder_is_defined_for_integers_only(self=None):
    """CEL gives % an int overload and no double one."""
    with pytest.raises(CELError):
        evaluate("7.0 % 2", {})


# ── bool is its own type, not a small integer ──
@pytest.mark.parametrize("expr", [
    "true + 1", "true * 2", "true - false", "-true", "true / 1", "true % 2",
])
def test_arithmetic_on_bools_is_a_type_error(expr):
    """Python makes bool a subclass of int, so these all silently computed a
    number. CEL has no such overload."""
    with pytest.raises(CELError):
        evaluate(expr, {})


@pytest.mark.parametrize("expr", [
    "'a' * 2",        # Python repeats the string
    "1 + 'a'", "'a' - 'b'", "[1] + 'a'", "'a' / 'b'", "null + 1",
])
def test_mixed_type_arithmetic_is_a_type_error(expr):
    with pytest.raises(CELError):
        evaluate(expr, {})


def test_the_operations_that_are_defined_still_work():
    """The type checks must not have narrowed anything real."""
    assert evaluate("'ab' + 'cd'", {}) == "abcd"
    assert evaluate("[1] + [2]", {}) == [1, 2]
    assert evaluate("1 + 2 * 3", {}) == 7
    assert evaluate("-5 + 2", {}) == -3
    assert evaluate("10.0 / 4", {}) == 2.5
    assert evaluate("1.5 + 2", {}) == 3.5


# ── one exception type at the boundary ──
@pytest.mark.parametrize("expr", [
    "1 + 'a'",            # raised a bare TypeError
    "'a' - 'b'",
    "[1] + 'a'",
    "size(1)",
    "'abc'.startsWith(1)",
])
def test_every_failure_leaves_as_a_celerror(expr):
    """Callers catch CELError. One that leaks a TypeError makes a bad
    expression look like a bug in the engine rather than a bad expression."""
    try:
        evaluate(expr, {})
    except CELError:
        pass
    except Exception as exc:  # noqa: BLE001 — that is the thing being asserted
        pytest.fail(f"{expr!r} leaked {type(exc).__name__}: {exc}")


def test_a_type_error_names_both_operand_types():
    """An operator error a human can act on without reading the engine."""
    with pytest.raises(CELError) as e:
        evaluate("1 + 'a'", {})
    msg = str(e.value)
    assert "int" in msg and "string" in msg, msg
