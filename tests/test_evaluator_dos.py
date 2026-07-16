"""Denial-of-service regression tests for the safe policy evaluator.

Policy expressions are attacker-reachable (POST /policies/import validates an
imported policy by evaluating its expressions). The evaluator is injection-safe,
but two DoS primitives were exploitable:

  1. Sequence-repetition memory bomb — `"a" * 999999999` / `[0] * 9999 * 9999`
     allocate memory linear in the multiplier, exhausting the process.
  2. ReDoS — `matches(s, "(a+)+$")` makes `re` (which has no timeout) backtrack
     catastrophically on a short subject.

These tests pin the mitigations: oversized repetitions raise, ReDoS-shaped
patterns are rejected instantly, and legitimate expressions still work.
"""
import time

import pytest

from app.policy_as_code.evaluator import (
    PolicyExpressionError,
    SafeEvaluator,
    _has_nested_quantifier,
)
from app.policy_as_code.evaluator import evaluate_expression as ev


def _eval(expr, ctx=None, params=None):
    return SafeEvaluator(ctx or {}, params or {}).eval(expr)


# ── multiplication memory bomb ──
@pytest.mark.parametrize("payload", [
    '"a" * 999999999',
    '"ab" * 100000000',
    '"a" * 99999 * 99999',   # chained: each factor is small, product is huge
    '[0] * 999999999',
    '[1, 2, 3] * 100000000',
])
def test_repetition_memory_bomb_blocked(payload):
    with pytest.raises(PolicyExpressionError):
        _eval(payload)


@pytest.mark.parametrize("payload,expected", [
    ('"ab" * 3', "ababab"),
    ('2 * 5', 10),
    ('[1] * 4', [1, 1, 1, 1]),
    ('3 * 3', 9),
    ('"x" * 0', ""),
    ('cost > budget * 1.4', True),  # numeric multiply in a real comparison
])
def test_legitimate_multiplication_still_works(payload, expected):
    assert _eval(payload, {"cost": 150, "budget": 100}) == expected


def test_repetition_at_cap_boundary_allowed():
    # 50_000-char string * 2 == 100_000 == cap → allowed; * 3 → blocked.
    assert len(_eval('s * 2', {"s": "a" * 50_000})) == 100_000
    with pytest.raises(PolicyExpressionError):
        _eval('s * 3', {"s": "a" * 50_000})


# ── ReDoS ──
@pytest.mark.parametrize("pattern", [
    "(a+)+$",
    "(a*)*$",
    "(a|aa)+$",
    "([a-z]+)*$",
    "(.*a){20}",
    "(x+x+)+y",
])
def test_redos_patterns_rejected_fast(pattern):
    assert _has_nested_quantifier(pattern) is True
    subject = "a" * 40 + "!"
    start = time.perf_counter()
    result = ev("matches(subj, pat)", {"subj": subject, "pat": pattern})
    elapsed = time.perf_counter() - start
    assert result is False
    assert elapsed < 0.5, f"pattern {pattern!r} took {elapsed:.2f}s (possible ReDoS)"


@pytest.mark.parametrize("pattern,subject,expected", [
    ("^h.*o$", "hello", True),
    ("^h.*o$", "world", False),
    (r"\d+", "abc123", True),
    ("[A-Z]+", "lower", False),
    ("foo|bar", "a bar b", True),
    ("arn:aws", "arn:aws:s3", True),
    (r"a+", "aaa", True),               # a single quantifier is fine
    (r"\(a\+\)\+", "(a+)+", True),      # escaped metachars: not a nested quantifier
])
def test_legitimate_regexes_still_work(pattern, subject, expected):
    assert ev("matches(subj, pat)", {"subj": subject, "pat": pattern}) is expected


def test_escaped_quantifier_not_flagged():
    # `\+` and `\|` are literals, not quantifiers — must not be rejected.
    assert _has_nested_quantifier(r"(a\+b\|c)+") is False
