"""Safe, dynamic expression evaluator for compliance-as-code policies.

Extends a strict AST-allowlist evaluator with the capabilities a real compliance
language needs, WITHOUT ever executing arbitrary code:

  comparisons   == != < <= > >= in 'not in'
  boolean       and or not
  arithmetic    + - * / % //
  literals      numbers, strings, true/false/null, lists
  field access  resource.config.encryption  (dotted navigation into nested dicts)
  functions     len, count, any, all, sum, min, max, abs, round,
                lower, upper, startswith, endswith, contains, matches (regex)
  quantifiers   all(buckets, "encryption == true")  any(...)  count(..., pred)
  parameters    thresholds resolved from a params map at eval time

Security model: an allowlist of AST node types and a fixed function registry.
Function calls are permitted ONLY to named functions in the registry — never
methods, never attributes of objects. Dotted names resolve as dict navigation
into the evidence context, never as Python attribute access, and any '__' name
is rejected outright. Every new capability below is covered by injection tests.
"""
from __future__ import annotations

import ast
import functools
import operator
import re
from collections.abc import Callable
from typing import Any


@functools.lru_cache(maxsize=512)
def _parse_cached(expr: str) -> ast.Expression:
    """Parse and cache expression ASTs — same policy expressions are evaluated
    thousands of times per day; re-parsing each time wastes CPU."""
    try:
        return ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise PolicyExpressionError(f"syntax error: {exc}") from exc

_CMP = {
    ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt,
    ast.LtE: operator.le, ast.Gt: operator.gt, ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b,
}
_BOOL = {ast.And: all, ast.Or: any}
_UNARY = {ast.Not: operator.not_, ast.USub: operator.neg, ast.UAdd: operator.pos}

# Cap sequence-repetition size. `"x" * n` / `[0] * n` allocate memory linear in
# `n`, so an attacker-supplied expression like `"a" * 999999999` (or chained,
# `"a" * 9999 * 9999`) is a memory-exhaustion DoS. Bound the resulting length of
# any sequence * int so a single expression cannot balloon allocation.
_MAX_SEQ_LEN = 100_000


class PolicyExpressionError(Exception):
    """Malformed expression or use of a disallowed construct."""


def _safe_mul(a: Any, b: Any) -> Any:
    """operator.mul, but reject sequence repetition that would exceed the cap."""
    for seq, n in ((a, b), (b, a)):
        if (isinstance(seq, (str, bytes, bytearray, list, tuple))
                and isinstance(n, int) and not isinstance(n, bool)
                and n > 0 and len(seq) * n > _MAX_SEQ_LEN):
            raise PolicyExpressionError("sequence repetition too large")
    return operator.mul(a, b)


_ARITH = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: _safe_mul,
    ast.Div: operator.truediv, ast.Mod: operator.mod, ast.FloorDiv: operator.floordiv,
}


class SafeEvaluator:
    def __init__(self, context: dict[str, Any], params: dict[str, Any] | None = None):
        self.ctx = context or {}
        self.params = params or {}

    # ── public ──
    def eval(self, expr: str) -> Any:
        if not isinstance(expr, str) or not expr.strip():
            raise PolicyExpressionError("empty expression")
        tree = _parse_cached(expr)  # cached — same expression parsed once ever
        return self._walk(tree.body)

    # ── core walker ──
    def _walk(self, node: ast.AST) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, (ast.List, ast.Tuple)):
            return [self._walk(e) for e in node.elts]
        if isinstance(node, ast.Name):
            return self._resolve_name(node.id)
        if isinstance(node, ast.Attribute):
            return self._resolve_dotted(node)
        if isinstance(node, ast.BoolOp):
            fn = _BOOL.get(type(node.op))
            if fn is None:
                raise PolicyExpressionError("unsupported boolean operator")
            return fn(bool(self._walk(v)) for v in node.values)
        if isinstance(node, ast.UnaryOp):
            fn = _UNARY.get(type(node.op))
            if fn is None:
                raise PolicyExpressionError("unsupported unary operator")
            return fn(self._walk(node.operand))
        if isinstance(node, ast.BinOp):
            fn = _ARITH.get(type(node.op))
            if fn is None:
                raise PolicyExpressionError("unsupported arithmetic operator")
            try:
                return fn(self._walk(node.left), self._walk(node.right))
            except (TypeError, ZeroDivisionError):
                return 0
        if isinstance(node, ast.Compare):
            left = self._walk(node.left)
            for op, comp in zip(node.ops, node.comparators, strict=False):
                fn = _CMP.get(type(op))
                if fn is None:
                    raise PolicyExpressionError("unsupported comparison operator")
                right = self._walk(comp)
                if left is None and isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
                    return False
                try:
                    if not fn(left, right):
                        return False
                except TypeError:
                    return False
                left = right
            return True
        if isinstance(node, ast.Call):
            return self._call(node)
        raise PolicyExpressionError(f"disallowed expression element: {type(node).__name__}")

    # ── name + dotted field resolution (context, params, literals) ──
    def _resolve_name(self, name: str) -> Any:
        if name in ("True", "true"):
            return True
        if name in ("False", "false"):
            return False
        if name in ("None", "null"):
            return None
        if "__" in name:
            raise PolicyExpressionError("illegal name")
        if name in self.ctx:
            return self.ctx[name]
        if name in self.params:
            return self.params[name]
        return None  # missing field → None (fail-closed), never an error

    def _resolve_dotted(self, node: ast.Attribute) -> Any:
        # build the full dotted path a.b.c — must be pure Name.attr.attr...
        parts: list[str] = []
        cur: ast.AST = node
        while isinstance(cur, ast.Attribute):
            if "__" in cur.attr:
                raise PolicyExpressionError("illegal attribute")
            parts.append(cur.attr)
            cur = cur.value
        if not isinstance(cur, ast.Name):
            raise PolicyExpressionError("attribute access only on named fields")
        parts.append(cur.id)
        parts.reverse()
        # navigate nested dicts in context
        val: Any = self.ctx.get(parts[0], self.params.get(parts[0]))
        for p in parts[1:]:
            if isinstance(val, dict):
                val = val.get(p)
            else:
                return None
        return val

    # ── function calls — registry only, never methods ──
    def _call(self, node: ast.Call) -> Any:
        if not isinstance(node.func, ast.Name):
            raise PolicyExpressionError("only named function calls are allowed")
        fname = node.func.id
        if fname not in _FUNCTIONS:
            raise PolicyExpressionError(f"unknown function: {fname}")
        if node.keywords:
            raise PolicyExpressionError("keyword arguments not allowed")
        # quantifiers take a raw predicate string and re-evaluate per item
        if fname in _QUANTIFIERS:
            return self._quantifier(fname, node.args)
        args = [self._walk(a) for a in node.args]
        try:
            return _FUNCTIONS[fname](*args)
        except (TypeError, ValueError):
            return None

    def _quantifier(self, fname: str, args: list[ast.AST]) -> Any:
        if not args:
            return 0 if fname == "count" else False
        collection = self._walk(args[0])
        if not isinstance(collection, list):
            collection = []
        # predicate is optional 2nd arg, a string expression evaluated per item
        pred: str | None = None
        if len(args) >= 2:
            p = self._walk(args[1])
            pred = p if isinstance(p, str) else None

        def test(item: Any) -> bool:
            if pred is None:
                return bool(item)
            item_ctx = item if isinstance(item, dict) else {"value": item}
            return bool(SafeEvaluator(item_ctx, self.params).eval(pred))

        if fname == "all":
            return all(test(i) for i in collection)
        if fname == "any":
            return any(test(i) for i in collection)
        if fname == "count":
            return sum(1 for i in collection if test(i))
        return False


# ── safe function registry ──
_MATCH_MAX_SUBJECT = 10_000
_MATCH_MAX_PATTERN = 1_000

# A quantifier (* + ? {..}) applied to a group that itself contains a quantifier
# or alternation — e.g. `(a+)+`, `(a|aa)*`, `(a*)*` — is the classic shape that
# makes `re` backtrack exponentially. `re` has no timeout, and patterns can come
# from evidence data / imported policies, so such a pattern is a ReDoS DoS. The
# subject-length cap alone does NOT prevent it: `(a+)+$` blows up on a ~30-char
# string. Reject these pattern shapes outright instead of running them.
_QUANTIFIED_GROUP = re.compile(r"\(([^()]*)\)\s*(?:[*+]|\{\d*,?\d*\}|[*+]\?)")


def _has_nested_quantifier(pat: str) -> bool:
    """True if `pat` has a quantified group whose body itself contains a
    quantifier or alternation (the catastrophic-backtracking shape)."""
    for m in _QUANTIFIED_GROUP.finditer(pat):
        body = m.group(1)
        # strip escaped metacharacters so `\+` / `\|` don't count as quantifiers
        stripped = re.sub(r"\\.", "", body)
        if any(c in stripped for c in "*+|") or re.search(r"\{\d", stripped):
            return True
    return False


def _matches(s: Any, pattern: Any) -> bool:
    # Bound subject and pattern length, and reject ReDoS-shaped patterns, to
    # limit catastrophic-backtracking exposure — re has no timeout and a pattern
    # may come from evidence data or an imported policy.
    pat = str(pattern)
    if len(pat) > _MATCH_MAX_PATTERN or _has_nested_quantifier(pat):
        return False
    try:
        return re.search(pat, str(s)[:_MATCH_MAX_SUBJECT]) is not None
    except re.error:
        return False


_FUNCTIONS: dict[str, Callable] = {
    "len": lambda x: len(x) if hasattr(x, "__len__") else 0,
    "abs": lambda x: abs(x) if isinstance(x, (int, float)) else 0,
    "round": lambda x, n=0: round(x, int(n)) if isinstance(x, (int, float)) else 0,
    "min": lambda *a: min(a[0]) if len(a) == 1 and isinstance(a[0], list) else min(a),
    "max": lambda *a: max(a[0]) if len(a) == 1 and isinstance(a[0], list) else max(a),
    "sum": lambda x: sum(v for v in x if isinstance(v, (int, float))) if isinstance(x, list) else 0,
    "lower": lambda s: str(s).lower(),
    "upper": lambda s: str(s).upper(),
    "startswith": lambda s, p: str(s).startswith(str(p)),
    "endswith": lambda s, p: str(s).endswith(str(p)),
    "contains": lambda s, sub: str(sub) in str(s) if not isinstance(s, list) else sub in s,
    "matches": _matches,
    # quantifiers (handled specially, registered so they pass the name check)
    "all": lambda *a: None, "any": lambda *a: None, "count": lambda *a: None,
}
_QUANTIFIERS = {"all", "any", "count"}


def evaluate_expression(expr: str, context: dict[str, Any],
                        params: dict[str, Any] | None = None) -> bool:
    return bool(SafeEvaluator(context, params).eval(expr))
