"""CEL — Common Expression Language, implemented here rather than depended on.

WHY THIS EXISTS
---------------
Control checks are data (app/data/control_checks.json), and their expressions
are the part of that data with semantics. Until now those expressions were
evaluated by parsing them with Python's own parser and walking the result under
an AST allowlist (app/policy_as_code/evaluator.py). That is safe — the
allowlist is strict and well tested — but it means the language a customer or
auditor reads in the check pack is "a subset of Python that resembles CEL",
defined by what the allowlist happens to permit. CEL is a published
specification with the same shape, so writing the expressions in real CEL makes
them portable to any other CEL runtime and gives a reader a spec to consult
instead of a codebase.

WHY NOT cel-python
------------------
The PyPI package pulls in google-re2 (a C++ extension needing pybind11 and
Bazel) and pendulum (a Rust extension needing maturin). Neither builds in this
environment. Rust and C++ toolchains are both present and a cdylib loads fine
through ctypes, so a native implementation was viable in principle — but
crates.io and PyPI are both blocked, so the one dependency that actually
mattered, a linear-time regex engine, could not be fetched either way.

That dependency is the interesting part. google-re2 is not there for speed; it
is there because CEL's matches() takes a user-supplied pattern, and Python's re
is backtracking, so a pattern like (a+)+$ against a non-matching string takes
exponential time. The existing evaluator defends against that with a heuristic
that rejects nested quantifiers — a guess about which patterns are dangerous.

The guarantee is algorithmic, not linguistic. A Thompson NFA simulation runs in
O(len(pattern) x len(text)) with no backtracking at all, in any language. So
matches() is implemented that way below, and the heuristic is not needed: there
is no pattern, nested quantifiers included, that makes it blow up.

WHAT IS SUPPORTED
-----------------
    literals      int, double, string, bool (true/false), null
    collections   [list], {map}, indexing a["k"] and a[0]
    operators     || && ! == != < <= > >= + - * / % in, and ?: ternary
    selection     a.b.c  (map navigation; never Python attribute access)
    functions     size, has, startsWith, endsWith, contains, matches,
                  lower, upper, int, double, string, min, max, abs
    macros        all(x, p) exists(x, p) exists_one(x, p) filter(x, p) map(x, p)

Deliberately absent: no user-defined functions, no arithmetic on durations or
timestamps, no protobuf types, no comprehensions beyond the standard macros.
A check expression that needs any of those is a check that should be a probe.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["CELError", "evaluate", "parse"]


class CELError(Exception):
    """Malformed expression, or a construct this subset does not accept."""


# ──────────────────────────────────────────────────────────────────────────
# Linear-time regex (Thompson NFA)
#
# Supports: literals, '.', '*', '+', '?', '|', groups, character classes with
# ranges and negation, the \d \w \s escapes and their negations, and the
# anchors '^' and '$'. Compilation is to an NFA; matching simulates every
# reachable state in lockstep, so there is no backtracking to exploit.
# ──────────────────────────────────────────────────────────────────────────

_RE_MAX_PATTERN = 512


@dataclass
class _Frag:
    """A regex AST node. kind: char|any|class|cat|alt|star|plus|opt|empty."""
    kind: str
    ch: str = ""
    ranges: tuple[tuple[str, str], ...] = ()
    negate: bool = False
    left: _Frag | None = None
    right: _Frag | None = None


_CLASS_ESCAPES = {
    "d": ((("0", "9"),), False),
    "D": ((("0", "9"),), True),
    "w": ((("a", "z"), ("A", "Z"), ("0", "9"), ("_", "_")), False),
    "W": ((("a", "z"), ("A", "Z"), ("0", "9"), ("_", "_")), True),
    "s": (((" ", " "), ("\t", "\t"), ("\n", "\n"), ("\r", "\r"), ("\f", "\f"), ("\v", "\v")), False),
    "S": (((" ", " "), ("\t", "\t"), ("\n", "\n"), ("\r", "\r"), ("\f", "\f"), ("\v", "\v")), True),
}


class _ReParser:
    def __init__(self, pattern: str) -> None:
        self.p = pattern
        self.i = 0

    def peek(self) -> str:
        return self.p[self.i] if self.i < len(self.p) else ""

    def next(self) -> str:
        c = self.p[self.i]
        self.i += 1
        return c

    def parse(self) -> _Frag:
        node = self.alt()
        if self.i != len(self.p):
            raise CELError(f"regex: unexpected {self.peek()!r} at {self.i}")
        return node

    def alt(self) -> _Frag:
        node = self.cat()
        while self.peek() == "|":
            self.next()
            node = _Frag("alt", left=node, right=self.cat())
        return node

    def cat(self) -> _Frag:
        node: _Frag | None = None
        while self.peek() and self.peek() not in "|)":
            piece = self.repeat()
            node = piece if node is None else _Frag("cat", left=node, right=piece)
        return node or _Frag("empty")

    def repeat(self) -> _Frag:
        node = self.atom()
        while self.peek() in ("*", "+", "?"):
            op = self.next()
            node = _Frag({"*": "star", "+": "plus", "?": "opt"}[op], left=node)
        return node

    def atom(self) -> _Frag:
        c = self.next()
        if c == "(":
            node = self.alt()
            if self.peek() != ")":
                raise CELError("regex: unbalanced (")
            self.next()
            return node
        if c == ".":
            return _Frag("any")
        if c == "[":
            return self.char_class()
        if c == "\\":
            if not self.peek():
                raise CELError("regex: trailing backslash")
            e = self.next()
            if e in _CLASS_ESCAPES:
                ranges, neg = _CLASS_ESCAPES[e]
                return _Frag("class", ranges=ranges, negate=neg)
            return _Frag("char", ch=e)
        return _Frag("char", ch=c)

    def char_class(self) -> _Frag:
        negate = False
        if self.peek() == "^":
            self.next()
            negate = True
        ranges: list[tuple[str, str]] = []
        while self.peek() and self.peek() != "]":
            c = self.next()
            if c == "\\" and self.peek():
                e = self.next()
                if e in _CLASS_ESCAPES:
                    sub, sub_neg = _CLASS_ESCAPES[e]
                    if sub_neg:
                        raise CELError("regex: negated escape inside a class")
                    ranges.extend(sub)
                    continue
                c = e
            if self.peek() == "-" and self.i + 1 < len(self.p) and self.p[self.i + 1] != "]":
                self.next()
                ranges.append((c, self.next()))
            else:
                ranges.append((c, c))
        if self.peek() != "]":
            raise CELError("regex: unbalanced [")
        self.next()
        return _Frag("class", ranges=tuple(ranges), negate=negate)


# NFA states are (kind, arg, out, out2). Compiled to a flat list of dicts.
def _compile_nfa(node: _Frag, states: list[dict[str, Any]], nxt: int) -> int:
    """Compile `node` so that on success control flows to state index `nxt`.
    Returns the entry state index."""
    k = node.kind
    if k == "empty":
        return nxt
    if k in ("char", "any", "class"):
        states.append({"k": k, "ch": node.ch, "ranges": node.ranges,
                       "neg": node.negate, "out": nxt})
        return len(states) - 1
    if k == "cat":
        second = _compile_nfa(node.right, states, nxt)
        return _compile_nfa(node.left, states, second)
    if k == "alt":
        a = _compile_nfa(node.left, states, nxt)
        b = _compile_nfa(node.right, states, nxt)
        states.append({"k": "split", "out": a, "out2": b})
        return len(states) - 1
    if k == "opt":
        a = _compile_nfa(node.left, states, nxt)
        states.append({"k": "split", "out": a, "out2": nxt})
        return len(states) - 1
    if k == "star":
        states.append({"k": "split", "out": -1, "out2": nxt})
        split = len(states) - 1
        a = _compile_nfa(node.left, states, split)
        states[split]["out"] = a
        return split
    if k == "plus":
        states.append({"k": "split", "out": -1, "out2": nxt})
        split = len(states) - 1
        a = _compile_nfa(node.left, states, split)
        states[split]["out"] = a
        return a
    raise CELError(f"regex: unsupported node {k}")


_MATCH_STATE = -1  # sentinel index meaning "accepted"


def _add_state(states: list[dict[str, Any]], idx: int, current: set[int],
               seen: set[int]) -> None:
    """Follow split (epsilon) edges, adding every reachable non-epsilon state."""
    stack = [idx]
    while stack:
        i = stack.pop()
        if i in seen:
            continue
        seen.add(i)
        if i == _MATCH_STATE:
            current.add(i)
            continue
        st = states[i]
        if st["k"] == "split":
            stack.append(st["out"])
            stack.append(st["out2"])
        else:
            current.add(i)


def _state_matches(st: dict[str, Any], c: str) -> bool:
    if st["k"] == "any":
        return c != "\n"
    if st["k"] == "char":
        return c == st["ch"]
    inside = any(lo <= c <= hi for lo, hi in st["ranges"])
    return (not inside) if st["neg"] else inside


def regex_search(pattern: str, text: str) -> bool:
    """True if `pattern` matches anywhere in `text`, in linear time.

    No backtracking is involved, so the catastrophic patterns that make
    Python's re exponential — (a+)+$ and friends — are ordinary input here.
    """
    if len(pattern) > _RE_MAX_PATTERN:
        raise CELError(f"regex pattern exceeds {_RE_MAX_PATTERN} characters")

    anchor_start = pattern.startswith("^")
    body = pattern[1:] if anchor_start else pattern
    anchor_end = body.endswith("$") and not body.endswith("\\$")
    if anchor_end:
        body = body[:-1]

    ast_node = _ReParser(body).parse()
    states: list[dict[str, Any]] = []
    start = _compile_nfa(ast_node, states, _MATCH_STATE)

    current: set[int] = set()
    _add_state(states, start, current, set())
    if _MATCH_STATE in current and not anchor_end:
        return True

    for pos, c in enumerate(text):
        nxt: set[int] = set()
        seen: set[int] = set()
        for i in current:
            if i == _MATCH_STATE:
                continue
            if _state_matches(states[i], c):
                _add_state(states, states[i]["out"], nxt, seen)
        # An unanchored pattern may start at any offset, so the start state is
        # kept live as the scan advances.
        if not anchor_start:
            _add_state(states, start, nxt, seen)
        current = nxt
        if _MATCH_STATE in current and not anchor_end:
            return True
        if not current:
            break
        _ = pos
    return _MATCH_STATE in current


# ──────────────────────────────────────────────────────────────────────────
# Lexer
# ──────────────────────────────────────────────────────────────────────────

_PUNCT = ["||", "&&", "==", "!=", "<=", ">=", "(", ")", "[", "]", "{", "}",
          ",", ".", ":", "?", "+", "-", "*", "/", "%", "<", ">", "!"]
_KEYWORDS = {"true": True, "false": False, "null": None}


@dataclass
class _Tok:
    kind: str          # num | str | ident | punct | eof
    value: Any
    pos: int


def _lex(src: str) -> list[_Tok]:
    toks: list[_Tok] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c in ("'", '"'):
            quote, j, buf = c, i + 1, []
            while j < n and src[j] != quote:
                if src[j] == "\\" and j + 1 < n:
                    esc = src[j + 1]
                    buf.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\",
                                "'": "'", '"': '"'}.get(esc, esc))
                    j += 2
                    continue
                buf.append(src[j])
                j += 1
            if j >= n:
                raise CELError("unterminated string literal")
            toks.append(_Tok("str", "".join(buf), i))
            i = j + 1
            continue
        if c.isdigit():
            j = i
            while j < n and (src[j].isdigit() or src[j] == "."):
                j += 1
            text = src[i:j]
            toks.append(_Tok("num", float(text) if "." in text else int(text), i))
            i = j
            continue
        if c.isalpha() or c == "_":
            j = i
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            toks.append(_Tok("ident", src[i:j], i))
            i = j
            continue
        for p in _PUNCT:
            if src.startswith(p, i):
                toks.append(_Tok("punct", p, i))
                i += len(p)
                break
        else:
            raise CELError(f"unexpected character {c!r} at {i}")
    toks.append(_Tok("eof", None, n))
    return toks


# ──────────────────────────────────────────────────────────────────────────
# Parser — precedence climbing over the CEL grammar
# ──────────────────────────────────────────────────────────────────────────

_BINARY_PRECEDENCE = [
    ("||",),
    ("&&",),
    ("==", "!=", "<", "<=", ">", ">=", "in"),
    ("+", "-"),
    ("*", "/", "%"),
]


class _Parser:
    def __init__(self, toks: list[_Tok]) -> None:
        self.t = toks
        self.i = 0

    def peek(self) -> _Tok:
        return self.t[self.i]

    def eat(self, value: str) -> None:
        tok = self.peek()
        if tok.value != value:
            raise CELError(f"expected {value!r} at {tok.pos}, found {tok.value!r}")
        self.i += 1

    def at(self, value: str) -> bool:
        tok = self.peek()
        return tok.kind in ("punct", "ident") and tok.value == value

    def parse(self) -> Any:
        node = self.ternary()
        if self.peek().kind != "eof":
            raise CELError(f"trailing input at {self.peek().pos}")
        return node

    def ternary(self) -> Any:
        cond = self.binary(0)
        if self.at("?"):
            self.eat("?")
            a = self.ternary()
            self.eat(":")
            b = self.ternary()
            return ("cond", cond, a, b)
        return cond

    def binary(self, level: int) -> Any:
        if level >= len(_BINARY_PRECEDENCE):
            return self.unary()
        node = self.binary(level + 1)
        while True:
            tok = self.peek()
            op = tok.value
            if tok.kind in ("punct", "ident") and op in _BINARY_PRECEDENCE[level]:
                self.i += 1
                node = ("bin", op, node, self.binary(level + 1))
            else:
                return node

    def unary(self) -> Any:
        if self.at("!"):
            self.eat("!")
            return ("not", self.unary())
        if self.at("-"):
            self.eat("-")
            return ("neg", self.unary())
        return self.postfix()

    def postfix(self) -> Any:
        node = self.primary()
        while True:
            if self.at("."):
                self.eat(".")
                name_tok = self.peek()
                if name_tok.kind != "ident":
                    raise CELError(f"expected a field name at {name_tok.pos}")
                self.i += 1
                if self.at("("):          # method form: x.startsWith("a")
                    args = self.arg_list()
                    node = ("call", name_tok.value, [node, *args])
                else:
                    node = ("select", node, name_tok.value)
            elif self.at("["):
                self.eat("[")
                idx = self.ternary()
                self.eat("]")
                node = ("index", node, idx)
            else:
                return node

    def arg_list(self) -> list[Any]:
        self.eat("(")
        args: list[Any] = []
        if not self.at(")"):
            args.append(self.ternary())
            while self.at(","):
                self.eat(",")
                args.append(self.ternary())
        self.eat(")")
        return args

    def primary(self) -> Any:
        tok = self.peek()
        if tok.kind == "num" or tok.kind == "str":
            self.i += 1
            return ("lit", tok.value)
        if tok.kind == "ident":
            if tok.value in _KEYWORDS:
                self.i += 1
                return ("lit", _KEYWORDS[tok.value])
            self.i += 1
            if self.at("("):
                return ("call", tok.value, self.arg_list())
            return ("ident", tok.value)
        if self.at("("):
            self.eat("(")
            node = self.ternary()
            self.eat(")")
            return node
        if self.at("["):
            self.eat("[")
            items: list[Any] = []
            if not self.at("]"):
                items.append(self.ternary())
                while self.at(","):
                    self.eat(",")
                    items.append(self.ternary())
            self.eat("]")
            return ("list", items)
        if self.at("{"):
            self.eat("{")
            pairs: list[tuple[Any, Any]] = []
            if not self.at("}"):
                while True:
                    k = self.ternary()
                    self.eat(":")
                    pairs.append((k, self.ternary()))
                    if self.at(","):
                        self.eat(",")
                        continue
                    break
            self.eat("}")
            return ("map", pairs)
        raise CELError(f"unexpected {tok.value!r} at {tok.pos}")


def parse(expr: str) -> Any:
    if not isinstance(expr, str) or not expr.strip():
        raise CELError("empty expression")
    return _Parser(_lex(expr)).parse()


# ──────────────────────────────────────────────────────────────────────────
# Evaluation
# ──────────────────────────────────────────────────────────────────────────

_MACROS = {"all", "exists", "exists_one", "filter", "map"}


def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    raise CELError(f"expected a bool, got {type(v).__name__}")


def _fn_size(v: Any) -> int:
    if isinstance(v, str | list | dict | tuple):
        return len(v)
    raise CELError("size() expects a string, list or map")


def _type_name(v: Any) -> str:
    """The CEL name for a value's type, for error messages."""
    if isinstance(v, bool):
        return "bool"
    if v is None:
        return "null"
    return {int: "int", float: "double", str: "string",
            list: "list", dict: "map"}.get(type(v), type(v).__name__)


def _is_int(v: Any) -> bool:
    """int, and not bool.

    Python makes bool a subclass of int, so `True + 1` is 2 and `'a' * 2` is
    'aa'. CEL has no such overloads — bool is its own type and arithmetic on it
    is a type error. Without this the engine silently accepts expressions the
    spec rejects, which is the same portability problem as the division one.
    """
    return isinstance(v, int) and not isinstance(v, bool)


def _is_number(v: Any) -> bool:
    return _is_int(v) or isinstance(v, float)


def _require_numbers(op: str, a: Any, b: Any) -> None:
    if not (_is_number(a) and _is_number(b)):
        raise CELError(f"no matching overload: {_type_name(a)} {op} {_type_name(b)}")


def _binary(op: str, a: Any, b: Any) -> Any:
    if op == "==":
        return a == b
    if op == "!=":
        return a != b
    if op == "in":
        if isinstance(b, dict):
            return a in b
        if isinstance(b, str | list | tuple):
            return a in b
        raise CELError("'in' expects a list, map or string on the right")
    if op in ("<", "<=", ">", ">="):
        if isinstance(a, bool) or isinstance(b, bool):
            raise CELError(f"cannot order bools with {op}")
        if a is None or b is None:
            raise CELError(f"cannot order null with {op}")
        return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
    if op == "+":
        if isinstance(a, str) and isinstance(b, str):
            return a + b
        if isinstance(a, list) and isinstance(b, list):
            return a + b
        _require_numbers(op, a, b)
        return a + b
    if op == "-":
        _require_numbers(op, a, b)
        return a - b
    if op == "*":
        _require_numbers(op, a, b)
        return a * b
    if op == "/":
        _require_numbers(op, a, b)
        if b == 0:
            raise CELError("division by zero")
        if _is_int(a) and _is_int(b):
            # CEL integer division truncates toward zero, like C, Go and Java.
            # Python's // floors toward negative infinity, so -7 / 2 is -4 here
            # and -3 in every conformant implementation. The whole reason this
            # pack is written in CEL rather than a Python subset is that the
            # language is a published spec somebody can look up — an expression
            # checked against that spec has to mean the same thing here.
            q = abs(a) // abs(b)
            return -q if (a < 0) != (b < 0) else q
        return a / b
    if op == "%":
        # CEL defines the remainder for integers only.
        if not (_is_int(a) and _is_int(b)):
            raise CELError(f"no matching overload: {_type_name(a)} % {_type_name(b)}")
        if b == 0:
            raise CELError("modulus by zero")
        # Sign follows the dividend, so that a == (a / b) * b + a % b holds
        # with truncating division above. Python's % takes the sign of the
        # divisor, which breaks that identity for mixed signs.
        return a - b * _binary("/", a, b)
    raise CELError(f"unsupported operator {op}")


class _Evaluator:
    def __init__(self, context: dict[str, Any]) -> None:
        self.ctx = context
        self.scopes: list[dict[str, Any]] = []

    def lookup(self, name: str) -> Any:
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        if name in self.ctx:
            return self.ctx[name]
        raise CELError(f"unknown identifier {name!r}")

    def eval(self, node: Any) -> Any:
        kind = node[0]
        if kind == "lit":
            return node[1]
        if kind == "ident":
            return self.lookup(node[1])
        if kind == "list":
            return [self.eval(x) for x in node[1]]
        if kind == "map":
            return {self.eval(k): self.eval(v) for k, v in node[1]}
        if kind == "not":
            return not _truthy(self.eval(node[1]))
        if kind == "neg":
            v = self.eval(node[1])
            if not _is_number(v):
                raise CELError(f"no matching overload: -{_type_name(v)}")
            return -v
        if kind == "cond":
            return self.eval(node[2]) if _truthy(self.eval(node[1])) else self.eval(node[3])
        if kind == "select":
            base = self.eval(node[1])
            if isinstance(base, dict):
                if node[2] not in base:
                    raise CELError(f"no such key: {node[2]!r}")
                return base[node[2]]
            raise CELError(f"cannot select {node[2]!r} from {type(base).__name__}")
        if kind == "index":
            base, idx = self.eval(node[1]), self.eval(node[2])
            try:
                return base[idx]
            except (KeyError, IndexError, TypeError) as exc:
                raise CELError(f"no such index: {idx!r}") from exc
        if kind == "bin":
            op = node[1]
            # Short-circuit, as the spec requires.
            if op == "&&":
                return _truthy(self.eval(node[2])) and _truthy(self.eval(node[3]))
            if op == "||":
                return _truthy(self.eval(node[2])) or _truthy(self.eval(node[3]))
            return _binary(op, self.eval(node[2]), self.eval(node[3]))
        if kind == "call":
            return self.call(node[1], node[2])
        raise CELError(f"unsupported node {kind}")

    # ── functions and macros ──
    def call(self, name: str, args: list[Any]) -> Any:
        if name in _MACROS:
            return self.macro(name, args)
        if name == "has":
            if len(args) != 1 or args[0][0] != "select":
                raise CELError("has() takes exactly one field selection")
            try:
                base = self.eval(args[0][1])
            except CELError:
                return False
            return isinstance(base, dict) and args[0][2] in base

        values = [self.eval(a) for a in args]

        def arity(n: int) -> None:
            if len(values) != n:
                raise CELError(f"{name}() takes {n} argument(s), got {len(values)}")

        if name == "size":
            arity(1)
            return _fn_size(values[0])
        if name in ("startsWith", "endsWith", "contains"):
            arity(2)
            a, b = values
            if not isinstance(a, str) or not isinstance(b, str):
                raise CELError(f"{name}() expects strings")
            return {"startsWith": a.startswith, "endsWith": a.endswith,
                    "contains": lambda x: x in a}[name](b)
        if name == "matches":
            arity(2)
            text, pattern = values
            if not isinstance(text, str) or not isinstance(pattern, str):
                raise CELError("matches() expects strings")
            return regex_search(pattern, text)
        if name in ("lower", "upper"):
            arity(1)
            if not isinstance(values[0], str):
                raise CELError(f"{name}() expects a string")
            return values[0].lower() if name == "lower" else values[0].upper()
        if name == "int":
            arity(1)
            return int(values[0])
        if name == "double":
            arity(1)
            return float(values[0])
        if name == "string":
            arity(1)
            v = values[0]
            return "true" if v is True else "false" if v is False else str(v)
        if name == "abs":
            arity(1)
            return abs(values[0])
        if name in ("min", "max"):
            seq = values[0] if len(values) == 1 and isinstance(values[0], list) else values
            if not seq:
                raise CELError(f"{name}() of an empty sequence")
            return min(seq) if name == "min" else max(seq)
        raise CELError(f"unknown function {name!r}")

    def macro(self, name: str, args: list[Any]) -> Any:
        """all/exists/exists_one/filter/map over a list.

        Written as all(items, item, predicate) or the two-argument shorthand
        all(items, predicate) where the bound variable is named `x`.
        """
        if len(args) == 3:
            if args[1][0] != "ident":
                raise CELError(f"{name}(): the second argument must be a variable name")
            var, pred, seq_node = args[1][1], args[2], args[0]
        elif len(args) == 2:
            var, pred, seq_node = "x", args[1], args[0]
        else:
            raise CELError(f"{name}() takes 2 or 3 arguments")

        seq = self.eval(seq_node)
        if not isinstance(seq, list):
            raise CELError(f"{name}() expects a list")

        results = []
        for item in seq:
            self.scopes.append({var: item})
            try:
                results.append(self.eval(pred))
            finally:
                self.scopes.pop()

        if name == "all":
            return all(_truthy(r) for r in results)
        if name == "exists":
            return any(_truthy(r) for r in results)
        if name == "exists_one":
            return sum(1 for r in results if _truthy(r)) == 1
        if name == "filter":
            return [v for v, r in zip(seq, results, strict=True) if _truthy(r)]
        return results  # map


def evaluate(expr: str, context: dict[str, Any]) -> Any:
    """Evaluate a CEL expression against a context of named values.

    Everything this raises is a CELError. The evaluator works on Python values,
    so an unhandled operand combination used to surface whatever Python raised —
    a bare TypeError from `1 + 'a'`, for instance. Callers catch CELError; one
    that leaks a TypeError makes a bad expression look like a bug in the engine
    rather than a bad expression.
    """
    if not isinstance(context, dict):
        raise CELError("context must be a mapping")
    try:
        return _Evaluator(context).eval(parse(expr))
    except CELError:
        raise
    except RecursionError as exc:                    # pathologically nested input
        raise CELError("expression is too deeply nested") from exc
    except Exception as exc:  # noqa: BLE001 — the library boundary: one error type out
        raise CELError(f"{type(exc).__name__}: {exc}") from exc
