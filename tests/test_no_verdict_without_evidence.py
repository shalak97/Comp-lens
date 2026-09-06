"""One defect class, checked across every Python file, forever.

Nearly every bug found in this codebase is the same one wearing different
clothes: **a value meaning "we do not know" collapsed into a value meaning "we
know".** It has appeared as

    risk_weighted_score  -> 100.0 when nothing was weighed
    all(buckets, ...)    -> pass over a missing field
    AI Act obligations   -> dropped from their own denominator
    a denied AWS call    -> False, i.e. "we looked, it is broken"
    an unsigned attestation -> build_provenance: True
    "runs": 5            -> `or []` -> crash
    unreadable NICs      -> public_ip_assigned: False, hiding a real exposure

Individually fixing each instance does not converge — the next one is written
the moment someone adds a connector, because the collapsing form is always the
SHORTER code. So this file checks the shape instead of the instances, over
every .py file under app/, cli/ and tools/.

Each detector carries an explicit register of the places where collapsing is
CORRECT, with the reason. That register is the actual specification: adding to
it should require saying out loud why absence really is an observation there.
A new entry is a decision, not a formality.
"""
from __future__ import annotations

import ast
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
FILES = sorted(p for d in ("app", "cli", "tools") for p in (ROOT / d).rglob("*.py")
               if "__pycache__" not in str(p))
PACK = json.loads((ROOT / "app" / "data" / "control_checks.json").read_text())
SIGNALS = {s for c in PACK["checks"] for s in c.get("requires", [])}
CONTROLS: dict[str, list] = {}
for _c in PACK["checks"]:
    for _s in _c.get("requires", []):
        CONTROLS.setdefault(_s, []).append((_c["control_id"], _c.get("severity", "?")))


def _rel(p: pathlib.Path) -> str:
    return str(p.relative_to(ROOT))


# ══════════════════════════════════════════════════════════════════════
# 1. A failed call must not answer a control question.
# ══════════════════════════════════════════════════════════════════════
#: Where returning a definite value from an exception handler is right.
#: `healthcheck` is excluded by name: a service you cannot reach IS unhealthy.
_MAY_ANSWER_ON_FAILURE = {
    "app/connectors/http_client.py::_is_blocked_host":
        "unresolvable host is not an SSRF target; let the request fail normally",
    "app/services/doc_fetch.py::_is_blocked_ip":
        "returns True = blocked; an unparseable address fails CLOSED",
    "app/services/crawler.py::_robots_allowed":
        "an unreachable robots.txt is allow-by-default, per the robots spec",
    "app/services/resolver.py::_connector_ok":
        "a connector that cannot be reached is not usable for this resolution",
    "app/grc_platforms/trust_telemetry.py::_clamp01":
        "clamping a non-numeric input to the bottom of its range",
    "app/policy_as_code/evaluator.py::_matches":
        "an invalid regex matches nothing; fails closed",
    "app/policy_as_code/evaluator.py::_walk":
        "a type error in an expression yields the falsy identity; fails closed",
    "app/policy_as_code/cel.py::call":
        "a CEL function that raises yields false; fails closed",
}


def test_no_connector_or_service_answers_a_control_question_after_a_failure():
    offenders = []
    for path in FILES:
        tree = ast.parse(path.read_text())
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            if fn.name.startswith("healthcheck"):
                continue
            key = f"{_rel(path)}::{fn.name}"
            if key in _MAY_ANSWER_ON_FAILURE:
                continue
            for h in [n for n in ast.walk(fn) if isinstance(n, ast.ExceptHandler)]:
                for st in h.body:
                    if (isinstance(st, ast.Return) and isinstance(st.value, ast.Constant)
                            and st.value.value in (True, False)):
                        offenders.append(f"{key} returns {st.value.value!r} (line {st.lineno})")
    assert not offenders, (
        "a failed call is being turned into a definite answer. Return None so "
        "the check reports NOT_APPLICABLE — or add the function to "
        "_MAY_ANSWER_ON_FAILURE with the reason absence really is an "
        "observation there:\n  " + "\n  ".join(offenders))


def test_the_register_has_no_stale_entries():
    """An exemption naming a function that no longer exists is a comment
    pretending to be a control."""
    stale = []
    for key in _MAY_ANSWER_ON_FAILURE:
        rel, _, fname = key.partition("::")
        path = ROOT / rel
        if not path.exists():
            stale.append(key)
            continue
        names = {n.name for n in ast.walk(ast.parse(path.read_text()))
                 if isinstance(n, ast.FunctionDef)}
        if fname not in names:
            stale.append(key)
    assert not stale, f"_MAY_ANSWER_ON_FAILURE names functions that are gone: {stale}"


# ══════════════════════════════════════════════════════════════════════
# 2. A swallowed failure must not leave a signal at its False default.
# ══════════════════════════════════════════════════════════════════════
def _signals_left_at_default(path: pathlib.Path):
    """The CloudTrail/GuardDuty shape: default False, loop, swallow, return.

    A function that returns early when nothing was readable is exempt — that is
    the fix, and it is what `guarded` detects.
    """
    out = []
    src = path.read_text()
    tree = ast.parse(src)
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        defaults = {t.id: st.lineno
                    for st in ast.walk(fn) if isinstance(st, ast.Assign)
                    and isinstance(st.value, ast.Constant) and st.value.value in (False, 0, 0.0)
                    for t in st.targets if isinstance(t, ast.Name)}
        if not defaults:
            continue
        swallows = [h for h in ast.walk(fn) if isinstance(h, ast.ExceptHandler)
                    and any(isinstance(s, (ast.Pass, ast.Continue)) for s in h.body)]
        if not swallows:
            continue
        # An early `return {...}` that omits the signals is the guard.
        guarded = any(isinstance(st, ast.Return) and isinstance(st.value, ast.Dict)
                      and not (SIGNALS & {k.value for k in st.value.keys
                                          if isinstance(k, ast.Constant)})
                      for st in ast.walk(fn))
        if guarded:
            continue
        for d in [n for n in ast.walk(fn) if isinstance(n, ast.Dict)]:
            for k, v in zip(d.keys, d.values):
                if (isinstance(k, ast.Constant) and k.value in SIGNALS
                        and isinstance(v, ast.Name) and v.id in defaults):
                    sev = max((c[1] for c in CONTROLS.get(k.value, [])), default="?")
                    out.append(f"{_rel(path)}:{k.lineno} {fn.name}() reports "
                               f"{k.value} from `{v.id}` (default line {defaults[v.id]}, "
                               f"swallow line {swallows[0].lineno}) -> {sev} control")
    return out


def test_no_swallowed_failure_leaves_a_signal_at_its_default():
    """This is the shape that produced the CloudTrail bug and then, thirty
    lines away in the same file, the GuardDuty one that the CloudTrail fix
    missed. Detecting the shape is what stops the third."""
    offenders = [o for p in FILES for o in _signals_left_at_default(p)]
    assert not offenders, (
        "a control signal keeps its False default when every read failed, which "
        "reports a verdict nothing was observed for. Track whether anything was "
        "readable and omit the signals if not:\n  " + "\n  ".join(offenders))


# ══════════════════════════════════════════════════════════════════════
# 3. The tri-state has to survive the whole way to the engine.
# ══════════════════════════════════════════════════════════════════════
def test_the_check_engine_still_treats_an_absent_signal_as_not_applicable():
    """Everything above is only worth anything because None means
    NOT_APPLICABLE downstream. If that ever changed, every fix in this family
    would silently become a FAIL instead."""
    import inspect

    from app.services import control_checks
    src = inspect.getsource(control_checks.evaluate)
    assert "telemetry.get(s) is None" in src
    assert "NOT_APPLICABLE" in src


def test_every_pack_signal_is_reachable_from_some_connector():
    """A signal no connector emits is permanently NOT_APPLICABLE — the honest
    answer, but worth knowing about rather than discovering in an audit."""
    emitted = set()
    for path in (ROOT / "app" / "connectors").glob("*.py"):
        tree = ast.parse(path.read_text())
        for d in [n for n in ast.walk(tree) if isinstance(n, ast.Dict)]:
            emitted |= {k.value for k in d.keys
                        if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    orphans = sorted(SIGNALS - emitted)
    assert not orphans, (
        "the declarative pack reads signals no connector produces, so these "
        f"controls can never be anything but NOT_APPLICABLE: {orphans}")
