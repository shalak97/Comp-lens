"""The vocabulary joining connectors to controls, made checkable.

`capabilities.py` inverted the connector/control relationship — probes declare
what they observe, controls are data, a resolver matches them. The join is a
signal name, and until now nothing declared what a signal *was*. Two halves of
one design; only one was built.

The cost of the missing half is not hypothetical. Nearly every defect fixed in
this codebase was one shape: a value meaning "we could not observe this"
emitted as `False`, meaning "we observed this is false". `None` ->
NOT_APPLICABLE held that line by convention, and a convention is a thing you
can forget. `absence: "unobserved"` in the registry is a thing a loader can
check.

These tests are the enforcement. They exist to fail when:

  * a check requires a signal nothing declares (today: the control becomes
    permanently NOT_APPLICABLE, which looks exactly like the honest answer);
  * a probe promises a signal the registry has never heard of;
  * a check compares a signal against a literal of the wrong type;
  * a control is decided on metadata like `owner`, which is an org chart;
  * the plane vocabulary forks again — it already had, silently, across three
    copies.
"""
from __future__ import annotations

import ast
import json
import pathlib

import pytest

from app import signals

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACK = json.loads((ROOT / "app" / "data" / "control_checks.json").read_text())
ONTOLOGY = json.loads((ROOT / "app" / "data" / "telemetry_ontology.json").read_text())


def _probe_declarations() -> list[tuple[str, str, str, set[str]]]:
    """(file, probe_id, plane, signals) for every statically-declared Probe."""
    out = []
    for path in (ROOT / "app" / "connectors").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "Probe"):
                continue
            kw = {k.arg: k.value for k in node.keywords}
            pid = getattr(kw.get("probe_id"), "value", None)
            plane = getattr(kw.get("plane"), "value", None)
            sig = kw.get("signals")
            names = ({e.value for e in sig.elts if isinstance(e, ast.Constant)}
                     if isinstance(sig, (ast.Tuple, ast.List)) else set())
            if pid:
                out.append((path.name, pid, plane, names))
    return out


# ── the pack ──
def test_every_signal_a_check_requires_is_declared():
    """A typo here is invisible: the resolver finds no probe emitting the
    misspelled name, and the control reports NOT_APPLICABLE forever — the same
    answer it would honestly give if nothing observed it."""
    missing = signals.unregistered_in_pack(PACK)
    assert not missing, (
        "control_checks.json requires signals that nothing declares. Add them "
        f"to app/data/signal_registry.json, or fix the spelling: {missing}")


def test_no_control_is_decided_on_metadata():
    """`owner` routes a finding to a team. Deciding a control on it would be
    deciding compliance on an org chart."""
    offenders = signals.metadata_used_as_evidence(PACK)
    assert not offenders, offenders


def test_no_check_compares_a_signal_against_the_wrong_type():
    """`encryption_at_rest >= 14` and `password_min_length == true` are both
    expressible today, and neither fails loudly — the evaluator coerces and
    the control returns a verdict nobody could defend in an audit."""
    conflicts = signals.type_conflicts(PACK)
    assert not conflicts, conflicts


def test_the_pack_validates_clean():
    assert signals.validate_all(PACK) == []


# ── the probes ──
def test_every_probe_signal_is_declared():
    """`Probe.signals` is a promise about vocabulary. Nothing verified it, so
    a new connector could invent a name that no check would ever match."""
    offenders = []
    for fname, pid, _plane, names in _probe_declarations():
        unknown = sorted(n for n in names if n not in signals.REGISTRY)
        if unknown:
            offenders.append(f"{fname}:{pid} -> {unknown}")
    assert not offenders, (
        "probes declare signals the registry has never heard of. Add them to "
        f"app/data/signal_registry.json with a type and a meaning: {offenders}")


def test_every_probe_is_on_a_known_plane():
    known = set(ONTOLOGY["planes"])
    offenders = [f"{f}:{p} plane={pl}" for f, p, pl, _ in _probe_declarations()
                 if pl is not None and pl not in known]
    assert not offenders, offenders


# ── one vocabulary, not three ──
def test_the_plane_vocabulary_has_a_single_source():
    """This is the failure the registry exists to prevent, and it had already
    happened one level up: capabilities.PLANES was a hand-written frozenset,
    telemetry_ontology.json had its own list, and they disagreed on five
    entries. Three planes that over half the platform's probes actually use —
    data_protection, logging_monitoring, network_boundary — were missing from
    the ontology entirely, so those probes silently fell out of every
    ontology-grouped view."""
    from app.connectors import capabilities

    assert capabilities.PLANES == frozenset(ONTOLOGY["planes"]), (
        "capabilities.PLANES must be derived from telemetry_ontology.json, "
        "not maintained alongside it")


def test_every_signal_sits_on_a_plane_the_ontology_knows():
    unknown = sorted({s.plane for s in signals.REGISTRY.values()}
                     - set(ONTOLOGY["planes"]))
    assert not unknown, unknown


# ── the tri-state, as a declaration rather than a habit ──
def test_absence_means_unobserved_everywhere():
    """The whole defect class in one assertion.

    If a signal ever declares that absence carries information, that is a
    decision someone must write down and argue for — because every instance of
    that reasoning found in this codebase so far has turned out to be a bug
    that either invented a breach or hid one.
    """
    odd = {n: s.absence for n, s in signals.REGISTRY.items()
           if s.absence != "unobserved"}
    assert not odd, (
        "a signal claims absence means something other than 'we did not "
        f"observe it': {odd}. See tests/test_no_verdict_without_evidence.py "
        "for why that has always been wrong here.")


def test_none_is_always_an_acceptable_value():
    """None is how a connector says 'unobserved'. If the registry rejected it,
    connectors would be pushed back toward the False that caused every bug in
    this family."""
    for sig in signals.REGISTRY.values():
        assert sig.accepts(None), sig.name


# ── value conformance: the half Probe.signals never checked ──
@pytest.mark.parametrize(("name", "value", "ok"), [
    ("encryption_at_rest", True, True),
    ("encryption_at_rest", False, True),
    ("encryption_at_rest", None, True),
    ("encryption_at_rest", "yes", False),
    ("encryption_at_rest", 1, False),
    ("password_min_length", 14, True),
    ("password_min_length", True, False),
    ("password_min_length", "14", False),
    ("owner", "identity-team", True),
])
def test_a_value_is_checked_against_what_the_signal_declares(name, value, ok):
    assert signals.REGISTRY[name].accepts(value) is ok


def test_a_bool_is_not_an_acceptable_integer():
    """Python says `isinstance(True, int)`, so a naive check would accept
    `password_min_length=True` and compare it as 1 — a password policy of one
    character, reported as compliant."""
    assert signals.REGISTRY["password_min_length"].accepts(True) is False


def test_nonconforming_values_are_reported_not_raised():
    bad = signals.nonconforming_values(
        {"encryption_at_rest": "yes", "password_min_length": 14, "unknown_thing": 1})
    assert len(bad) == 1
    assert "encryption_at_rest" in bad[0]


# ── the registry itself ──
def test_every_signal_says_what_it_means():
    """A registry of names with no meanings is a spellchecker."""
    thin = [n for n, s in signals.REGISTRY.items() if len(s.meaning.strip()) < 20]
    assert not thin, f"these signals need a real one-line meaning: {thin}"


def test_numeric_signals_carry_a_unit():
    """`password_max_age_days` — days or seconds? A check comparing against
    the wrong unit passes silently, which is the expensive kind of wrong."""
    missing = [n for n, s in signals.REGISTRY.items()
               if s.type == "int" and s.is_evidence and not s.unit]
    assert not missing, f"numeric signals with no declared unit: {missing}"


def test_the_registry_covers_what_the_platform_actually_uses():
    """Guards against the registry being added and then quietly bypassed."""
    declared = set().union(*(n for _, _, _, n in _probe_declarations())) \
        if _probe_declarations() else set()
    required = {s for c in PACK["checks"] for s in c.get("requires", [])}
    assert (declared | required) <= set(signals.REGISTRY)
    assert len(signals.REGISTRY) >= len(declared | required)
