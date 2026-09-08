"""The vocabulary that joins connectors to controls.

`app/connectors/capabilities.py` inverted the connector/control relationship:
probes declare what they observe, controls are declarative data, and a resolver
matches them. That inversion has two halves and only one of them was built.

A probe says `signals=("encryption_at_rest", ...)`. A check says
`"requires": ["encryption_at_rest"]`. The two are joined by **string
equality**, and nothing anywhere declares what that string means. So the
vocabulary had no owner, and everything that follows from that was left to
whoever wrote the next connector:

  * **What absence means.** This is the one that mattered. Roughly sixty
    defects fixed in this codebase were the same shape — a value meaning "we
    could not observe this" emitted as ``False``, meaning "we observed this is
    false", turning an under-provisioned IAM role into a critical finding or a
    missing read into a passing control. ``None`` -> NOT_APPLICABLE was a
    convention held up by review and, latterly, by
    tests/test_no_verdict_without_evidence.py. A convention is a thing you can
    forget; ``"absence": "unobserved"`` is a thing the loader can check.

  * **Type.** ``password_max_age_days`` — days or seconds? Nothing said, so a
    check comparing it against the wrong unit would pass silently, and a
    connector emitting a string where a bool was meant would flow all the way
    to a verdict.

  * **Which plane it belongs to.** Planes were declared on the *probe*, so the
    same signal sits on ``identity_access`` when AWS emits it and
    ``logging_monitoring`` when Azure does. The plane is a property of the
    fact, not of who noticed it.

  * **Whether a name is real at all.** Misspell a signal in a connector and it
    is emitted and never read. Misspell it in control_checks.json and the
    control becomes permanently NOT_APPLICABLE — indistinguishable from the
    honest answer this product exists to give.

There is no free tool that does this for compliance posture. The closest
analogue is OpenTelemetry's semantic-convention registry and its Weaver
live-check, which is the same shape — declare the vocabulary, then verify
emitters conform — but for observability telemetry, not control evidence. This
is that idea applied here.

The registry data lives in ``app/data/signal_registry.json``. This module
loads it and provides the checks; ``validate_all()`` is what CI runs.
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass
from typing import Any

_DATA = pathlib.Path(__file__).resolve().parent / "data" / "signal_registry.json"

#: Python types a declared signal type maps to. `int` accepts bools in Python,
#: so the check below is stricter than isinstance.
_TYPES: dict[str, tuple[type, ...]] = {
    "bool": (bool,),
    "int": (int, float),
    "string": (str,),
}


@dataclass(frozen=True)
class Signal:
    """One fact a connector can observe about an asset."""

    name: str
    type: str
    plane: str
    kind: str
    """``signal`` — read by checks. ``metadata`` — carried alongside (owner,
    asset, principal) and never used as evidence for a verdict."""

    meaning: str
    absence: str
    """What it means for this signal to be missing from a telemetry dict.

    ``unobserved`` — we did not find out. The check must report
    NOT_APPLICABLE, never a pass or a fail. This is the only value currently
    in use, and that is deliberate: a signal where absence carried information
    would need a written argument, because every instance of that reasoning
    found in this codebase so far has been a bug.
    """

    emitted_by: tuple[str, ...] = ()
    unit: str | None = None

    @property
    def is_evidence(self) -> bool:
        return self.kind == "signal"

    def accepts(self, value: Any) -> bool:
        """True if ``value`` is a shape this signal is declared to carry.

        ``None`` is always acceptable: it is how a connector says "unobserved",
        and refusing it here would push connectors back toward the ``False``
        that caused the whole defect class.
        """
        if value is None:
            return True
        if self.type == "int" and isinstance(value, bool):
            return False          # bool is an int in Python; not the same fact
        return isinstance(value, _TYPES[self.type])


def _load() -> dict[str, Signal]:
    raw = json.loads(_DATA.read_text())
    out: dict[str, Signal] = {}
    for name, s in raw["signals"].items():
        out[name] = Signal(
            name=name, type=s["type"], plane=s["plane"], kind=s["kind"],
            meaning=s["meaning"], absence=s["absence"],
            emitted_by=tuple(s.get("emitted_by", ())), unit=s.get("unit"))
    return out


REGISTRY: dict[str, Signal] = _load()

#: Canonical plane vocabulary, derived from the registry rather than repeated.
#: `capabilities.PLANES` and `telemetry_ontology.json` each had their own copy
#: and had already drifted apart on five entries.
PLANES: frozenset[str] = frozenset(s.plane for s in REGISTRY.values())


def get(name: str) -> Signal | None:
    return REGISTRY.get(name)


def evidence_signals() -> set[str]:
    """Names a check may legitimately require."""
    return {n for n, s in REGISTRY.items() if s.is_evidence}


# ══════════════════════════════════════════════════════════════════
# Validation — what CI enforces
# ══════════════════════════════════════════════════════════════════
def unregistered_in_pack(pack: dict) -> list[str]:
    """Signals control_checks.json requires that nothing declares.

    A typo here makes a control permanently NOT_APPLICABLE, which reads
    exactly like the honest answer and so is never noticed.
    """
    required = {s for c in pack["checks"] for s in c.get("requires", [])}
    return sorted(required - set(REGISTRY))


def metadata_used_as_evidence(pack: dict) -> list[str]:
    """Checks requiring a field that is not evidence.

    ``owner`` is for routing a finding to a team; deciding a control on it
    would be deciding compliance on an org chart.
    """
    out = []
    for c in pack["checks"]:
        for s in c.get("requires", []):
            sig = REGISTRY.get(s)
            if sig and not sig.is_evidence:
                out.append(f"{c['control_id']} requires {s!r} ({sig.kind})")
    return sorted(out)


def type_conflicts(pack: dict) -> list[str]:
    """Checks comparing a signal against a literal of the wrong type.

    `encryption_at_rest >= 14` or `password_min_length == true` are both
    expressible today and neither fails loudly — the expression evaluator
    coerces, and the control quietly returns a verdict nobody can defend.
    """
    import re

    out = []
    for c in pack["checks"]:
        expr = c.get("expression", "")
        for name in c.get("requires", []):
            sig = REGISTRY.get(name)
            if sig is None:
                continue
            for m in re.finditer(
                    re.escape(name) + r"\s*(==|!=|>=|<=|>|<)\s*([A-Za-z0-9_.\"']+)", expr):
                op, literal = m.group(1), m.group(2)
                is_bool_lit = literal in ("true", "false", "True", "False")
                is_num_lit = re.fullmatch(r"-?\d+(\.\d+)?", literal) is not None
                if sig.type == "bool" and is_num_lit:
                    out.append(f"{c['control_id']}: {name} is bool but compared "
                               f"with number ({op}{literal})")
                elif sig.type == "int" and is_bool_lit:
                    out.append(f"{c['control_id']}: {name} is {sig.type} but "
                               f"compared with {literal}")
                elif sig.type == "bool" and op in (">", "<", ">=", "<="):
                    out.append(f"{c['control_id']}: {name} is bool but ordered "
                               f"with {op}")
    return sorted(set(out))


def nonconforming_values(telemetry: dict[str, Any]) -> list[str]:
    """Emitted values whose shape contradicts the registry.

    Connectors call this in tests; it is the half of the promise that
    `Probe.signals` never checked — that what comes back is what was declared.
    """
    out = []
    for name, value in telemetry.items():
        sig = REGISTRY.get(name)
        if sig is None:
            continue
        if not sig.accepts(value):
            out.append(f"{name}={value!r} ({type(value).__name__}) but declared "
                       f"{sig.type}")
    return sorted(out)


def validate_all(pack: dict) -> list[str]:
    """Every registry-level problem, as a list of sentences. Empty is good."""
    return [*(f"unregistered signal required by a check: {s}"
              for s in unregistered_in_pack(pack)),
            *(f"non-evidence field used as evidence: {s}"
              for s in metadata_used_as_evidence(pack)),
            *type_conflicts(pack)]
