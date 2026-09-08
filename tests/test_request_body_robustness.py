"""A malformed request body is a bad request, not a server error.

Iteration 4 of a fault-finding sweep, instrument: fuzzing the HTTP boundary.
The same instrument found 35 crashes in the standards adapters; the request
layer had never had it.

Seventeen routes accept a body typed only as `dict`. FastAPI validates the
outer object and **nothing inside it**, so every field arrives as whatever JSON
the caller sent, and any assumption the handler makes about shape is an
unhandled exception — a 500 with a stack trace in the log, where 400 or 422 is
the honest answer.

Three service functions reachable that way crashed on ordinary wrong types:

    POST /v1/ai-gov/assess-pet   {"pet":"differential_privacy","params":"x"}
        -> params.get()      AttributeError: 'str' object has no attribute 'get'
    POST /v1/ai-gov/assess-pet   {"pet":["x"]}
        -> PET_CATALOG.get() TypeError: unhashable type: 'list'
    POST /v1/ai-gov/score        {"pets":"abc"}
        -> iterating a string yields characters, and "a".get() raises
    POST /v1/ai-gov/score        {"pets":5}
        -> TypeError: 'int' object is not iterable
    POST /v1/documents/upload    {"filename":123,"content_base64":"eA=="}
        -> `or "upload"` only replaces a FALSY filename; 123 is truthy and has
           no .lower()

The fix is the one the adapters already use — app/services/shapes.py — because
the reading is the same: a field of the wrong type carries nothing, which is
exactly what an absent field carries.

This file keeps the fuzzer rather than pinning the inputs. The inputs were
never the point; the property is that no body produces a 500.
"""
from __future__ import annotations

import itertools

import pytest

from app.services import ai_governance as aigov

#: Values a client can put in any JSON field, deliberately including the ones
#: that are truthy (so `or default` does not save you) and unhashable (so a
#: dict lookup raises rather than missing).
HOSTILE = [
    None, "", "str", 0, -1, 1.5, True, False, [], [1, 2], {}, {"a": 1},
    {"pet": []}, float("nan"), 1e309, "abc", "x" * 2000,
    [{"pet": "differential_privacy", "params": "x"}], [{"pet": [1]}], [None],
]


# ── the service layer these routes reach ──
def test_assess_pet_never_raises():
    """`params` and `pet` both arrive unvalidated from the body."""
    pets = [*aigov.PET_CATALOG, "unknown", None, 123, [], {}, [1]]
    for pet, params in itertools.product(pets, HOSTILE):
        try:
            aigov.assess_pet(pet, params)
        except Exception as exc:  # noqa: BLE001 — that is the assertion
            pytest.fail(f"assess_pet({pet!r}, {params!r}) raised "
                        f"{type(exc).__name__}: {exc}")


def test_compute_privacy_risk_never_raises():
    for sensitivity, pets in itertools.product(HOSTILE, HOSTILE):
        try:
            aigov.compute_privacy_risk(sensitivity, pets)
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"compute_privacy_risk({sensitivity!r}, {pets!r}) raised "
                        f"{type(exc).__name__}: {exc}")


def test_ai_act_obligations_never_raises():
    for tier, governance in itertools.product(HOSTILE, HOSTILE):
        try:
            aigov.ai_act_obligations(tier, governance)
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"ai_act_obligations({tier!r}, {governance!r}) raised "
                        f"{type(exc).__name__}: {exc}")


# ── the specific readings, so a future "simplification" cannot undo them ──
@pytest.mark.parametrize("params", ["x", 5, [], [1, 2], True, None])
def test_a_malformed_params_object_carries_no_parameters(params):
    """Not a crash, and not an invented value: a params field that is not an
    object declares nothing, exactly like an absent one."""
    result = aigov.assess_pet("differential_privacy", params)
    assert result["pet"] == "differential_privacy"
    # the no-parameter reading, identical to what {} gives
    assert result == aigov.assess_pet("differential_privacy", {})


@pytest.mark.parametrize("pet", [["x"], {"a": 1}, 123, None])
def test_an_unhashable_or_non_string_pet_is_simply_unknown(pet):
    """PET_CATALOG.get(pet) raised "unhashable type" on a list, and the
    endpoint's `if not pet` guard passes a non-empty one straight through."""
    result = aigov.assess_pet(pet, {})
    assert result["known"] is False


@pytest.mark.parametrize("pets", ["abc", 5, True, {"pet": "x"}, [1, 2], None])
def test_a_malformed_pets_list_contributes_no_mitigation(pets):
    """A string iterates into characters and an int does not iterate at all.
    Both were 500s; both mean "no PETs were declared"."""
    result = aigov.compute_privacy_risk("phi", pets)
    assert result == aigov.compute_privacy_risk("phi", [])


def test_valid_input_still_produces_the_same_answer():
    """Hardening that quietly changed a score would pass every test above."""
    assert aigov.assess_pet("differential_privacy", {"epsilon": 0.5})["effectiveness"] == 0.95
    risk = aigov.compute_privacy_risk(
        "phi", [{"pet": "differential_privacy", "params": {"epsilon": 0.5}}])
    assert risk["inherent_risk"] == 80
    assert risk["residual_risk"] == 6


# ── the route that formatted an unvalidated field ──
def test_a_non_string_filename_does_not_reach_a_string_method():
    """`(payload.get("filename") or "upload").lower()` — `or` only replaces a
    FALSY value, so 123 or ["a.pdf"] went straight to .lower()."""
    import inspect

    from app import main
    src = inspect.getsource(main.doc_upload)
    assert 'str(payload.get("filename")' in src, (
        "the filename is used as a string without being coerced to one")


def test_no_route_calls_a_string_method_on_an_unvalidated_body_field():
    """The class, not the instance. A body typed `dict` is unvalidated inside,
    so `payload.get("x").strip()` is a 500 waiting for a client that sends a
    number."""
    import ast
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent.parent
    tree = ast.parse((root / "app" / "main.py").read_text())
    methods = {"lower", "upper", "strip", "endswith", "startswith", "split",
               "replace", "title", "rstrip", "lstrip"}
    offenders = []
    for fn in tree.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not [d for d in fn.decorator_list
                if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                and isinstance(d.func.value, ast.Name) and d.func.value.id == "app"]:
            continue
        raw = {a.arg for a in fn.args.args if a.annotation
               and ast.unparse(a.annotation) in ("dict", "dict[str, Any]",
                                                 "dict | None", "Any")}
        if not raw:
            continue
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in methods):
                continue
            inner = ast.unparse(node.func.value)
            if inner.startswith("str(") or inner.startswith("_as_text("):
                continue
            if any(re.search(rf"\b{name}\.get\(", inner) for name in raw):
                offenders.append(f"main.py:{node.lineno} {ast.unparse(node)[:70]}")
    assert not offenders, (
        "a string method is applied to a field that arrives unvalidated from a "
        "request body; wrap it in str() or reject it:\n  " + "\n  ".join(offenders))
