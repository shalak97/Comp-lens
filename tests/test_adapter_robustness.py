"""A malformed evidence document is a bad request, not a server error.

The seven standards adapters parse documents that arrive over
`POST /v1/ingest/standard` — a SARIF log from someone's scanner, a CycloneDX
BOM from a build, an OCSF event from a SIEM. They are JSON, so every field can
be any type, and the idiom all seven reached for handles only two of the three
ways a field can be wrong:

    for run in log.get("runs") or []:

That copes with `runs` missing and with `runs: null`. It does not cope with
`runs: 5`, which passes straight through `or []` and raises
`TypeError: 'int' object is not iterable` from inside the adapter.

Structure-aware fuzzing of the seven adapters found **33 distinct crashes** of
that family, plus two more: an unhashable value used as a dict key
(`"class_uid": []`), and `int(Infinity)` on a timestamp. Every one turned a
malformed document into an HTTP 500 — the endpoint catches and logs a stack
trace — where 400 is the honest answer. A customer whose scanner emits a
slightly-off document got "internal server error" and nothing to act on.

The fix is `app/services/shapes.py`: `as_list`/`as_dict` treat a wrong-typed
field exactly like an absent one, which is the correct reading — a `runs` that
is not an array carries no runs.

This file keeps the fuzzer rather than pinning the 35 individual inputs. The
inputs were never the point; the property is: **no adapter raises on any
document.** A new adapter, or a new field access in an existing one, is
covered without anyone remembering to add a case.
"""
from __future__ import annotations

import json
import random

import pytest

from app.services import (
    cyclonedx,
    intoto,
    ocsf,
    sarif,
    sigstore,
    spdx,
    stix,
)
from app.services.shapes import as_dict, as_dicts, as_list, as_text

ADAPTERS = {
    "ocsf": ocsf.from_ocsf,
    "sarif": sarif.from_sarif,
    "cyclonedx": cyclonedx.from_cyclonedx,
    "spdx": spdx.from_spdx,
    "intoto": intoto.from_intoto,
    "stix": stix.from_stix,
    "sigstore": sigstore.from_sigstore,
}

#: A realistic document per format, as the mutation base.
SEEDS = {
    "ocsf": {"class_uid": 3002, "category_uid": 3, "severity_id": 3,
             "time": 1700000000, "actor": {"user": {"name": "u"}},
             "metadata": {"product": {"name": "P"}},
             "unmapped": {"is_encrypted": True}},
    "sarif": {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": [{"id": "r1"}]}},
        "results": [{"ruleId": "r1", "level": "error", "message": {"text": "m"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": "a.py"},
                         "region": {"startLine": 1}}}]}]}]},
    "cyclonedx": {"bomFormat": "CycloneDX", "specVersion": "1.6",
                  "components": [{"bom-ref": "p", "name": "n"}],
                  "vulnerabilities": [{"id": "CVE-1",
                                       "ratings": [{"severity": "high", "score": 8.1}],
                                       "affects": [{"ref": "p"}]}]},
    "spdx": {"spdxVersion": "SPDX-2.3", "creationInfo": {"creators": ["Tool: X"]},
             "packages": [{"name": "p", "versionInfo": "1", "externalRefs": [
                 {"referenceCategory": "SECURITY", "referenceLocator": "CVE-1"}]}]},
    "intoto": {"_type": "https://in-toto.io/Statement/v1",
               "predicateType": "https://slsa.dev/provenance/v1",
               "subject": [{"name": "a", "digest": {"sha256": "a" * 64}}],
               "predicate": {"runDetails": {"builder": {"id": "b"}}}},
    "stix": {"type": "bundle", "objects": [{"type": "vulnerability", "name": "V",
             "external_references": [{"source_name": "cve", "external_id": "CVE-1"}]}]},
    "sigstore": {"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
                 "dsseEnvelope": {"payload": "e30=",
                                  "payloadType": "application/vnd.in-toto+json",
                                  "signatures": [{"sig": "AA"}]}},
}

#: Values a hostile or merely buggy producer can put in any field.
HOSTILE = [None, True, 0, -1, 1e309, float("nan"), "", "x" * 5000, [], {},
           [[]] * 50, {"a": {"b": {"c": {}}}}, "../../etc/passwd", "\x00",
           {"__proto__": 1}]


def _mutate(obj, rng, depth=0):
    if depth > 6:
        return rng.choice(HOSTILE)
    r = rng.random()
    if isinstance(obj, dict):
        out = dict(obj)
        if r < 0.3 and out:
            out.pop(rng.choice(list(out)))
        elif r < 0.6 and out:
            k = rng.choice(list(out))
            out[k] = _mutate(out[k], rng, depth + 1)
        elif r < 0.8:
            out[rng.choice(["type", "id", "name", "x"])] = rng.choice(HOSTILE)
        else:
            return rng.choice(HOSTILE)
        return out
    if isinstance(obj, list):
        if r < 0.3:
            return rng.choice(HOSTILE)
        if r < 0.6 and obj:
            return [_mutate(v, rng, depth + 1) for v in obj]
        return [*obj, rng.choice(HOSTILE)]
    return rng.choice(HOSTILE)


# ── the property ──
@pytest.mark.parametrize("name", sorted(ADAPTERS))
def test_no_document_makes_an_adapter_raise(name):
    """2,000 mutations per adapter. A raise here is an HTTP 500 in production."""
    fn = ADAPTERS[name]
    rng = random.Random(f"seed-{name}")
    seed = SEEDS[name]
    for _ in range(2000):
        case = _mutate(json.loads(json.dumps(seed)), rng)
        try:
            fn(case)
        except Exception as exc:  # noqa: BLE001 — that is the thing being asserted
            pytest.fail(f"{name} raised {type(exc).__name__}: {exc}\n"
                        f"  on: {json.dumps(case, default=str)[:400]}")


@pytest.mark.parametrize("name", sorted(ADAPTERS))
@pytest.mark.parametrize("value", [None, True, 0, -1, "", [], {}, "x" * 1000])
def test_a_non_document_is_handled_rather_than_raising(name, value):
    """The top-level guard, which several adapters had and others relied on
    never being tested."""
    ADAPTERS[name](value)


@pytest.mark.parametrize(("name", "field"), [
    ("sarif", "runs"), ("cyclonedx", "vulnerabilities"), ("spdx", "packages"),
    ("stix", "objects"),
])
@pytest.mark.parametrize("wrong", [5, True, "text", {"not": "a list"}])
def test_a_list_field_of_the_wrong_type_carries_nothing(name, field, wrong):
    """The specific 33-crash family: `X or []` lets a non-list through, and the
    loop over it raises. A wrong-typed field means the document carries none of
    that thing — not that the server should fail."""
    doc = json.loads(json.dumps(SEEDS[name]))
    doc[field] = wrong
    assert ADAPTERS[name](doc) == []


@pytest.mark.parametrize("wrong", [5, True, "text", {"not": "a list"}])
def test_a_statement_with_a_malformed_subject_is_still_a_statement(wrong):
    """in-toto returns one object rather than a list, and a bad `subject` does
    not invalidate the statement around it — it just names no artifact. The
    point is that it does not raise, and does not invent a subject."""
    doc = json.loads(json.dumps(SEEDS["intoto"]))
    doc["subject"] = wrong
    ev = intoto.from_intoto(doc)
    assert ev is not None
    assert ev.asset_id is None
    assert ev.provenance["subjects"] == []


@pytest.mark.parametrize(("name", "field"), [
    ("ocsf", "metadata"), ("sarif", "runs"), ("spdx", "creationInfo"),
])
def test_a_dict_field_of_the_wrong_type_does_not_raise(name, field):
    for wrong in (5, True, "text", [1, 2], float("nan")):
        doc = json.loads(json.dumps(SEEDS[name], default=str))
        doc[field] = wrong
        ADAPTERS[name](doc)


def test_a_non_finite_timestamp_does_not_overflow():
    """`int(Infinity)` raised OverflowError out of the OCSF adapter."""
    for t in (float("inf"), float("-inf"), float("nan"), 1e309):
        ev = ocsf.from_ocsf({"class_uid": 3002, "time": t})
        assert ev is not None and ev.observed_at


@pytest.mark.parametrize("unhashable", [[], {}, [1, 2], {"a": 1}])
def test_an_unhashable_type_id_is_not_used_as_a_key(unhashable):
    """`_CLASS_CONCEPTS.get(class_uid)` with a list raised `unhashable type`."""
    ocsf.from_ocsf({"class_uid": unhashable, "category_uid": unhashable, "time": 1})
    stix.from_stix({"type": "bundle", "objects": [{"type": unhashable, "name": "x"}]})


# ── the helpers themselves ──
@pytest.mark.parametrize(("value", "want"), [
    ([1, 2], [1, 2]), (None, []), (5, []), (True, []), ("abc", []), ({}, []),
])
def test_as_list(value, want):
    assert as_list(value) == want


def test_as_list_does_not_split_a_string():
    """`"objects": "abc"` means the producer sent something wrong, not three
    objects — the failure mode a naive `list(value)` would introduce."""
    assert as_list("abc") == []


@pytest.mark.parametrize(("value", "want"), [
    ({"a": 1}, {"a": 1}), (None, {}), (5, {}), ([], {}), ("abc", {}),
])
def test_as_dict(value, want):
    assert as_dict(value) == want


def test_as_dicts_keeps_only_the_objects():
    assert as_dicts([{"a": 1}, 5, None, {"b": 2}, "x"]) == [{"a": 1}, {"b": 2}]


def test_as_text_never_raises():
    for value in (None, 5, [], {}, float("nan"), object()):
        assert isinstance(as_text(value), str)
    assert as_text("abcdef", 3) == "abc"


# ── and the adapters still do their job ──
@pytest.mark.parametrize("name", sorted(ADAPTERS))
def test_a_well_formed_document_still_produces_evidence(name):
    """Hardening that quietly stopped extracting anything would pass every test
    above. `intoto` and `sigstore` return a single object; the rest a list."""
    result = ADAPTERS[name](SEEDS[name])
    assert result, f"{name} extracted nothing from a valid document"
