"""One idempotency key must mean exactly one assessment.

`_idem_key` decides whether an incoming assessment is a repeat of one already
recorded. If two genuinely different assessments produce the same key, the
second one silently returns the first one's verdict — a control reporting a
status that was never measured for it. That is the defect class this codebase
keeps finding, arriving through a string format rather than a missing guard.

The old format joined caller-controlled fields with ':', a delimiter that is
legal — and in AWS, ubiquitous — inside those fields:

    f"{tenant_id}:{framework}:{control_id}:{source_system}:{asset_id}"

Three collisions were reachable and are pinned below. The third is the one that
matters most: it needs no unusual data at all, only a caller who supplies an
`idempotency_key` that happens to look like a derived one. Authorization does
not help, because both assessments are inside the same tenant.

The fix hashes a JSON array. JSON escapes the separator, so the encoding is
injective; `None` and `"None"` encode differently; and the two KINDS of key are
namespaced so a client-supplied one can never impersonate a derived one.
"""
from __future__ import annotations

import itertools

import pytest

from app.models import AssessmentRequest
from app.services.assessment import _idem_key, _legacy_idem_key


def req(**kw) -> AssessmentRequest:
    base = {"tenant_id": "acme", "framework": "NIST", "control_id": "AC-2",
            "source_system": "AWS"}
    return AssessmentRequest(**{**base, **kw})


# ── the three proven collisions ──
def test_a_client_key_cannot_impersonate_a_derived_one():
    """The serious one. A caller sending idempotency_key="NIST:AC-2:AWS:prod"
    produced exactly the key the platform derives for control AC-2 on asset
    "prod" — so they were handed, or overwrote, the verdict of a control they
    never assessed. No unusual data required."""
    impersonator = req(idempotency_key="NIST:AC-2:AWS:prod")
    derived = req(asset_id="prod")
    assert _legacy_idem_key(impersonator) == _legacy_idem_key(derived), (
        "precondition: this collided under the old format")
    assert _idem_key(impersonator) != _idem_key(derived)


def test_colons_in_an_asset_id_cannot_shift_a_field_boundary():
    """Every AWS ARN contains colons, so this is ordinary data, not an attack."""
    a = req(source_system="AWS", asset_id="arn:aws:s3:::bucket")
    b = req(source_system="AWS:arn", asset_id="aws:s3:::bucket")
    assert _legacy_idem_key(a) == _legacy_idem_key(b)
    assert _idem_key(a) != _idem_key(b)


def test_an_absent_asset_is_not_an_asset_named_none():
    """asset_id=None formatted as the literal "None", so an account-wide check
    and a single oddly-named asset shared one verdict."""
    absent, named = req(asset_id=None), req(asset_id="None")
    assert _legacy_idem_key(absent) == _legacy_idem_key(named)
    assert _idem_key(absent) != _idem_key(named)


# ── the property, rather than the three examples ──
_HOSTILE = ["", "a", "a:b", ":", "::", "None", "x:y:z", "arn:aws:s3:::b",
            "client", "derived", "acme", "NIST:AC-2:AWS"]


def test_distinct_assessments_never_share_a_key():
    """The examples above were found by reasoning; this is the property they
    are examples of. Any two different (framework, control, source, asset)
    tuples — or a client key against any of them — must differ."""
    seen: dict[str, tuple] = {}
    collisions = []
    for f, c, s, a in itertools.product(_HOSTILE[:6], _HOSTILE[:6],
                                        _HOSTILE[:6], [*_HOSTILE, None]):
        ident = ("derived", f, c, s, a)
        key = _idem_key(req(framework=f, control_id=c, source_system=s, asset_id=a))
        if seen.get(key, ident) != ident:
            collisions.append((seen[key], ident))
        seen[key] = ident
    for ck in _HOSTILE:
        ident = ("client", ck)
        key = _idem_key(req(idempotency_key=ck))
        if seen.get(key, ident) != ident:
            collisions.append((seen[key], ident))
        seen[key] = ident
    assert not collisions, f"{len(collisions)} distinct assessments share a key: {collisions[:3]}"


def test_the_same_assessment_always_gets_the_same_key():
    """Idempotency is worthless if the key is not stable."""
    for _ in range(3):
        assert _idem_key(req(asset_id="arn:aws:s3:::b")) == \
               _idem_key(req(asset_id="arn:aws:s3:::b"))


def test_the_tenant_is_part_of_the_key():
    """`_existing` looks up by primary key with no tenant predicate, which is
    only safe because the key itself carries the tenant. If that ever stopped
    being true, the lookup would become a cross-tenant read."""
    assert _idem_key(req(tenant_id="a")) != _idem_key(req(tenant_id="b"))


# ── the column ──
@pytest.mark.parametrize("field", ["asset_id", "idempotency_key"])
def test_the_key_fits_the_column_whatever_the_input(field):
    """`idempotency_keys.key` is String(256). The old format grew with its
    inputs — a realistic long ECS task-definition ARN already reached 254
    characters — so a slightly longer asset would have overflowed the column:
    an error on PostgreSQL, a silent truncation (and therefore a COLLISION) on
    databases that do not enforce length."""
    key = _idem_key(req(**{field: "x" * 4000}))
    assert len(key) <= 256
    assert len(key) < 100, "a hash should be short and fixed-width"


def test_key_length_does_not_depend_on_input_length():
    short = _idem_key(req(asset_id="a"))
    long = _idem_key(req(asset_id="a" * 3000))
    assert len(short) == len(long)


# ── the same flaw, in a second hand-built key ──
def test_an_external_scanner_id_cannot_impersonate_a_derived_key():
    """`record_external_finding` built its own key the same way:

        f"{tenant_id}:ext:{external_id or (control_id + ':' + (asset_id or ''))}"

    so a scanner posting external_id="AC-2:prod" produced exactly the key
    derived for control AC-2 on asset "prod" — one finding silently suppressing
    an unrelated one, because ingestion returns None when the key already
    exists. Not adversarial input; just a tool that puts colons in its ids.
    """
    from app.services.assessment import _hash_key

    impersonator = _hash_key("external", ["acme", "AC-2:prod", "X", None])
    derived = _hash_key("external", ["acme", None, "AC-2", "prod"])
    assert impersonator != derived

    def old(t, e, c, a):
        return f"{t}:ext:{e or (c + ':' + (a or ''))}"
    assert old("acme", "AC-2:prod", "X", None) == old("acme", None, "AC-2", "prod"), (
        "precondition: these collided under the old format")


def test_the_three_kinds_of_key_occupy_disjoint_spaces():
    """Derived, caller-supplied and externally-ingested keys all live in one
    column. Namespacing them is what stops one kind impersonating another."""
    from app.services.assessment import _hash_key

    keys = {_idem_key(req(asset_id="p")),
            _idem_key(req(idempotency_key="p")),
            _hash_key("external", ["acme", None, "AC-2", "p"])}
    assert len(keys) == 3


# ── migration safety ──
def test_a_record_written_under_the_old_format_is_still_found():
    """Changing the key format means every previously-assessed control misses
    and mints a duplicate finding. `_existing` takes a legacy key so the first
    assessment after this change still matches."""
    import inspect

    from app.services.assessment import AssessmentService
    src = inspect.getsource(AssessmentService._existing)
    assert "legacy_key" in src
    sig = inspect.signature(AssessmentService._existing)
    assert "legacy_key" in sig.parameters
    assert sig.parameters["legacy_key"].default is None


def test_the_legacy_format_is_still_computable():
    """It has to keep producing exactly what it used to, or the fallback looks
    up a key that was never written."""
    assert _legacy_idem_key(req(asset_id="prod")) == "acme:NIST:AC-2:AWS:prod"
    assert _legacy_idem_key(req(idempotency_key="k")) == "acme:k"
