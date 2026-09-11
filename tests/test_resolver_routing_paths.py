"""Every branch of the ontology resolver's strategy loop.

`app/services/resolver.py` sits on the verdict path — it decides *which*
mechanism answers a control — and the CI coverage run puts it at **25%**: 83 of
its 110 statements never execute. Three test files mention the module, so it is
not unreached; it is barely exercised. That is the gap this file closes, and it
is a different gap from "has no tests at all".

The instrument is whitebox: read the loop, enumerate the ways through it, and
write one case per edge rather than per feature. `resolve()` has eleven distinct
outcomes and the existing suite reaches a handful.

    no binding for the control                    -> ValueError
    strategy's asset_types excludes this asset    -> skipped, try the next
    telemetry, no producer in available           -> skipped
    telemetry, producer present but unhealthy     -> skipped
    telemetry, producer present and healthy       -> chosen
    telemetry, only DEMO available                -> chosen as simulation
    document, no concept hits                     -> skipped
    document, concept hits present                -> chosen
    attestation, a record exists                  -> that record's status
    attestation, no record                        -> "not_assessed"
    nothing matched at all                        -> attestation floor

`resolve()` is lifted out of the module and run against fakes, the same way
tests/test_aws_absent_vs_negative.py lifts the AWS telemetry methods. That keeps
this a unit test of the decision logic: no database, no connector registry, no
SQLAlchemy. The document path is exercised with dry_run=True because the real
path imports evidence_policy inside the function body, and importing it here
would drag in the whole evidence stack to test a routing decision.

One thing this file deliberately pins rather than fixes, because fixing it is a
behaviour change that needs a decision: at line 141 of resolver.py,

    [h for h in hits if h.confirmed]

computes the confirmed subset and throws it away. The routing decision is made
on *any* hits, confirmed or not, so unconfirmed evidence still wins the document
strategy and `break`s before the attestation floor the module docstring calls
"the floor; never silently skipped". No wrong verdict results today —
evidence_policy re-checks confirmation at its own line 128 and refuses — but the
dead expression is a filter somebody meant to apply. test_unconfirmed_evidence_
still_wins_the_document_strategy records the behaviour as it actually is, so
that changing it is a visible decision rather than an accident.
"""
from __future__ import annotations

import ast
import pathlib
import textwrap

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESOLVER = ROOT / "app" / "services" / "resolver.py"


class _ConnectorError(Exception):
    pass


class _Row:
    """Stands in for an ORM row; attributes are whatever the test supplies."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Result:
    """What db.execute() returns, covering both call shapes resolve() uses."""

    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class _DB:
    """A session that answers each query from a queue the test sets up."""

    def __init__(self, hits=None, attestation=None):
        self.hits = hits or []
        self.attestation = [attestation] if attestation is not None else []
        self.added = []

    def execute(self, marker):
        # resolve() only ever selects concept hits or an attestation, and the
        # stub select() below records which.
        return _Result(self.hits if marker == "EvidenceConceptHit" else self.attestation)

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        pass

    def refresh(self, obj):
        obj.id = "decision-1"


class _Registry:
    """`healthy` names the connectors whose healthcheck() returns True.
    Anything in `raises` blows up instead, which is a different branch."""

    def __init__(self, healthy=(), raises=()):
        self.healthy, self.raises = set(healthy), set(raises)

    def get(self, source_system):
        if source_system in self.raises:
            raise _ConnectorError(f"{source_system} exploded")
        healthy = source_system in self.healthy
        return _Row(healthcheck=lambda: healthy)


def _select(model):
    """Record which table was queried without needing SQLAlchemy."""
    marker = getattr(model, "__name__", str(model))
    return _Row(where=lambda *a, **k: marker, __eq__=lambda _s, o: o == marker)


def _load():
    src = RESOLVER.read_text()
    tree = ast.parse(src)
    ns: dict = {
        "ConnectorError": _ConnectorError,
        "EvidenceConceptHit": type("EvidenceConceptHit", (), {"tenant_id": None,
                                                              "concept_id": _Row(in_=lambda *a: None)}),
        "ControlAttestation": type("ControlAttestation", (), {"tenant_id": None,
                                                              "framework": None,
                                                              "control_id": None}),
        "AssessmentRequest": lambda **kw: _Row(**kw),
        "RoutingDecision": lambda **kw: _Row(id=None, **kw),
        "select": _select,
        "Any": object,
    }
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in (
                "_connector_ok", "_pick_producer", "control_binding", "resolve"):
            exec(textwrap.dedent(ast.get_source_segment(src, node)), ns)  # noqa: S102
    return ns


NS = _load()


def _bind(*strategies):
    """Install a binding table containing one control, and return its name."""
    NS["bindings"] = lambda: {"frameworks": {"FW": {"C-1": {"strategies": list(strategies)}}}}
    return "C-1"


def _telemetry(producers, *, preference=10, asset_types=("*",)):
    return {"type": "telemetry", "plane": "p", "signal": "sig", "eval_control": "C-1",
            "producers": list(producers), "asset_types": list(asset_types),
            "preference": preference}


def _document(*, preference=50, concepts=("c1",), asset_types=("*",)):
    return {"type": "document", "plane": "attestation_document", "signal": "concepts",
            "concepts": list(concepts), "asset_types": list(asset_types),
            "preference": preference}


def _attestation(*, preference=99, asset_types=("*",)):
    return {"type": "attestation", "plane": "attestation_document",
            "signal": "human_attestation", "asset_types": list(asset_types),
            "preference": preference}


def _resolve(db, *, available=(), healthy=(), raises=(), asset=None, dry_run=True):
    NS["registry"] = _Registry(healthy=healthy, raises=raises)
    NS["AssessmentService"] = lambda _db: _Row(
        run_single=lambda _req: _Row(status=_Row(value="pass"),
                                     description="ran", finding_id="f-1"))
    return NS["resolve"](db, "t1", "FW", "C-1", asset=asset,
                         available_connectors=list(available), dry_run=dry_run)


# ── the guard clause ──
def test_a_control_with_no_binding_is_an_error_not_a_silent_pass():
    NS["bindings"] = lambda: {"frameworks": {}}
    with pytest.raises(ValueError) as excinfo:
        _resolve(_DB())
    assert "C-1" in str(excinfo.value)


# ── telemetry ──
def test_a_healthy_available_producer_is_chosen():
    _bind(_telemetry(["AWS"]), _attestation())
    out = _resolve(_DB(), available=["AWS"], healthy=["AWS"])
    assert out["chosen"]["type"] == "telemetry"
    assert out["chosen"]["module"] == "AWS"
    assert out["skipped"] == []


def test_a_producer_that_is_not_available_is_skipped_with_a_reason():
    _bind(_telemetry(["AWS"]), _attestation())
    out = _resolve(_DB(), available=[], healthy=["AWS"])
    assert out["chosen"]["type"] == "attestation"
    assert len(out["skipped"]) == 1
    assert "no available/healthy producer" in out["skipped"][0]["reason"]


def test_an_available_but_unhealthy_producer_is_skipped():
    """The branch that separates 'configured' from 'working'. A connector whose
    healthcheck fails must not be routed to, or the control is answered by a
    module that cannot reach its vendor."""
    _bind(_telemetry(["AWS"]), _attestation())
    out = _resolve(_DB(), available=["AWS"], healthy=[])
    assert out["chosen"]["type"] == "attestation"
    assert "no available/healthy producer" in out["skipped"][0]["reason"]


def test_a_connector_whose_healthcheck_raises_is_treated_as_unhealthy():
    """_connector_ok swallows every exception. That is defensible — a broken
    healthcheck should not take down routing — but it means 'errored' and
    'absent' are the same answer, so the skip reason is all the operator gets."""
    _bind(_telemetry(["AWS"]), _attestation())
    out = _resolve(_DB(), available=["AWS"], raises=["AWS"])
    assert out["chosen"]["type"] == "attestation"


def test_demo_stands_in_for_any_producer_and_is_labelled_as_simulation():
    """DEMO is a wildcard so the collect->evaluate path can be exercised before
    real credentials exist. It must be visibly a simulation in the record, or a
    demo run reads as a real assessment."""
    _bind(_telemetry(["AWS"]), _attestation())
    out = _resolve(_DB(), available=["DEMO"], healthy=["DEMO"])
    assert out["chosen"]["module"] == "DEMO (simulation)"
    assert "simulation" in out["chosen"]["module"]


def test_demo_does_not_override_a_real_producer_that_is_available():
    _bind(_telemetry(["AWS"]), _attestation())
    out = _resolve(_DB(), available=["AWS", "DEMO"], healthy=["AWS", "DEMO"])
    assert out["chosen"]["module"] == "AWS"


def test_executing_a_telemetry_strategy_records_the_finding():
    _bind(_telemetry(["AWS"]), _attestation())
    out = _resolve(_DB(), available=["AWS"], healthy=["AWS"], dry_run=False)
    assert out["status"] == "pass"
    assert out["finding_id"] == "f-1"
    assert out["executed"] is True


# ── asset-type filtering ──
def test_a_strategy_that_does_not_apply_to_this_asset_type_is_skipped():
    _bind(_telemetry(["AWS"], asset_types=["object_storage"]), _attestation())
    out = _resolve(_DB(), available=["AWS"], healthy=["AWS"],
                   asset={"type": "iam_user"})
    assert out["chosen"]["type"] == "attestation"
    assert "not in" in out["skipped"][0]["reason"]


def test_a_wildcard_asset_matches_every_strategy():
    """asset_type '*' is the 'any asset' case and must not be filtered out by
    a strategy that names specific types."""
    _bind(_telemetry(["AWS"], asset_types=["object_storage"]), _attestation())
    out = _resolve(_DB(), available=["AWS"], healthy=["AWS"], asset={})
    assert out["chosen"]["type"] == "telemetry"


# ── document ──
def test_document_strategy_is_skipped_when_no_concept_hits_exist():
    _bind(_document(), _attestation())
    out = _resolve(_DB(hits=[]))
    assert out["chosen"]["type"] == "attestation"
    assert "no evidence hits" in out["skipped"][0]["reason"]


def test_document_strategy_wins_when_hits_exist():
    hits = [_Row(concept_id="c1", confirmed=True, quote="q")]
    _bind(_document(), _attestation())
    out = _resolve(_DB(hits=hits))
    assert out["chosen"]["type"] == "document"
    assert out["chosen"]["concepts"] == ["c1"]


def test_unconfirmed_evidence_still_wins_the_document_strategy():
    """Recorded as-is, not asserted as correct — see the module docstring.

    resolver.py computes `[h for h in hits if h.confirmed]` and discards it, so
    routing is decided on any hit at all. A control whose only evidence is
    unconfirmed therefore never reaches the attestation floor. evidence_policy
    refuses to call it satisfied, so no false verdict escapes today; this test
    exists so that if somebody applies the filter the author clearly intended,
    the change shows up here as a deliberate one.
    """
    hits = [_Row(concept_id="c1", confirmed=False, quote="q")]
    _bind(_document(), _attestation())
    out = _resolve(_DB(hits=hits))
    assert out["chosen"]["type"] == "document", (
        "if this now routes to attestation, the discarded `confirmed` filter "
        "was applied — update this test and say so in the commit")


# ── attestation ──
def test_an_attestation_on_record_supplies_the_status():
    _bind(_attestation())
    att = _Row(status=_Row(value="satisfied"))
    out = _resolve(_DB(attestation=att), dry_run=False)
    assert out["status"] == "satisfied"
    assert "human attestation on record" in out["reason"]


def test_no_attestation_is_not_assessed_rather_than_failing():
    """The distinction this whole codebase turns on: nothing recorded is not a
    negative finding."""
    _bind(_attestation())
    out = _resolve(_DB(), dry_run=False)
    assert out["status"] == "not_assessed"
    assert "requires attestation" in out["reason"]


# ── ordering and the floor ──
def test_strategies_are_tried_in_preference_order():
    _bind(_attestation(preference=99), _telemetry(["AWS"], preference=10))
    out = _resolve(_DB(), available=["AWS"], healthy=["AWS"])
    assert out["chosen"]["type"] == "telemetry", (
        "a preference-10 telemetry strategy must beat a preference-99 "
        "attestation regardless of the order they appear in the binding")


def test_a_binding_with_no_usable_strategy_falls_through_to_the_floor():
    """The defensive branch. A binding whose only strategy excludes this asset
    leaves nothing chosen, and the module must still record a decision."""
    _bind(_telemetry(["AWS"], asset_types=["object_storage"]))
    out = _resolve(_DB(), available=[], asset={"type": "iam_user"})
    assert out["chosen"]["type"] == "attestation"
    assert out["chosen"]["module"] == "ATTEST"


def test_the_floor_reports_no_status_on_a_dry_run():
    _bind(_telemetry(["AWS"], asset_types=["object_storage"]))
    out = _resolve(_DB(), asset={"type": "iam_user"}, dry_run=True)
    assert out["status"] is None, "a dry run must not claim an outcome"
    assert out["executed"] is False


# ── the audit record ──
def test_every_resolution_writes_one_routing_decision():
    _bind(_telemetry(["AWS"]), _attestation())
    db = _DB()
    _resolve(db, available=["AWS"], healthy=["AWS"])
    assert len(db.added) == 1


def test_the_record_carries_the_skipped_alternatives():
    """The point of the decision log: why the alternatives lost, not just what
    won. Without this an auditor cannot tell a deliberate route from a default."""
    _bind(_telemetry(["AWS"]), _document(), _attestation())
    db = _DB(hits=[])
    out = _resolve(db, available=[])
    assert len(out["skipped"]) == 2
    assert {s["type"] for s in out["skipped"]} == {"telemetry", "document"}
    assert db.added[0].skipped == out["skipped"]
