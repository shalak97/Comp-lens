"""A control signal the platform could not observe is not a failing control.

app/services/control_checks.evaluate() states the rule the whole product rests
on: "we could not observe this" and "we observed it and it is wrong" are
different claims, and conflating them is how a compliance tool ends up lying to
an auditor. It returns NOT_APPLICABLE for any absent signal.

The legacy evaluators in app/policy/engine.py — which still back the ten
original controls (AC-2-7, SC-7, SC-28, AU-2, CM-3, SA-15-*, ...) — did not all
follow it. Three were tri-state; the other seven read `is True` and returned
FAIL for everything else, so a signal that was never collected became a
confident finding that the control was violated.

That direction fails closed, which is why it went unnoticed, but it is still a
fabricated finding: "secret scanning is disabled" when the truth is "our token
could not read whether secret scanning is enabled". It puts remediation work in
front of a customer for a control nobody actually assessed.

Connectors leave signals unset routinely — app/connectors/aws.py swallows
per-call IAM/KMS/CloudTrail errors and leaves the field None by design, and any
connector simply omits signals its provider doesn't expose.
"""
from __future__ import annotations

import pytest

from app.models import ControlStatus
from app.policy.engine import CONTROL_CATALOG

# control_id -> the telemetry key its evaluator reads
BOOLEAN_CONTROLS = [
    ("AC-2-7", "mfa_enforced"),
    ("SA-15-BRANCH", "branch_protection_enabled"),
    ("SA-15-SECRETS", "secret_scanning_enabled"),
    ("SC-28", "encryption_at_rest"),
    ("SC-7", "public_access_blocked"),
    ("AU-2", "logging_enabled"),
    ("CM-3", "change_has_approval"),
    ("SC-28-HOST", "disk_encrypted"),
]


@pytest.mark.parametrize(("control_id", "field"), BOOLEAN_CONTROLS)
def test_unobserved_signal_is_not_applicable(control_id, field):
    """The regression itself: an absent signal must not read as a violation."""
    evaluate = CONTROL_CATALOG[control_id]["evaluator"]
    status, reason = evaluate({})
    assert status is ControlStatus.NOT_APPLICABLE, (
        f"{control_id}: a signal that was never collected reported {status.value}, "
        f"which asserts a finding no evidence supports")
    assert "unavailable" in reason.lower(), (
        f"{control_id}: the reason should say the signal was unavailable, got {reason!r}")


@pytest.mark.parametrize(("control_id", "field"), BOOLEAN_CONTROLS)
def test_explicit_none_is_treated_as_unobserved(control_id, field):
    """A present-but-None key is the same as an absent one — this is the shape
    AWS telemetry actually produces when a per-call error is swallowed."""
    evaluate = CONTROL_CATALOG[control_id]["evaluator"]
    status, _ = evaluate({field: None})
    assert status is ControlStatus.NOT_APPLICABLE


@pytest.mark.parametrize(("control_id", "field"), BOOLEAN_CONTROLS)
def test_observed_true_passes(control_id, field):
    status, _ = CONTROL_CATALOG[control_id]["evaluator"]({field: True})
    assert status is ControlStatus.PASS


@pytest.mark.parametrize(("control_id", "field"), BOOLEAN_CONTROLS)
def test_observed_false_still_fails(control_id, field):
    """The half that must not change. A real violation stays a real violation;
    only the unobserved case was reclassified."""
    status, _ = CONTROL_CATALOG[control_id]["evaluator"]({field: False})
    assert status is ControlStatus.FAIL


def test_every_catalog_entry_has_an_evaluator_returning_a_valid_status():
    """Cheap structural guard over the whole catalog, including the controls
    merged in from the declarative pack."""
    for control_id, meta in CONTROL_CATALOG.items():
        evaluate = meta.get("evaluator")
        assert callable(evaluate), f"{control_id} has no callable evaluator"
        status, reason = evaluate({})
        assert isinstance(status, ControlStatus), f"{control_id} returned {status!r}"
        assert isinstance(reason, str) and reason, f"{control_id} returned an empty reason"


def test_no_control_reports_a_violation_from_empty_telemetry():
    """The invariant behind all of the above, stated once over the real catalog.

    Given no telemetry at all, nothing may claim a control is failing. A
    connector that collected nothing must produce "not assessed", never a
    remediation queue full of findings the platform invented.
    """
    fabricated = []
    for control_id, meta in CONTROL_CATALOG.items():
        status, _ = meta["evaluator"]({})
        if status is ControlStatus.FAIL:
            fabricated.append(control_id)
    assert not fabricated, (
        "these controls report FAIL on empty telemetry, inventing findings from "
        f"the absence of evidence: {fabricated}")
