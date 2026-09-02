"""Capability surface + declarative control checks.

These tests guard the seam inversion: connectors declare probes (data), checks
declare what they need (data), and a resolver joins them. The most important
test here is `test_no_orphan_checks` — it fails the build if the check pack ever
promises a control no connector can actually satisfy, which is exactly the drift
that let the old control_bindings.json reference connectors that did not exist.
"""

from __future__ import annotations

import pytest

from app.connectors.aws import AWSConnector
from app.connectors.base import BaseConnector, ConnectorError
from app.connectors.capabilities import Probe, build_surface
from app.models import ControlStatus, Severity
from app.services import control_checks


# ──────────────────────────────────────────────────────────────────────────
# Check pack integrity
# ──────────────────────────────────────────────────────────────────────────
def test_pack_loads():
    checks = control_checks.load_checks()
    assert checks, "declarative check pack is empty"


def test_every_check_has_a_crosswalk():
    """A control with no framework mapping cannot appear in any report."""
    missing = [cid for cid, c in control_checks.all_checks().items() if not c.crosswalk]
    assert not missing, f"checks with no framework crosswalk: {missing}"


def test_no_orphan_checks():
    """Every declared check must be satisfiable by at least one connector.

    This is the guardrail that keeps declarative coverage honest: content can
    outrun the connectors, but the build should say so rather than shipping a
    control the platform silently cannot evaluate.
    """
    orphans = control_checks.orphan_checks()
    assert not orphans, f"checks no connector can satisfy: {orphans}"


def test_control_ids_are_unique_against_builtins():
    """The pack extends the catalog; it must not redefine a built-in control."""
    from app.policy.engine import CONTROL_CATALOG

    for cid, meta in CONTROL_CATALOG.items():
        if meta.get("declarative"):
            assert cid in control_checks.all_checks()


# ──────────────────────────────────────────────────────────────────────────
# Evaluation semantics
# ──────────────────────────────────────────────────────────────────────────
def test_missing_signal_is_not_applicable_never_fail():
    """"Could not observe" and "observed and wrong" must stay distinguishable."""
    for cid, check in control_checks.all_checks().items():
        status, reason, _ = control_checks.evaluate(check, {})
        assert status is ControlStatus.NOT_APPLICABLE, (
            f"{cid}: absent telemetry produced {status}, which would report an "
            f"unobserved control as a real finding")
        assert "unavailable" in reason.lower()


def test_partial_telemetry_is_not_applicable():
    """One missing signal is enough to make the whole check unevaluable."""
    check = control_checks.get("IA-5-PW-COMPLEXITY")
    assert check is not None
    partial = {
        "password_requires_symbols": True,
        "password_requires_numbers": True,
        "password_requires_uppercase": True,
        # password_requires_lowercase deliberately absent
    }
    status, _, _ = control_checks.evaluate(check, partial)
    assert status is ControlStatus.NOT_APPLICABLE


def test_boolean_check_pass_and_fail():
    check = control_checks.get("IA-2-ROOT-MFA")
    assert check is not None
    assert check.severity is Severity.CRITICAL

    status, reason, sev = control_checks.evaluate(check, {"root_mfa_enabled": True})
    assert status is ControlStatus.PASS
    assert sev is Severity.CRITICAL

    status, reason, _ = control_checks.evaluate(check, {"root_mfa_enabled": False})
    assert status is ControlStatus.FAIL
    assert "NOT" in reason or "not" in reason


def test_threshold_check_boundaries():
    """A >= threshold must pass exactly at the boundary, fail just under."""
    check = control_checks.get("IA-5-PW-LENGTH")
    assert check is not None
    assert control_checks.evaluate(check, {"password_min_length": 14})[0] is ControlStatus.PASS
    assert control_checks.evaluate(check, {"password_min_length": 13})[0] is ControlStatus.FAIL
    assert control_checks.evaluate(check, {"password_min_length": 64})[0] is ControlStatus.PASS


def test_inverted_threshold_check_boundaries():
    """Age-style checks pass below the limit and fail above it."""
    check = control_checks.get("AC-2-KEY-ROTATION")
    assert check is not None
    assert control_checks.evaluate(check, {"days_since_key_rotation": 90})[0] is ControlStatus.PASS
    assert control_checks.evaluate(check, {"days_since_key_rotation": 91})[0] is ControlStatus.FAIL


#: Signals naming a quantity where a *lower* reading is the compliant one.
_LOWER_IS_BETTER = ("days_since", "_count", "vulnerabilities")

#: Signals describing the situation a control applies to rather than whether it
#: is satisfied. Inverting one does not violate the control, it makes the
#: control inapplicable — flipping console_access_enabled turns "a login user
#: without MFA" into "not a login user", which passes for the wrong reason. The
#: same distinction the DEMO estate draws in app/connectors/mock.py.
_PRECONDITIONS = frozenset({"console_access_enabled"})

#: Numeric signals with a compliant floor the generic heuristic cannot guess.
_COMPLIANT_NUMBERS = {
    "password_min_length": 16,
    "password_reuse_prevention": 24,
    "password_max_age_days": 60,
    "backup_retention_days": 30,
    "retention_days": 400,
}

#: Booleans whose compliant value is False rather than True.
_COMPLIANT_FALSE = frozenset({
    "publicly_accessible", "root_access_keys_present", "has_inline_policy",
    "has_admin_policy", "public_ip_assigned", "unrestricted_ingress",
    "ssh_open_to_world", "rdp_open_to_world",
})


def test_every_check_evaluates_in_all_three_states():
    """Exercise the whole pack so a malformed expression cannot ship."""
    for cid, check in control_checks.all_checks().items():
        compliant: dict = {}
        for sig in check.requires:
            if sig in _COMPLIANT_NUMBERS:
                compliant[sig] = _COMPLIANT_NUMBERS[sig]
            elif any(tok in sig for tok in _LOWER_IS_BETTER):
                compliant[sig] = 0
            elif sig in _COMPLIANT_FALSE:
                compliant[sig] = False
            else:
                compliant[sig] = True

        status, _, _ = control_checks.evaluate(check, compliant)
        assert status is ControlStatus.PASS, f"{cid}: compliant telemetry did not pass"

        violating = {}
        for s, v in compliant.items():
            if s in _PRECONDITIONS:
                violating[s] = v          # keep the control applicable
            elif isinstance(v, bool):
                violating[s] = not v
            elif any(t in s for t in _LOWER_IS_BETTER):
                violating[s] = 9999
            else:
                violating[s] = 0
        status, _, _ = control_checks.evaluate(check, violating)
        assert status is ControlStatus.FAIL, f"{cid}: violating telemetry did not fail"


def test_invalid_expression_is_error_not_crash():
    from app.services.control_checks import Check

    bad = Check(
        control_id="TEST-BAD", title="bad", domain="Test", severity=Severity.LOW,
        asset_type="thing", plane="configuration", requires=("x",),
        expression="x.__class__", pass_reason="p", fail_reason="f",
    )
    status, reason, _ = control_checks.evaluate(bad, {"x": 1})
    assert status is ControlStatus.ERROR
    assert "expression" in reason.lower()


# ──────────────────────────────────────────────────────────────────────────
# Capability surface mechanics
# ──────────────────────────────────────────────────────────────────────────
def test_probe_covers():
    p = Probe(probe_id="p", asset_type="t", plane="configuration",
              signals=("a", "b", "c"))
    assert p.covers(["a", "b"])
    assert p.covers([])
    assert not p.covers(["a", "z"])


def test_resolver_prefers_narrowest_probe():
    """A one-signal need should not trigger an expensive wide probe."""
    narrow = Probe(probe_id="narrow", asset_type="t", plane="configuration", signals=("a",))
    wide = Probe(probe_id="wide", asset_type="t", plane="configuration",
                 signals=("a", "b", "c", "d"))
    surface = build_surface("TEST", [wide, narrow])
    assert surface.resolve("t", ["a"]).probe_id == "narrow"
    assert surface.resolve("t", ["a", "c"]).probe_id == "wide"
    assert surface.resolve("t", ["z"]) is None
    assert surface.resolve("other", ["a"]) is None


def test_duplicate_probe_id_rejected():
    p1 = Probe(probe_id="dup", asset_type="t", plane="configuration", signals=("a",))
    p2 = Probe(probe_id="dup", asset_type="t", plane="configuration", signals=("b",))
    with pytest.raises(ValueError, match="duplicate probe"):
        build_surface("TEST", [p1, p2])


def test_surface_is_readable_without_instantiation():
    """Coverage must be computable with no credentials present."""
    surface = AWSConnector.surface()
    assert surface.source_system == "AWS"
    assert len(surface.probes) >= 10
    assert "object_storage" in surface.asset_types()


# ──────────────────────────────────────────────────────────────────────────
# Connector dispatch through the inverted seam
# ──────────────────────────────────────────────────────────────────────────
class _FakeConnector(BaseConnector):
    source_system = "FAKE"
    PROBES = (
        Probe(probe_id="widget", asset_type="widget", plane="configuration",
              signals=("encryption_at_rest", "public_access_blocked")),
        Probe(probe_id="tenant", asset_type="fake_tenant", plane="configuration",
              requires_asset=False, signals=("logging_enabled",)),
        # A real asset type, so the dispatch path can be exercised end to end
        # against an actual check from the pack.
        Probe(probe_id="bucket", asset_type="object_storage", plane="data_protection",
              signals=("kms_encrypted",)),
    )

    def __init__(self):
        self.calls = []

    def healthcheck(self) -> bool:
        return True

    def collect_telemetry(self, control_id, asset_id, params):
        return self.collect_via_capability(control_id, asset_id, params)

    def run_probe(self, probe_id, asset_id, params):
        self.calls.append((probe_id, asset_id))
        return {"encryption_at_rest": True, "public_access_blocked": True,
                "logging_enabled": True, "kms_encrypted": True}


def test_unknown_control_is_rejected_clearly():
    c = _FakeConnector()
    with pytest.raises(ConnectorError, match="does not support control"):
        c.collect_telemetry("NOT-A-REAL-CONTROL", "x", {})


def test_control_with_no_matching_probe_is_rejected():
    """A real control this connector cannot observe must say so precisely."""
    c = _FakeConnector()
    with pytest.raises(ConnectorError, match="no probe emits"):
        # SC-28-RDS needs encryption_at_rest on a managed_database, not a widget.
        c.collect_telemetry("SC-28-DATABASE", "db-1", {})


def test_missing_asset_id_is_rejected_before_any_api_call():
    """Input validation must happen before the probe fires, not inside it."""
    c = _FakeConnector()
    # SC-28-OBJSTORE-KMS resolves to the fake object_storage probe, which needs
    # an asset — so this exercises the asset check, not the resolution failure.
    with pytest.raises(ConnectorError, match="requires an asset_id"):
        c.collect_telemetry("SC-28-OBJSTORE-KMS", None, {})
    assert c.calls == [], "connector must not probe before validating its input"


def test_resolved_probe_is_actually_invoked():
    c = _FakeConnector()
    telemetry = c.collect_telemetry("SC-28-OBJSTORE-KMS", "bucket-1", {})
    assert c.calls == [("bucket", "bucket-1")]
    assert telemetry["kms_encrypted"] is True


def test_aws_legacy_control_ids_still_use_handwritten_path():
    """The inversion must not change behaviour for the original controls.

    Existing findings, idempotency keys and stored evidence all depend on the
    legacy control ids resolving exactly as before.
    """
    import inspect

    src = inspect.getsource(AWSConnector.collect_telemetry)
    for legacy in ("AC-2-7", "AC-2-3", "SC-28", "SC-7", "AU-2"):
        assert legacy in src, f"legacy control {legacy} lost its explicit dispatch"
    assert "collect_via_capability" in src, "capability fallthrough is missing"


# ──────────────────────────────────────────────────────────────────────────
# Registry + catalog integration
# ──────────────────────────────────────────────────────────────────────────
def test_registry_exposes_surfaces_without_credentials():
    from app.connectors.registry import registry

    surfaces = registry.surfaces()
    assert "AWS" in surfaces
    assert registry.surface("aws") is not None
    assert registry.surface("NOPE") is None


def test_declarative_controls_reach_the_policy_catalog():
    """One JSON entry must surface everywhere the catalog is read.

    Instantiates RuleEngine directly rather than using the module-level
    `policy_engine` singleton: that singleton can be left pointing at an
    OPAEngine by tests elsewhere that reload the module under POLICY_ENGINE=opa,
    and what is under test here is the built-in catalog wiring, not which engine
    the process happens to have selected.
    """
    from app.policy.engine import CONTROL_CATALOG, RuleEngine

    assert "IA-2-ROOT-MFA" in CONTROL_CATALOG
    meta = CONTROL_CATALOG["IA-2-ROOT-MFA"]
    assert meta["declarative"] is True
    assert meta["severity"] is Severity.CRITICAL

    status, _reason, sev = RuleEngine().evaluate("IA-2-ROOT-MFA", {"root_mfa_enabled": False})
    assert status is ControlStatus.FAIL
    assert sev is Severity.CRITICAL

    status, _reason, _sev = RuleEngine().evaluate("IA-2-ROOT-MFA", {"root_mfa_enabled": True})
    assert status is ControlStatus.PASS


def test_declarative_crosswalk_reaches_frameworks():
    from app.frameworks import controls_for_framework, crosswalk_for

    assert "IA-2(1)" in crosswalk_for("IA-2-ROOT-MFA").get("NIST", [])
    nist_controls = controls_for_framework("NIST")
    assert "IA-2-ROOT-MFA" in nist_controls
    assert "AC-2-7" in nist_controls, "legacy crosswalk entries must survive the merge"


def test_builtin_controls_are_not_shadowed():
    """A pack entry must never override hand-written control behaviour."""
    from app.policy.engine import CONTROL_CATALOG

    for legacy in ("AC-2-7", "SC-28", "AU-2", "RA-5"):
        assert not CONTROL_CATALOG[legacy].get("declarative"), (
            f"{legacy} was replaced by a declarative check")


def test_coverage_matrix_reports_real_numbers():
    matrix = control_checks.coverage_matrix()
    assert matrix["total_checks"] == len(control_checks.all_checks())
    assert matrix["covered"] == matrix["total_checks"], "some checks are unsatisfiable"
    assert matrix["coverage_pct"] == 100.0
    row = next(r for r in matrix["checks"] if r["control_id"] == "IA-2-ROOT-MFA")
    assert "AWS" in row["producers"]
