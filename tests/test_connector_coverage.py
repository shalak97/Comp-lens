"""Multi-cloud parity and the newly-implemented security tools.

The platform's central claim is that a check written once runs unchanged
against any cloud whose connector emits the same normalized signals. That was
true in principle and thin in practice: of 38 declarative checks, AWS could
satisfy all 38 while Azure managed 6 and GCP 4. A customer not on AWS was
buying a control catalog the product could barely evaluate for them.

These tests pin the parity that closed that gap, and — just as importantly —
pin the places where the gap was left open on purpose. A signal is only
declared when the cloud genuinely exposes an equivalent. Azure has no root
user, no CloudTrail digest validation and no IMDSv2; inventing values for
those would turn "we cannot observe this" into a compliance claim, which is
the failure this codebase exists to prevent. Those checks stay AWS-only, and
the test below says so by name so that stays a decision rather than a gap
nobody noticed.
"""
from __future__ import annotations

import pytest

from app.connectors.registry import registry
from app.services import control_checks


def _satisfied_by_any(check) -> list[str]:
    return [n for n in registry.supported() if n != "DEMO"
            and (s := registry.surface(n)) and s.resolve(check.asset_type, check.requires)]


def _covered(source_system: str) -> set[str]:
    surface = registry.surface(source_system)
    assert surface is not None, f"{source_system} is not registered"
    return {cid for cid, c in control_checks.all_checks().items()
            if surface.resolve(c.asset_type, c.requires)}


# Checks that read an AWS-specific construct. Each has no honest counterpart on
# another cloud, so no other connector should claim it.
AWS_ONLY = {
    "AC-6-ROOT-KEYS",              # no root user exists on Azure or GCP
    "IA-2-ROOT-MFA",               # ditto
    "AU-9-LOG-VALIDATION",         # no digest validation for Azure/GCP audit logs
    "AU-9-TRAIL-ENCRYPTION",       # no trail object to key
    "CM-8-CONFIG-RECORDER",        # AWS Config has no single equivalent service
    "CM-8-CONFIG-ALL-RESOURCES",
    "IA-5-PW-LENGTH",              # Entra/Google password policy is not per-rule readable
    "IA-5-PW-COMPLEXITY",
    "IA-5-PW-REUSE",
    "SC-7-IMDSV2",                 # no v1/v2 metadata split off AWS
    # Signals only the AWS probes collect today. Azure and GCP could answer
    # these — an inactive-principal query, a password expiry policy, a disk's
    # key custody — so unlike the entries above these are a gap to close, not
    # a concept that does not exist off AWS.
    "AC-2-INACTIVE-ACCOUNT",
    "IA-5-PW-MAX-AGE",
    "SC-28-BLOCKSTORE-KMS",
}

#: Asset types that belong to the scanning and SIEM connectors rather than to
#: any cloud. Checks on these are not "AWS-only" — no cloud provider is the
#: right answer for a Splunk index or a Snyk project — so they sit outside the
#: portable/AWS-only split entirely.
NON_CLOUD_ASSET_TYPES = {"host", "code_repository", "log_index"}


def test_aws_still_covers_every_declarative_check():
    assert _covered("AWS") == set(control_checks.all_checks())


@pytest.mark.parametrize(("cloud", "floor"), [("AZURE", 24), ("GCP", 20)])
def test_secondary_clouds_have_real_coverage(cloud, floor):
    """Azure was at 6 and GCP at 4 before this work; the floors here are set
    just under what they reach now, so a regression that quietly drops probes
    fails rather than silently shrinking multi-cloud support."""
    covered = _covered(cloud)
    assert len(covered) >= floor, (
        f"{cloud} covers only {len(covered)} checks, expected at least {floor}")


@pytest.mark.parametrize("cloud", ["AZURE", "GCP"])
def test_no_cloud_claims_an_aws_specific_check(cloud):
    """The deliberate gaps. Emitting these would be fabricating evidence."""
    overreach = _covered(cloud) & AWS_ONLY
    assert not overreach, (
        f"{cloud} claims checks that read AWS-specific constructs: {sorted(overreach)}")


def test_every_check_is_covered_by_aws_or_deliberately_aws_only():
    """Nothing falls outside the three categories: a cloud check is either
    portable (some non-AWS cloud can satisfy it) or explicitly listed as
    AWS-only, and anything on a non-cloud asset type is out of scope for this
    split."""
    all_checks = control_checks.all_checks()
    cloud_checks = {cid for cid, c in all_checks.items()
                    if c.asset_type not in NON_CLOUD_ASSET_TYPES}
    portable = _covered("AZURE") | _covered("GCP")
    unexplained = cloud_checks - portable - AWS_ONLY
    assert not unexplained, (
        "checks neither portable nor recorded as AWS-only — either add a probe "
        f"or add them to AWS_ONLY with a reason: {sorted(unexplained)}")


def test_non_cloud_checks_are_served_by_a_real_tool():
    """The other half of that split: a check on a non-cloud asset type must
    still be satisfiable by something, or it is an orphan wearing a category
    as an excuse."""
    for cid, check in control_checks.all_checks().items():
        if check.asset_type not in NON_CLOUD_ASSET_TYPES:
            continue
        satisfied = _satisfied_by_any(check)
        assert satisfied, f"{cid} ({check.asset_type}) is served by no connector"


# ── the four newly-implemented security tools ──
NEW_CONNECTORS = ["SNYK", "TENABLE", "WIZ", "SPLUNK"]


@pytest.mark.parametrize("name", NEW_CONNECTORS)
def test_new_connector_is_registered(name):
    assert name in registry.supported()


@pytest.mark.parametrize("name", NEW_CONNECTORS)
def test_new_connector_declares_a_usable_surface(name):
    """Surfaces are read off the class, so this works without credentials."""
    surface = registry.surface(name)
    assert surface.probes, f"{name} declares no probes"
    for probe in surface.probes.values():
        assert probe.signals, f"{name}:{probe.probe_id} emits no signals"
        assert probe.asset_type
        assert probe.plane


@pytest.mark.parametrize("name", NEW_CONNECTORS)
def test_new_connector_appears_implemented_in_the_catalog(name):
    from app.connectors import catalog as cat
    row = cat.get(name)
    assert row is not None and row["implemented"] is True
    assert row["maturity"] == "production"


@pytest.mark.parametrize("name", NEW_CONNECTORS)
def test_advertised_evidence_is_backed_by_a_probe_signal(name):
    """The catalog's evidence_types must describe what the connector returns.

    These four advertised evidence they had no code to produce (Snyk claimed
    patch_status, Wiz claimed encryption_enabled and logging_enabled) because
    nothing checked the claim against an implementation. Now something does.
    """
    from app.connectors import catalog as cat

    # evidence_type vocabulary -> the probe signals that satisfy it
    backing = {
        "vulnerability_findings": {"critical_vulnerabilities"},
        "code_scanning_enabled": {"code_scanning_enabled"},
        "logging_enabled": {"logging_enabled"},
        "audit_logs_retained": {"audit_logs_retained", "retention_days"},
        "siem_alerts_monitored": {"siem_alerts_monitored"},
    }
    emitted: set[str] = set()
    for probe in registry.surface(name).probes.values():
        emitted |= set(probe.signals)

    for evidence in cat.get(name)["evidence_types"]:
        expected = backing.get(evidence)
        assert expected, f"{name} advertises unmapped evidence type {evidence!r}"
        assert expected & emitted, (
            f"{name} advertises {evidence!r} but emits none of {sorted(expected)}")


def test_no_catalog_entry_points_at_a_missing_connector():
    from app.connectors import catalog as cat
    live = set(registry.supported())
    dangling = sorted({r["registry_key"] for r in cat.all_connectors()
                       if r["registry_key"] and r["registry_key"] not in live})
    assert not dangling, f"catalog references connectors that do not exist: {dangling}"
