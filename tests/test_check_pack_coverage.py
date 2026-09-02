"""Depth of the declarative check pack.

A note on measurement, because the obvious metric is misleading.

"Percent of the NIST catalog covered" counts *citations*: whether some check
somewhere names a control id in its crosswalk. It barely moves when you add a
check that verifies a control another check already cites — adding an object
storage public-access check does nothing for the number if AC-3 was already
cited by a database check — even though the platform now genuinely verifies
something it could not verify before.

The metric that tracks assurance is how many things are actually checked, and
on how many systems. These tests pin that: the size of the pack, that every
check resolves to a real probe, and that the checks meant to be portable are
satisfiable on more than one cloud rather than quietly collapsing to AWS.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.connectors.registry import registry
from app.services import control_checks

_PACK = Path(__file__).resolve().parent.parent / "app" / "data" / "control_checks.json"

#: Checks added to consume signals connectors were already collecting but no
#: check read. Each cost zero connector code.
NEW_CHECKS = {
    "IA-2-CONSOLE-MFA", "AC-2-INACTIVE-ACCOUNT", "SC-28-OBJSTORE",
    "AC-3-OBJSTORE-PUBLIC", "SC-28-BLOCKSTORE-KMS", "AU-2-ACCOUNT-LOGGING",
    "IA-5-PW-MAX-AGE", "RA-5-HOST-CRITICAL", "RA-5-CODE-DEPENDENCIES",
    "SA-11-CODE-SCANNING", "AU-11-LOG-RETENTION", "SI-4-SIEM-ALERTING",
}

#: Checks whose asset type exists on more than one cloud, so a regression that
#: drops a probe signal shows up as a portability loss rather than silently
#: reverting to AWS-only.
PORTABLE = {
    "SC-28-OBJSTORE": 3,        # object storage on AWS, Azure, GCP
    "AC-3-OBJSTORE-PUBLIC": 3,
    "AU-2-ACCOUNT-LOGGING": 3,
    "IA-2-CONSOLE-MFA": 2,      # AWS + Azure
}


def _real_connectors() -> list[str]:
    """Everything except DEMO, which fabricates telemetry and would make any
    coverage assertion pass trivially."""
    return [n for n in registry.supported() if n != "DEMO"]


def _satisfied_by(control_id: str) -> list[str]:
    check = control_checks.all_checks()[control_id]
    return [n for n in _real_connectors()
            if (s := registry.surface(n)) and s.resolve(check.asset_type, check.requires)]


def test_pack_has_grown_and_did_not_lose_checks():
    assert len(control_checks.all_checks()) >= 50


@pytest.mark.parametrize("control_id", sorted(NEW_CHECKS))
def test_new_check_is_present_and_resolvable(control_id):
    """The guardrail that matters: a check nothing can satisfy is a promise the
    platform cannot keep."""
    assert control_id in control_checks.all_checks()
    assert _satisfied_by(control_id), f"{control_id} resolves to no connector probe"


@pytest.mark.parametrize(("control_id", "minimum"), sorted(PORTABLE.items()))
def test_portable_checks_run_on_more_than_one_system(control_id, minimum):
    satisfied = _satisfied_by(control_id)
    assert len(satisfied) >= minimum, (
        f"{control_id} is meant to be portable but only {satisfied} can satisfy it")


def test_the_security_tool_connectors_now_verify_controls():
    """Snyk, Tenable, Wiz and Splunk shipped as evidence sources only. These
    checks are what turn that evidence into control verification."""
    for name in ("SNYK", "TENABLE", "WIZ", "SPLUNK"):
        covered = [cid for cid, c in control_checks.all_checks().items()
                   if (s := registry.surface(name)) and s.resolve(c.asset_type, c.requires)]
        assert covered, f"{name} satisfies no declarative check"


# ── pack integrity, applied to the whole pack rather than just the new rows ──
def test_no_duplicate_control_ids():
    rows = json.loads(_PACK.read_text())["checks"]
    ids = [c["control_id"] for c in rows]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"duplicate control ids in the pack: {dupes}"


def test_every_check_crosswalks_to_real_catalog_ids():
    """A crosswalk pointing at a control id that does not exist in the
    framework catalog cannot be followed by a reader, and quietly inflates any
    coverage figure computed from it."""
    root = _PACK.parent / "frameworks"
    nist = {r["id"] for r in json.loads((root / "nist_800_53.json").read_text())}
    iso = {r["id"] for r in json.loads((root / "iso_27001_2022.json").read_text())}

    bad: list[str] = []
    for check in json.loads(_PACK.read_text())["checks"]:
        cw = check["crosswalk"]
        for ref in cw.get("NIST", []):
            if ref not in nist:
                bad.append(f"{check['control_id']} -> NIST {ref}")
        for ref in cw.get("ISO27001", []):
            if ref not in iso:
                bad.append(f"{check['control_id']} -> ISO {ref}")
    assert not bad, f"crosswalk references not present in the catalogs: {bad}"


def test_every_check_has_reasons_and_remediation():
    """A failing control that does not say what to do about it is a ticket
    somebody has to research before they can act on it."""
    thin = [c["control_id"] for c in json.loads(_PACK.read_text())["checks"]
            if not (c.get("pass_reason") and c.get("fail_reason") and c.get("remediation"))]
    assert not thin, f"checks missing pass/fail reason or remediation: {thin}"


def test_expressions_only_reference_declared_signals():
    """An expression reading a signal the check does not declare in `requires`
    would evaluate against a missing value instead of reporting
    NOT_APPLICABLE — the check would silently answer a question it never
    collected the evidence for."""
    import re

    offenders: list[str] = []
    for check in json.loads(_PACK.read_text())["checks"]:
        declared = set(check["requires"])
        names = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", check["expression"]))
        names -= {"true", "false", "and", "or", "not", "null", "None"}
        undeclared = names - declared
        if undeclared:
            offenders.append(f"{check['control_id']}: {sorted(undeclared)}")
    assert not offenders, f"expressions using undeclared signals: {offenders}"
