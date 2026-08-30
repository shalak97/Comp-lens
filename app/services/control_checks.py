"""Declarative control checks — coverage as content, not code.

A *check* is the data form of "what does this control mean, mechanically".
It names the asset type it applies to, the normalized signals it needs, and a
boolean expression over them. It never names a vendor: any connector whose
capability surface (app/connectors/capabilities.py) exposes a probe for that
asset type emitting those signals can satisfy it.

That indirection is the whole point. Adding a control is a JSON entry, not a
connector edit plus a hand-written Python evaluator plus a crosswalk edit. A
check written once runs against AWS, Azure and GCP the moment each declares a
probe emitting the same signals.

Checks are loaded from app/data/control_checks.json and merged into the two
registries the rest of the platform already reads — the policy engine's
CONTROL_CATALOG and the framework CROSSWALK — so a new check shows up in
assessment, coverage, the audit control list and OSCAL export with no further
wiring.

Expressions are evaluated by the existing sandboxed evaluator in
app/policy_as_code/evaluator.py (no eval(), no attribute traversal off
non-dicts, no dunder access), so check content is data, not executable code.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.models import ControlStatus, Severity

logger = logging.getLogger(__name__)

_PACK_PATH = Path(__file__).resolve().parent.parent / "data" / "control_checks.json"

SCHEMA_VERSION = "control-checks-v1"

_SEVERITIES = {s.value for s in Severity}


@dataclass(frozen=True)
class Check:
    """One declarative, vendor-neutral control check."""

    control_id: str
    title: str
    domain: str
    severity: Severity
    asset_type: str
    plane: str
    requires: tuple[str, ...]
    expression: str
    pass_reason: str
    fail_reason: str
    crosswalk: dict[str, list[str]] = field(default_factory=dict)
    #: optional narrative shown in remediation guidance
    remediation: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "domain": self.domain,
            "severity": self.severity.value,
            "asset_type": self.asset_type,
            "plane": self.plane,
            "requires": list(self.requires),
            "expression": self.expression,
            "crosswalk": self.crosswalk,
            "remediation": self.remediation,
        }


class CheckPackError(ValueError):
    """Raised when the check pack is structurally invalid."""


_REQUIRED_KEYS = ("control_id", "title", "asset_type", "requires", "expression")


def _parse_check(raw: dict[str, Any], index: int) -> Check:
    missing = [k for k in _REQUIRED_KEYS if not raw.get(k)]
    if missing:
        raise CheckPackError(
            f"check #{index} ({raw.get('control_id', '?')}) missing required key(s): "
            f"{', '.join(missing)}")

    sev = str(raw.get("severity", "medium")).lower()
    if sev not in _SEVERITIES:
        raise CheckPackError(
            f"check {raw['control_id']}: unknown severity {sev!r} "
            f"(expected one of {', '.join(sorted(_SEVERITIES))})")

    requires = raw["requires"]
    if not isinstance(requires, list) or not all(isinstance(s, str) for s in requires):
        raise CheckPackError(f"check {raw['control_id']}: 'requires' must be a list of strings")

    title = str(raw["title"])
    return Check(
        control_id=str(raw["control_id"]),
        title=title,
        domain=str(raw.get("domain", "General")),
        severity=Severity(sev),
        asset_type=str(raw["asset_type"]),
        plane=str(raw.get("plane", "configuration")),
        requires=tuple(requires),
        expression=str(raw["expression"]),
        pass_reason=str(raw.get("pass_reason") or f"{title}: requirement met."),
        fail_reason=str(raw.get("fail_reason") or f"{title}: requirement NOT met."),
        crosswalk={k: list(v) for k, v in (raw.get("crosswalk") or {}).items()},
        remediation=str(raw.get("remediation", "")),
    )


@lru_cache(maxsize=1)
def load_checks() -> dict[str, Check]:
    """Parse and validate the check pack. Cached — the pack is static content.

    A malformed pack is a deploy-time bug, not a runtime condition: it raises so
    CI catches it, rather than silently shipping a platform with missing
    controls.
    """
    if not _PACK_PATH.exists():
        logger.warning("control check pack not found at %s", _PACK_PATH)
        return {}

    doc = json.loads(_PACK_PATH.read_text())
    version = doc.get("version")
    if version != SCHEMA_VERSION:
        raise CheckPackError(
            f"check pack version {version!r} is not supported (expected {SCHEMA_VERSION!r})")

    checks: dict[str, Check] = {}
    for i, raw in enumerate(doc.get("checks", [])):
        check = _parse_check(raw, i)
        if check.control_id in checks:
            raise CheckPackError(f"duplicate control_id in check pack: {check.control_id}")
        checks[check.control_id] = check

    logger.info("loaded %d declarative control checks", len(checks))
    return checks


def get(control_id: str) -> Check | None:
    return load_checks().get(control_id)


def all_checks() -> dict[str, Check]:
    return load_checks()


# ──────────────────────────────────────────────────────────────────────────
# Evaluation
# ──────────────────────────────────────────────────────────────────────────
def evaluate(check: Check, telemetry: dict[str, Any]) -> tuple[ControlStatus, str, Severity]:
    """Decide a check against collected telemetry.

    Tri-state on purpose. A missing signal is NOT_APPLICABLE, never a silent
    FAIL: "we could not observe this" and "we observed it and it is wrong" are
    different claims, and conflating them is how a compliance tool ends up
    lying to an auditor.
    """
    absent = [s for s in check.requires if telemetry.get(s) is None]
    if absent:
        return (
            ControlStatus.NOT_APPLICABLE,
            f"Signal(s) unavailable in telemetry: {', '.join(absent)}.",
            check.severity,
        )

    from app.policy_as_code.evaluator import PolicyExpressionError, evaluate_expression

    try:
        ok = evaluate_expression(check.expression, telemetry)
    except PolicyExpressionError as exc:
        logger.error("check %s has an invalid expression: %s", check.control_id, exc)
        return (ControlStatus.ERROR, f"Invalid check expression: {exc}", Severity.INFO)

    reason = check.pass_reason if ok else check.fail_reason
    return (ControlStatus.PASS if ok else ControlStatus.FAIL), reason, check.severity


# ──────────────────────────────────────────────────────────────────────────
# Resolution: which connector can satisfy which check
# ──────────────────────────────────────────────────────────────────────────
def resolve_probe(source_system: str, check: Check):
    """Return the probe on `source_system` that can satisfy `check`, or None."""
    from app.connectors.registry import registry

    surface = registry.surface(source_system)
    if surface is None:
        return None
    return surface.resolve(check.asset_type, check.requires)


def producers_for(check: Check) -> list[str]:
    """Every connector that can currently satisfy this check."""
    from app.connectors.registry import registry

    out = []
    for name, surface in registry.surfaces().items():
        if surface.resolve(check.asset_type, check.requires) is not None:
            out.append(name)
    return sorted(out)


def coverage_matrix() -> dict[str, Any]:
    """How much of the declarative catalog is actually machine-verifiable.

    This is the product's core health metric: a check that no connector can
    satisfy is a promise the platform cannot keep, and it should be visible
    rather than discovered during an audit.
    """
    checks = load_checks()
    rows = []
    covered = 0
    for cid, check in sorted(checks.items()):
        producers = producers_for(check)
        if producers:
            covered += 1
        rows.append({
            "control_id": cid,
            "title": check.title,
            "domain": check.domain,
            "severity": check.severity.value,
            "asset_type": check.asset_type,
            "plane": check.plane,
            "producers": producers,
            "covered": bool(producers),
        })
    total = len(checks)
    return {
        "total_checks": total,
        "covered": covered,
        "uncovered": total - covered,
        "coverage_pct": round(covered / total * 100, 1) if total else 0.0,
        "checks": rows,
    }


def orphan_checks() -> list[str]:
    """Checks no connector can satisfy — the guardrail CI asserts on."""
    return [cid for cid, c in load_checks().items() if not producers_for(c)]
