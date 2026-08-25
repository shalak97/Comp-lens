"""Policy evaluation engine.

This is a deterministic, rule-based evaluator. Each control maps to an
evaluation function that inspects collected telemetry and returns a status.

In a larger deployment you can swap this for OPA/Rego by sending the telemetry
to an OPA server and reading the decision back — the interface
(`evaluate(control_id, telemetry)`) stays the same, so nothing else changes.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.models import ControlStatus, Severity

# An evaluator takes telemetry and returns (status, reason)
Evaluator = Callable[[dict[str, Any]], tuple[ControlStatus, str]]


# ──────────────────────────────────────────────────────────────────────────
# Control catalog: control_id -> metadata + evaluator
# Each control is vendor-agnostic; the connector normalizes telemetry into the
# fields these rules expect.
# ──────────────────────────────────────────────────────────────────────────


def _eval_mfa_enforced(t: dict[str, Any]) -> tuple[ControlStatus, str]:
    if t.get("mfa_enforced") is True:
        return ControlStatus.PASS, "MFA is enforced for the principal."
    if t.get("mfa_enforced") is False:
        return ControlStatus.FAIL, "MFA is NOT enforced for the principal."
    return ControlStatus.NOT_APPLICABLE, "MFA status unavailable in telemetry."


def _eval_no_stale_accounts(t: dict[str, Any]) -> tuple[ControlStatus, str]:
    days = t.get("days_since_last_login")
    if days is None:
        return ControlStatus.NOT_APPLICABLE, "Last-login data unavailable."
    if days > 90:
        return ControlStatus.FAIL, f"Account inactive for {days} days (>90)."
    return ControlStatus.PASS, f"Account active within {days} days."


def _eval_branch_protection(t: dict[str, Any]) -> tuple[ControlStatus, str]:
    if t.get("branch_protection_enabled") is True:
        return ControlStatus.PASS, "Default branch is protected."
    return ControlStatus.FAIL, "Default branch protection is disabled."


def _eval_secret_scanning(t: dict[str, Any]) -> tuple[ControlStatus, str]:
    if t.get("secret_scanning_enabled") is True:
        return ControlStatus.PASS, "Secret scanning is enabled."
    return ControlStatus.FAIL, "Secret scanning is disabled."


def _eval_encryption_at_rest(t: dict[str, Any]) -> tuple[ControlStatus, str]:
    if t.get("encryption_at_rest") is True:
        return ControlStatus.PASS, "Encryption at rest is enabled."
    return ControlStatus.FAIL, "Encryption at rest is NOT enabled."


def _eval_public_access_blocked(t: dict[str, Any]) -> tuple[ControlStatus, str]:
    if t.get("public_access_blocked") is True:
        return ControlStatus.PASS, "Public access is blocked."
    return ControlStatus.FAIL, "Resource is publicly accessible."


def _eval_logging_enabled(t: dict[str, Any]) -> tuple[ControlStatus, str]:
    if t.get("logging_enabled") is True:
        return ControlStatus.PASS, "Audit logging is enabled."
    return ControlStatus.FAIL, "Audit logging is disabled."


def _eval_patch_level(t: dict[str, Any]) -> tuple[ControlStatus, str]:
    crit = t.get("critical_vulnerabilities")
    if crit is None:
        return ControlStatus.NOT_APPLICABLE, "Vulnerability data unavailable."
    if crit > 0:
        return ControlStatus.FAIL, f"{crit} critical vulnerabilities open."
    return ControlStatus.PASS, "No critical vulnerabilities open."


def _eval_change_approval(t: dict[str, Any]) -> tuple[ControlStatus, str]:
    if t.get("change_has_approval") is True:
        return ControlStatus.PASS, "Change record has documented approval."
    return ControlStatus.FAIL, "Change record lacks documented approval."


def _eval_disk_encryption_host(t: dict[str, Any]) -> tuple[ControlStatus, str]:
    if t.get("disk_encrypted") is True:
        return ControlStatus.PASS, "Host disk encryption active."
    return ControlStatus.FAIL, "Host disk is not encrypted."


CONTROL_CATALOG: dict[str, dict[str, Any]] = {
    "AC-2-7": {
        "title": "Privileged account MFA enforcement",
        "domain": "Access Control",
        "severity": Severity.HIGH,
        "evaluator": _eval_mfa_enforced,
    },
    "AC-2-3": {
        "title": "Disable inactive accounts",
        "domain": "Access Control",
        "severity": Severity.MEDIUM,
        "evaluator": _eval_no_stale_accounts,
    },
    "CM-3": {
        "title": "Change control approval",
        "domain": "Configuration Management",
        "severity": Severity.MEDIUM,
        "evaluator": _eval_change_approval,
    },
    "SC-28": {
        "title": "Protection of information at rest",
        "domain": "System & Communications",
        "severity": Severity.HIGH,
        "evaluator": _eval_encryption_at_rest,
    },
    "SC-7": {
        "title": "Boundary protection / no public exposure",
        "domain": "System & Communications",
        "severity": Severity.CRITICAL,
        "evaluator": _eval_public_access_blocked,
    },
    "AU-2": {
        "title": "Audit logging enabled",
        "domain": "Audit & Accountability",
        "severity": Severity.HIGH,
        "evaluator": _eval_logging_enabled,
    },
    "RA-5": {
        "title": "Vulnerability remediation",
        "domain": "Risk Assessment",
        "severity": Severity.HIGH,
        "evaluator": _eval_patch_level,
    },
    "SA-15-BRANCH": {
        "title": "Source branch protection",
        "domain": "System & Services Acquisition",
        "severity": Severity.MEDIUM,
        "evaluator": _eval_branch_protection,
    },
    "SA-15-SECRETS": {
        "title": "Secret scanning enabled",
        "domain": "System & Services Acquisition",
        "severity": Severity.HIGH,
        "evaluator": _eval_secret_scanning,
    },
    "SC-28-HOST": {
        "title": "Host disk encryption",
        "domain": "System & Communications",
        "severity": Severity.HIGH,
        "evaluator": _eval_disk_encryption_host,
    },
}


# ── AI governance controls (ISO 42001 / NIST AI RMF / EU AI Act) ──
def _flag(field: str, label: str):
    def _eval(t: dict[str, Any]):
        if t.get(field) is True:
            return ControlStatus.PASS, f"{label} is in place."
        if t.get(field) is False:
            return ControlStatus.FAIL, f"{label} is NOT in place."
        return ControlStatus.NOT_APPLICABLE, f"{label} status unavailable."
    return _eval


_AI_CONTROLS = {
    "AI-INV": ("AI system inventory & ownership", "Governance", Severity.MEDIUM, "ai_inventoried"),
    "AI-RISK": ("AI risk / impact assessment", "Risk Assessment", Severity.HIGH, "impact_assessment"),
    "AI-DATA": ("AI data governance & quality", "Data", Severity.HIGH, "data_governance"),
    "AI-OVERSIGHT": ("Human oversight of AI", "Accountability", Severity.CRITICAL, "human_oversight"),
    "AI-TRANSP": ("AI transparency / user disclosure", "Transparency", Severity.MEDIUM, "transparency_notice"),
    "AI-EVAL": ("AI evaluation & bias testing", "Measurement", Severity.HIGH, "eval_report"),
    "AI-LOG": ("AI event & incident logging", "Audit & Accountability", Severity.HIGH, "logging_enabled"),
    "AI-ROBUST": ("AI accuracy / robustness testing", "System & Communications", Severity.HIGH, "accuracy_tested"),
}
for _cid, (_title, _domain, _sev, _field) in _AI_CONTROLS.items():
    CONTROL_CATALOG[_cid] = {"title": _title, "domain": _domain, "severity": _sev,
                             "evaluator": _flag(_field, _title)}


# ── declarative checks (app/data/control_checks.json) ──
# Controls defined as data are merged into the same catalog the hand-written
# ones live in, wrapped so they satisfy the identical Evaluator signature. That
# means every existing consumer — RuleEngine, the coverage endpoint, the audit
# control list, OSCAL export — picks them up with no further wiring, and a new
# control ships as a single JSON entry rather than three code edits.
def _declarative_evaluator(check):
    def _eval(t: dict[str, Any]) -> tuple[ControlStatus, str]:
        from app.services.control_checks import evaluate as _evaluate
        status, reason, _severity = _evaluate(check, t)
        return status, reason
    return _eval


def _load_declarative_controls() -> int:
    import logging

    from app.services.control_checks import all_checks

    log = logging.getLogger(__name__)
    added = 0
    for cid, check in all_checks().items():
        if cid in CONTROL_CATALOG:
            # A hand-written control always wins: the pack extends the catalog,
            # it never silently redefines behaviour something already depends on.
            log.warning(
                "declarative check %s shadows a built-in control; keeping built-in", cid)
            continue
        CONTROL_CATALOG[cid] = {
            "title": check.title,
            "domain": check.domain,
            "severity": check.severity,
            "evaluator": _declarative_evaluator(check),
            "declarative": True,
            "asset_type": check.asset_type,
            "plane": check.plane,
            "remediation": check.remediation,
        }
        added += 1
    return added


_load_declarative_controls()


class RuleEngine:
    """Built-in deterministic rule catalog (default)."""

    def evaluate(self, control_id: str, telemetry: dict[str, Any]) -> tuple[ControlStatus, str, Severity]:
        control = CONTROL_CATALOG.get(control_id)
        if control is None:
            return (ControlStatus.ERROR, f"Unknown control '{control_id}'. Not in catalog.", Severity.INFO)
        status, reason = control["evaluator"](telemetry)
        return status, reason, control["severity"]

    def control_meta(self, control_id: str) -> dict[str, Any]:
        return CONTROL_CATALOG.get(control_id, {})


class OPAEngine:
    """Delegates the decision to an Open Policy Agent server (Rego policies).

    POSTs {"input": {"control_id", "telemetry"}} to
    {opa_url}/v1/data/{package}/decision and reads back
    {"result": {"status", "reason"}}. Severity/title still come from the local
    catalog so reporting is consistent. Falls back to ERROR (never crashes) if
    OPA is unreachable or returns nothing.
    """

    def __init__(self) -> None:
        from app.config import settings
        # opa_url defaults to None (OPA is opt-in); when this engine is selected
        # or constructed directly without a URL, fall back to the conventional
        # local OPA endpoint rather than crashing.
        base = (settings.opa_url or "http://localhost:8181").rstrip("/")
        self._url = f"{base}/v1/data/{settings.opa_package}/decision"
        self._timeout = settings.request_timeout_seconds

    def evaluate(self, control_id: str, telemetry: dict[str, Any]) -> tuple[ControlStatus, str, Severity]:
        import requests
        meta = CONTROL_CATALOG.get(control_id, {})
        severity = meta.get("severity", Severity.MEDIUM)
        try:
            r = requests.post(self._url, json={"input": {"control_id": control_id, "telemetry": telemetry}},
                              timeout=self._timeout)
            r.raise_for_status()
            result = r.json().get("result") or {}
        except Exception as exc:  # noqa: BLE001
            return (ControlStatus.ERROR, f"OPA evaluation failed: {exc}", Severity.INFO)
        status_str = str(result.get("status", "error")).lower()
        try:
            status = ControlStatus(status_str)
        except ValueError:
            status = ControlStatus.ERROR
        reason = result.get("reason", "OPA decision")
        return status, reason, severity

    def control_meta(self, control_id: str) -> dict[str, Any]:
        return CONTROL_CATALOG.get(control_id, {})


def _build_engine():
    from app.config import settings
    if settings.policy_engine.lower() == "opa":
        return OPAEngine()
    return RuleEngine()


policy_engine = _build_engine()
# Backwards-compatible alias
PolicyEngine = RuleEngine
