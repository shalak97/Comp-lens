"""Realistic demo evidence per connector.

Rich, hand-authored profiles for the eight flagship connectors; per-category
templates generate plausible evidence for the rest. Demo evidence is
DETERMINISTIC (seeded per connector key) so dashboards and tests are stable,
and every item carries signals shaped like the real vendor APIs would yield
after normalization — so the scoring engine can consume them identically in
demo and live modes.
"""
from __future__ import annotations

import random
from typing import Any

# ── flagship profiles (the 8 required demo connectors) ──────────────────────
_RICH: dict[str, list[dict[str, Any]]] = {
    "AWS_SECURITY_HUB": [
        {"evidence_type": "vulnerability_findings", "title": "Security Hub findings summary",
         "signals": {"critical_findings": 2, "high_findings": 11, "medium_findings": 37,
                     "standards_enabled": ["AWS Foundational Security Best Practices", "CIS AWS Foundations v1.4"],
                     "score_pct": 78.4}, "status": "fail"},
        {"evidence_type": "logging_enabled", "title": "CloudTrail multi-region trail",
         "signals": {"cloudtrail_enabled": True, "multi_region": True, "log_file_validation": True,
                     "kms_encrypted": True}, "status": "pass"},
        {"evidence_type": "encryption_enabled", "title": "S3 default encryption posture",
         "signals": {"buckets_total": 23, "buckets_encrypted": 23, "encryption_at_rest": True,
                     "default_sse": "aws:kms"}, "status": "pass"},
        {"evidence_type": "siem_alerts_monitored", "title": "GuardDuty findings routed",
         "signals": {"guardduty_enabled": True, "eventbridge_rule": True,
                     "open_high_alerts": 1}, "status": "pass"},
    ],
    "OKTA": [
        {"evidence_type": "mfa_enabled", "title": "MFA enrollment across active users",
         "signals": {"users_total": 412, "users_mfa_enrolled": 401, "mfa_enforced": True,
                     "factors": ["okta_verify", "webauthn"], "coverage_pct": 97.3}, "status": "pass"},
        {"evidence_type": "inactive_accounts_disabled", "title": "Dormant account hygiene",
         "signals": {"inactive_over_90d": 6, "auto_suspend_policy": True,
                     "max_inactive_days": 90}, "status": "fail"},
        {"evidence_type": "privileged_users_reviewed", "title": "Super-admin population",
         "signals": {"super_admins": 4, "admins_with_mfa": 4, "last_review_days_ago": 21},
         "status": "pass"},
        {"evidence_type": "logging_enabled", "title": "System Log streaming",
         "signals": {"syslog_streaming": True, "destination": "splunk",
                     "retention_days": 365}, "status": "pass"},
    ],
    "GITHUB": [
        {"evidence_type": "branch_protection", "title": "Default-branch protection",
         "signals": {"repos_total": 58, "repos_protected": 54, "required_reviews": 1,
                     "force_push_blocked": True, "branch_protection_enabled": True}, "status": "fail"},
        {"evidence_type": "code_scanning_enabled", "title": "CodeQL + secret scanning",
         "signals": {"code_scanning_repos": 49, "secret_scanning": True,
                     "dependabot_alerts": True}, "status": "pass"},
        {"evidence_type": "mfa_enabled", "title": "Org 2FA requirement",
         "signals": {"two_factor_required": True, "members_total": 87,
                     "members_without_2fa": 0, "mfa_enforced": True}, "status": "pass"},
        {"evidence_type": "vulnerability_findings", "title": "Open Dependabot alerts",
         "signals": {"critical_vulnerabilities": 1, "high": 7, "moderate": 22}, "status": "fail"},
    ],
    "JIRA": [
        {"evidence_type": "incidents_tracked", "title": "Security incident project",
         "signals": {"incident_project": "SEC", "open_incidents": 3, "mttr_hours": 18.5,
                     "sla_breaches_30d": 0, "incidents_tracked": True}, "status": "pass"},
        {"evidence_type": "access_reviews_completed", "title": "Quarterly access-review tickets",
         "signals": {"review_tickets_open": 1, "last_completed_days_ago": 47,
                     "review_cadence_days": 90}, "status": "pass"},
    ],
    "SERVICENOW": [
        {"evidence_type": "incidents_tracked", "title": "Incident table hygiene",
         "signals": {"open_p1": 0, "open_p2": 4, "mttr_hours": 9.2,
                     "incidents_tracked": True}, "status": "pass"},
        {"evidence_type": "patch_status", "title": "Change requests for patching",
         "signals": {"patch_changes_30d": 14, "emergency_changes_30d": 1,
                     "patch_compliance_pct": 92.6}, "status": "pass"},
        {"evidence_type": "access_reviews_completed", "title": "Access certification campaigns",
         "signals": {"campaigns_active": 1, "last_completed_days_ago": 35}, "status": "pass"},
    ],
    "CROWDSTRIKE": [
        {"evidence_type": "endpoint_protection_active", "title": "Falcon sensor coverage",
         "signals": {"hosts_total": 318, "hosts_with_sensor": 311, "coverage_pct": 97.8,
                     "prevention_policy": "enforced"}, "status": "pass"},
        {"evidence_type": "patch_status", "title": "Spotlight patch exposure",
         "signals": {"hosts_critical_vulns": 9, "median_patch_age_days": 12}, "status": "fail"},
        {"evidence_type": "incidents_tracked", "title": "Detections triaged",
         "signals": {"detections_7d": 22, "untriaged": 0, "containment_actions_7d": 2},
         "status": "pass"},
    ],
    "ENTRA_ID": [
        {"evidence_type": "mfa_enabled", "title": "Conditional Access MFA policy",
         "signals": {"ca_policy_mfa_all_users": True, "users_total": 530,
                     "legacy_auth_blocked": True, "mfa_enforced": True,
                     "coverage_pct": 99.1}, "status": "pass"},
        {"evidence_type": "privileged_users_reviewed", "title": "PIM role assignments",
         "signals": {"global_admins": 3, "pim_eligible_only": True,
                     "standing_privileged": 0, "last_review_days_ago": 14}, "status": "pass"},
        {"evidence_type": "inactive_accounts_disabled", "title": "Stale account sweep",
         "signals": {"inactive_over_90d": 12, "auto_disable_policy": False}, "status": "fail"},
        {"evidence_type": "audit_logs_retained", "title": "Entra audit log export",
         "signals": {"diagnostic_settings": True, "destination": "log_analytics",
                     "retention_days": 365}, "status": "pass"},
    ],
    "ONETRUST": [
        {"evidence_type": "consent_records_managed", "title": "Consent transaction records",
         "signals": {"active_consent_templates": 7, "consent_records_90d": 18230,
                     "withdrawal_honored_pct": 100.0}, "status": "pass"},
        {"evidence_type": "data_retention_policy", "title": "Retention schedules published",
         "signals": {"retention_schedules": 12, "assets_with_schedule_pct": 88.0,
                     "last_updated_days_ago": 41}, "status": "pass"},
        {"evidence_type": "ai_system_inventory", "title": "AI & data-use registry",
         "signals": {"ai_systems_registered": 6, "dpia_completed": 5,
                     "high_risk_systems": 1}, "status": "pass"},
    ],
}

# ── category templates for everything else ───────────────────────────────────
_TEMPLATES: dict[str, dict[str, Any]] = {
    "mfa_enabled": {"title": "MFA enforcement", "signals": lambda r: {
        "mfa_enforced": True, "coverage_pct": round(90 + r.random() * 10, 1)}, "status": "pass"},
    "privileged_users_reviewed": {"title": "Privileged access review", "signals": lambda r: {
        "privileged_users": r.randint(2, 9), "last_review_days_ago": r.randint(7, 80)}, "status": "pass"},
    "inactive_accounts_disabled": {"title": "Inactive account hygiene", "signals": lambda r: {
        "inactive_over_90d": r.randint(0, 15), "auto_disable_policy": r.random() > 0.4}, "status": "info"},
    "logging_enabled": {"title": "Audit logging", "signals": lambda r: {
        "logging_enabled": True, "retention_days": r.choice([90, 180, 365])}, "status": "pass"},
    "encryption_enabled": {"title": "Encryption posture", "signals": lambda r: {
        "encryption_at_rest": True, "tls_min_version": "1.2"}, "status": "pass"},
    "vulnerability_findings": {"title": "Open vulnerability findings", "signals": lambda r: {
        "critical_vulnerabilities": r.randint(0, 4), "high": r.randint(2, 15)}, "status": "info"},
    "incidents_tracked": {"title": "Incident tracking", "signals": lambda r: {
        "incidents_tracked": True, "open_incidents": r.randint(0, 6)}, "status": "pass"},
    "patch_status": {"title": "Patch compliance", "signals": lambda r: {
        "patch_compliance_pct": round(80 + r.random() * 19, 1)}, "status": "info"},
    "backup_configuration": {"title": "Backup configuration", "signals": lambda r: {
        "backups_enabled": True, "last_successful_backup_hours": r.randint(2, 30)}, "status": "pass"},
    "audit_logs_retained": {"title": "Log retention", "signals": lambda r: {
        "retention_days": r.choice([180, 365, 730])}, "status": "pass"},
    "access_reviews_completed": {"title": "Access reviews", "signals": lambda r: {
        "last_completed_days_ago": r.randint(10, 100), "cadence_days": 90}, "status": "pass"},
    "branch_protection": {"title": "Branch protection", "signals": lambda r: {
        "branch_protection_enabled": True, "required_reviews": r.randint(1, 2)}, "status": "pass"},
    "code_scanning_enabled": {"title": "Static analysis coverage", "signals": lambda r: {
        "code_scanning_enabled": True, "coverage_pct": round(70 + r.random() * 30, 1)}, "status": "pass"},
    "endpoint_protection_active": {"title": "EDR coverage", "signals": lambda r: {
        "coverage_pct": round(92 + r.random() * 8, 1)}, "status": "pass"},
    "data_retention_policy": {"title": "Retention policy", "signals": lambda r: {
        "retention_schedules": r.randint(3, 15)}, "status": "pass"},
    "ai_system_inventory": {"title": "AI system registry", "signals": lambda r: {
        "ai_systems_registered": r.randint(1, 8)}, "status": "pass"},
    "consent_records_managed": {"title": "Consent management", "signals": lambda r: {
        "active_consent_templates": r.randint(2, 10)}, "status": "pass"},
    "siem_alerts_monitored": {"title": "SIEM alert monitoring", "signals": lambda r: {
        "open_high_alerts": r.randint(0, 3), "alerts_routed": True}, "status": "pass"},
}


def demo_evidence(connector: dict[str, Any]) -> list[dict[str, Any]]:
    """Deterministic, realistic demo evidence for any catalogued connector."""
    key = connector["key"]
    if key in _RICH:
        return [dict(item) for item in _RICH[key]]
    rng = random.Random(key)  # seeded -> stable across calls
    out = []
    for et in connector["evidence_types"]:
        t = _TEMPLATES.get(et)
        if not t:
            continue
        out.append({"evidence_type": et, "title": t["title"],
                    "signals": t["signals"](rng), "status": t["status"]})
    return out
