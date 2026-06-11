"""Connector catalog — the marketplace definition layer.

Every connector Comp-Lens knows about is DEFINED here as data: identity,
category, auth method, required env vars (names only — never values), the
evidence types it can produce, and (where one exists) the key of a real
BaseConnector implementation in the registry.

Three tiers of maturity, surfaced honestly in the API/UI:
  implemented – a real connector class exists (live API calls when creds set)
  demo        – produces realistic normalized demo evidence; live client not built
  planned     – defined in the catalog, demo evidence via category template

A connector with an implementation but missing creds still works in demo mode,
so the dashboard is fully functional with zero credentials.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

CATEGORIES = ["cloud", "identity", "devops", "itsm", "security", "grc", "saas", "endpoint"]

# evidence types the platform understands (mapped to controls in connector_control_map.json)
EVIDENCE_TYPES = [
    "mfa_enabled", "privileged_users_reviewed", "inactive_accounts_disabled",
    "logging_enabled", "encryption_enabled", "vulnerability_findings",
    "incidents_tracked", "patch_status", "backup_configuration",
    "audit_logs_retained", "access_reviews_completed", "branch_protection",
    "code_scanning_enabled", "endpoint_protection_active", "data_retention_policy",
    "ai_system_inventory", "consent_records_managed", "siem_alerts_monitored",
]


def _c(key: str, name: str, category: str, auth: str, env: List[str],
       evidence: List[str], registry_key: Optional[str] = None,
       maturity: str = "demo", vendor: str = "") -> Dict[str, Any]:
    return {"key": key, "name": name, "category": category, "auth_method": auth,
            "env_vars": env, "evidence_types": evidence,
            "registry_key": registry_key, "maturity": maturity,
            "vendor": vendor or name.split()[0]}


CONNECTOR_CATALOG: List[Dict[str, Any]] = [
    # ── Cloud ────────────────────────────────────────────────────────────────
    _c("AWS_SECURITY_HUB", "AWS Security Hub", "cloud", "iam_keys",
       ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"],
       ["vulnerability_findings", "logging_enabled", "encryption_enabled", "siem_alerts_monitored"],
       registry_key="AWS", maturity="implemented", vendor="AWS"),
    _c("AWS_IAM", "AWS IAM", "cloud", "iam_keys",
       ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
       ["mfa_enabled", "privileged_users_reviewed", "inactive_accounts_disabled", "access_reviews_completed"],
       registry_key="AWS", maturity="implemented", vendor="AWS"),
    _c("AWS_CONFIG", "AWS Config", "cloud", "iam_keys",
       ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"],
       ["logging_enabled", "encryption_enabled", "backup_configuration", "patch_status"],
       registry_key="AWS", maturity="implemented", vendor="AWS"),
    _c("AZURE_DEFENDER", "Microsoft Defender for Cloud", "cloud", "oauth_client_credentials",
       ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"],
       ["vulnerability_findings", "patch_status", "encryption_enabled", "siem_alerts_monitored"],
       registry_key="AZURE", maturity="implemented", vendor="Microsoft"),
    _c("GCP_SCC", "GCP Security Command Center", "cloud", "service_account_json",
       ["GCP_SERVICE_ACCOUNT_JSON", "GCP_PROJECT_ID"],
       ["vulnerability_findings", "logging_enabled", "encryption_enabled"],
       registry_key="GCP", maturity="implemented", vendor="Google"),
    _c("GCP_IAM", "GCP IAM", "cloud", "service_account_json",
       ["GCP_SERVICE_ACCOUNT_JSON", "GCP_PROJECT_ID"],
       ["mfa_enabled", "privileged_users_reviewed", "access_reviews_completed"],
       registry_key="GCP", maturity="implemented", vendor="Google"),
    # ── Identity ─────────────────────────────────────────────────────────────
    _c("OKTA", "Okta", "identity", "api_token",
       ["OKTA_ORG_URL", "OKTA_API_TOKEN"],
       ["mfa_enabled", "inactive_accounts_disabled", "privileged_users_reviewed",
        "access_reviews_completed", "logging_enabled"],
       registry_key="OKTA", maturity="implemented", vendor="Okta"),
    _c("ENTRA_ID", "Microsoft Entra ID", "identity", "oauth_client_credentials",
       ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"],
       ["mfa_enabled", "privileged_users_reviewed", "inactive_accounts_disabled",
        "access_reviews_completed", "audit_logs_retained"],
       registry_key="AZURE", maturity="implemented", vendor="Microsoft"),
    _c("GOOGLE_WORKSPACE", "Google Workspace", "identity", "service_account_json",
       ["GOOGLE_WORKSPACE_SA_JSON", "GOOGLE_WORKSPACE_ADMIN"],
       ["mfa_enabled", "inactive_accounts_disabled", "audit_logs_retained"],
       vendor="Google"),
    _c("ONELOGIN", "OneLogin", "identity", "oauth_client_credentials",
       ["ONELOGIN_CLIENT_ID", "ONELOGIN_CLIENT_SECRET"],
       ["mfa_enabled", "inactive_accounts_disabled", "access_reviews_completed"],
       vendor="OneLogin"),
    _c("PING_IDENTITY", "Ping Identity", "identity", "oauth_client_credentials",
       ["PING_CLIENT_ID", "PING_CLIENT_SECRET", "PING_ENV_ID"],
       ["mfa_enabled", "access_reviews_completed"], vendor="Ping"),
    # ── DevOps / Code ────────────────────────────────────────────────────────
    _c("GITHUB", "GitHub", "devops", "pat_token",
       ["GITHUB_TOKEN", "GITHUB_ORG"],
       ["branch_protection", "code_scanning_enabled", "mfa_enabled", "vulnerability_findings"],
       registry_key="GITHUB", maturity="implemented", vendor="GitHub"),
    _c("GITLAB", "GitLab", "devops", "pat_token",
       ["GITLAB_TOKEN", "GITLAB_GROUP"],
       ["branch_protection", "code_scanning_enabled", "vulnerability_findings"],
       registry_key="GITLAB", maturity="implemented", vendor="GitLab"),
    _c("BITBUCKET", "Bitbucket", "devops", "app_password",
       ["BITBUCKET_USER", "BITBUCKET_APP_PASSWORD", "BITBUCKET_WORKSPACE"],
       ["branch_protection", "code_scanning_enabled"], vendor="Atlassian"),
    _c("JENKINS", "Jenkins", "devops", "api_token",
       ["JENKINS_URL", "JENKINS_USER", "JENKINS_API_TOKEN"],
       ["code_scanning_enabled", "logging_enabled"], vendor="Jenkins"),
    _c("SONARQUBE", "SonarQube", "devops", "api_token",
       ["SONARQUBE_URL", "SONARQUBE_TOKEN"],
       ["code_scanning_enabled", "vulnerability_findings"], vendor="Sonar"),
    _c("SNYK", "Snyk", "devops", "api_token",
       ["SNYK_TOKEN", "SNYK_ORG_ID"],
       ["vulnerability_findings", "code_scanning_enabled", "patch_status"], vendor="Snyk"),
    # ── ITSM / Ticketing ─────────────────────────────────────────────────────
    _c("JIRA", "Jira", "itsm", "api_token",
       ["JIRA_URL", "JIRA_EMAIL", "JIRA_API_TOKEN"],
       ["incidents_tracked", "access_reviews_completed"],
       registry_key="JIRA", maturity="implemented", vendor="Atlassian"),
    _c("SERVICENOW", "ServiceNow", "itsm", "basic_auth",
       ["SERVICENOW_INSTANCE", "SERVICENOW_USER", "SERVICENOW_PASSWORD"],
       ["incidents_tracked", "patch_status", "access_reviews_completed"],
       registry_key="SERVICENOW", maturity="implemented", vendor="ServiceNow"),
    _c("FRESHSERVICE", "Freshservice", "itsm", "api_token",
       ["FRESHSERVICE_DOMAIN", "FRESHSERVICE_API_KEY"],
       ["incidents_tracked", "patch_status"], vendor="Freshworks"),
    # ── Security tools ───────────────────────────────────────────────────────
    _c("CROWDSTRIKE", "CrowdStrike Falcon", "security", "oauth_client_credentials",
       ["CROWDSTRIKE_CLIENT_ID", "CROWDSTRIKE_CLIENT_SECRET"],
       ["endpoint_protection_active", "patch_status", "vulnerability_findings", "incidents_tracked"],
       registry_key="CROWDSTRIKE", maturity="implemented", vendor="CrowdStrike"),
    _c("QUALYS", "Qualys VMDR", "security", "basic_auth",
       ["QUALYS_PLATFORM_URL", "QUALYS_USER", "QUALYS_PASSWORD"],
       ["vulnerability_findings", "patch_status"],
       registry_key="QUALYS", maturity="implemented", vendor="Qualys"),
    _c("TENABLE", "Tenable.io", "security", "api_keys",
       ["TENABLE_ACCESS_KEY", "TENABLE_SECRET_KEY"],
       ["vulnerability_findings", "patch_status"], vendor="Tenable"),
    _c("WIZ", "Wiz", "security", "oauth_client_credentials",
       ["WIZ_CLIENT_ID", "WIZ_CLIENT_SECRET"],
       ["vulnerability_findings", "encryption_enabled", "logging_enabled"], vendor="Wiz"),
    _c("PRISMA_CLOUD", "Prisma Cloud", "security", "api_keys",
       ["PRISMA_ACCESS_KEY", "PRISMA_SECRET_KEY", "PRISMA_API_URL"],
       ["vulnerability_findings", "encryption_enabled", "logging_enabled"], vendor="Palo Alto"),
    _c("SENTINELONE", "SentinelOne", "security", "api_token",
       ["SENTINELONE_URL", "SENTINELONE_API_TOKEN"],
       ["endpoint_protection_active", "incidents_tracked", "patch_status"], vendor="SentinelOne"),
    _c("SPLUNK", "Splunk", "security", "api_token",
       ["SPLUNK_URL", "SPLUNK_TOKEN"],
       ["siem_alerts_monitored", "audit_logs_retained", "logging_enabled"], vendor="Splunk"),
    _c("MS_SENTINEL", "Microsoft Sentinel", "security", "oauth_client_credentials",
       ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "SENTINEL_WORKSPACE_ID"],
       ["siem_alerts_monitored", "incidents_tracked", "audit_logs_retained"], vendor="Microsoft"),
    # ── Privacy / GRC ────────────────────────────────────────────────────────
    _c("ONETRUST", "OneTrust", "grc", "oauth_client_credentials",
       ["ONETRUST_HOSTNAME", "ONETRUST_CLIENT_ID", "ONETRUST_CLIENT_SECRET"],
       ["consent_records_managed", "data_retention_policy", "ai_system_inventory"],
       vendor="OneTrust"),
    _c("ARCHER", "RSA Archer", "grc", "basic_auth",
       ["ARCHER_URL", "ARCHER_USER", "ARCHER_PASSWORD", "ARCHER_INSTANCE"],
       ["incidents_tracked", "access_reviews_completed"], vendor="RSA"),
    _c("SERVICENOW_GRC", "ServiceNow GRC", "grc", "basic_auth",
       ["SERVICENOW_INSTANCE", "SERVICENOW_USER", "SERVICENOW_PASSWORD"],
       ["incidents_tracked", "access_reviews_completed", "data_retention_policy"],
       registry_key="SERVICENOW", vendor="ServiceNow"),
    _c("VANTA", "Vanta", "grc", "oauth_client_credentials",
       ["VANTA_CLIENT_ID", "VANTA_CLIENT_SECRET"],
       ["mfa_enabled", "endpoint_protection_active", "access_reviews_completed"], vendor="Vanta"),
    _c("DRATA", "Drata", "grc", "api_token",
       ["DRATA_API_TOKEN"],
       ["mfa_enabled", "endpoint_protection_active", "access_reviews_completed"], vendor="Drata"),
    _c("SECUREFRAME", "Secureframe", "grc", "api_token",
       ["SECUREFRAME_API_TOKEN"],
       ["mfa_enabled", "access_reviews_completed"], vendor="Secureframe"),
    # ── SaaS / Collaboration ─────────────────────────────────────────────────
    _c("SLACK", "Slack", "saas", "bot_token",
       ["SLACK_BOT_TOKEN"],
       ["mfa_enabled", "audit_logs_retained"],
       registry_key="SLACK", maturity="implemented", vendor="Slack"),
    _c("MICROSOFT_365", "Microsoft 365", "saas", "oauth_client_credentials",
       ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"],
       ["mfa_enabled", "audit_logs_retained", "data_retention_policy"],
       registry_key="AZURE", vendor="Microsoft"),
    _c("GOOGLE_DRIVE", "Google Drive", "saas", "service_account_json",
       ["GOOGLE_WORKSPACE_SA_JSON"],
       ["data_retention_policy", "audit_logs_retained"], vendor="Google"),
    _c("CONFLUENCE", "Confluence", "saas", "api_token",
       ["JIRA_URL", "JIRA_EMAIL", "JIRA_API_TOKEN"],
       ["data_retention_policy", "audit_logs_retained"], vendor="Atlassian"),
    _c("SHAREPOINT", "SharePoint", "saas", "oauth_client_credentials",
       ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"],
       ["data_retention_policy", "audit_logs_retained"], vendor="Microsoft"),
    # ── Endpoint / Legacy ────────────────────────────────────────────────────
    _c("SSH", "SSH Linux", "endpoint", "ssh_key",
       ["SSH_HOST", "SSH_USER", "SSH_PRIVATE_KEY"],
       ["patch_status", "logging_enabled", "encryption_enabled"],
       registry_key="SSH", maturity="implemented", vendor="Linux"),
    _c("WINDOWS_SERVER", "Windows Server", "endpoint", "winrm_credentials",
       ["WINRM_HOST", "WINRM_USER", "WINRM_PASSWORD"],
       ["patch_status", "logging_enabled", "endpoint_protection_active"], vendor="Microsoft"),
    _c("DATABASE_AUDIT", "Database Audit (PostgreSQL/MySQL)", "endpoint", "connection_string",
       ["AUDIT_DB_URL"],
       ["encryption_enabled", "audit_logs_retained", "backup_configuration", "inactive_accounts_disabled"],
       registry_key="LEGACY", vendor="SQL"),
    # ── Built-ins ────────────────────────────────────────────────────────────
    _c("DEMO", "Demo (synthetic)", "endpoint", "none", [],
       EVIDENCE_TYPES, registry_key="DEMO", maturity="implemented", vendor="Comp-Lens"),
    _c("AIGOV", "AI Governance Inventory", "grc", "none", [],
       ["ai_system_inventory"], registry_key="AIGOV", maturity="implemented", vendor="Comp-Lens"),
]

_BY_KEY = {c["key"]: c for c in CONNECTOR_CATALOG}


def get(key: str) -> Optional[Dict[str, Any]]:
    return _BY_KEY.get((key or "").upper())


def all_connectors() -> List[Dict[str, Any]]:
    return CONNECTOR_CATALOG


def by_category(cat: str) -> List[Dict[str, Any]]:
    return [c for c in CONNECTOR_CATALOG if c["category"] == cat]
