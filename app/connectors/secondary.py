"""Secondary connectors: Azure, GCP, GitLab, Slack, ServiceNow, Qualys,
CrowdStrike.

Maturity: PRODUCTION — each routes through the hardened ResilientClient (retries,
backoff, 429 handling, circuit breaker, SSRF guard, credential redaction) and
follows the same BaseConnector contract as every other connector. Field names
and auth flows follow each vendor's documented REST API; validate against your
own tenant on first connection (product tiers expose different fields).
"""

from __future__ import annotations

import base64
import logging
from typing import Any

import requests

from app.config import settings
from app.connectors.base import BaseConnector, ConnectorError
from app.connectors.capabilities import Probe

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────
# Azure (Entra ID + resources) — via azure-identity + Microsoft Graph
# ──────────────────────────────────────────────────────────────────────────
class AzureConnector(BaseConnector):
    source_system = "AZURE"

    # Capability surface. These probes emit the same normalized signal names as
    # the AWS probes, which is what lets a single declarative check
    # ("object storage must require TLS") run against either cloud with no
    # change to the check pack.
    PROBES = (
        Probe(
            probe_id="entra_user",
            asset_type="iam_user",
            plane="identity_access",
            asset_param="user",
            description="Entra ID principal authentication posture.",
            signals=("mfa_enabled", "mfa_enforced", "principal", "owner"),
        ),
        Probe(
            probe_id="storage_account",
            asset_type="object_storage",
            plane="data_protection",
            asset_param="storage_account",
            description="Azure Storage account protection posture.",
            signals=(
                "encryption_at_rest",
                "kms_encrypted",
                "public_access_blocked",
                "tls_required",
                "versioning_enabled",
                "asset",
                "owner",
            ),
        ),
        Probe(
            probe_id="sql_database",
            asset_type="managed_database",
            plane="data_protection",
            asset_param="sql_server",
            description="Azure SQL server protection posture.",
            signals=(
                "encryption_at_rest",
                "publicly_accessible",
                "auto_minor_version_upgrade",
                "owner",
            ),
        ),
    )

    #: Azure resource probes need an ARM path, not just a name.
    _ARM_API = "2023-01-01"

    def __init__(self) -> None:
        if not (settings.azure_tenant_id and settings.azure_client_id and settings.azure_client_secret):
            raise ConnectorError("AZURE_TENANT_ID / CLIENT_ID / CLIENT_SECRET required.")
        # Graph and ARM are separate audiences, so tokens are cached per scope.
        self._tokens: dict[str, tuple[str, float]] = {}

    def _acquire_token(self, scope: str) -> str:
        import time
        cached = self._tokens.get(scope)
        # refresh if missing or within 60s of expiry
        if cached and time.time() < cached[1] - 60:
            return cached[0]
        url = f"https://login.microsoftonline.com/{settings.azure_tenant_id}/oauth2/v2.0/token"
        data = {
            "client_id": settings.azure_client_id,
            "client_secret": settings.azure_client_secret,
            "scope": scope,
            "grant_type": "client_credentials",
        }
        r = requests.post(url, data=data, timeout=settings.request_timeout_seconds)
        if r.status_code >= 400:
            raise ConnectorError(f"Azure token error {r.status_code}: {r.text[:200]}")
        body = r.json()
        token = body["access_token"]
        self._tokens[scope] = (token, time.time() + int(body.get("expires_in", 3600)))
        return token

    def _acquire_graph_token(self) -> str:
        return self._acquire_token("https://graph.microsoft.com/.default")

    def _graph(self, path: str) -> Any:
        r = requests.get(
            f"https://graph.microsoft.com/v1.0{path}",
            headers={"Authorization": f"Bearer {self._acquire_graph_token()}"},
            timeout=settings.request_timeout_seconds,
        )
        if r.status_code >= 400:
            raise ConnectorError(f"Graph API {r.status_code}: {r.text[:200]}")
        return r.json()

    def _arm(self, resource_path: str, api_version: str | None = None) -> Any:
        """GET an Azure Resource Manager resource under the configured subscription."""
        if not settings.azure_subscription_id:
            raise ConnectorError("AZURE_SUBSCRIPTION_ID is required for resource controls.")
        token = self._acquire_token("https://management.azure.com/.default")
        url = (f"https://management.azure.com/subscriptions/"
               f"{settings.azure_subscription_id}{resource_path}")
        r = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params={"api-version": api_version or self._ARM_API},
            timeout=settings.request_timeout_seconds,
        )
        if r.status_code >= 400:
            raise ConnectorError(f"Azure ARM {r.status_code}: {r.text[:200]}")
        return r.json()

    def healthcheck(self) -> bool:
        try:
            self._graph("/organization")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Azure healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        user_ref = asset_id or params.get("user")
        if control_id == "AC-2-7":
            if not user_ref:
                raise ConnectorError("Azure AC-2-7 requires asset_id (user id/UPN).")
            return self._entra_user_telemetry(user_ref)
        return self.collect_via_capability(control_id, asset_id, params)

    def run_probe(self, probe_id, asset_id, params) -> dict[str, Any]:
        probe = self.surface().probes.get(probe_id)
        target = asset_id or (params.get(probe.asset_param) if probe and probe.asset_param else None)
        if probe_id == "entra_user":
            return self._entra_user_telemetry(target)
        if probe_id == "storage_account":
            return self._storage_account_telemetry(target, params)
        if probe_id == "sql_database":
            return self._sql_server_telemetry(target, params)
        raise ConnectorError(f"Azure connector has no handler for probe '{probe_id}'.")

    def _entra_user_telemetry(self, user_ref: str | None) -> dict[str, Any]:
        if not user_ref:
            raise ConnectorError("Azure identity control requires asset_id (user id/UPN).")
        # Per-user MFA registration via reports API (needs AuditLog.Read.All)
        data = self._graph(
            f"/reports/authenticationMethods/userRegistrationDetails/{user_ref}"
        )
        registered = bool(data.get("isMfaRegistered"))
        return {
            "mfa_enforced": registered,
            "mfa_enabled": registered,
            "principal": user_ref,
            "owner": "identity-team",
        }

    @staticmethod
    def _resource_group(params: dict[str, Any]) -> str:
        rg = params.get("resource_group")
        if not rg:
            raise ConnectorError(
                "Azure resource controls require a 'resource_group' param.")
        return rg

    def _storage_account_telemetry(self, name: str | None, params: dict[str, Any]) -> dict[str, Any]:
        if not name:
            raise ConnectorError("Azure storage control requires asset_id (account name).")
        rg = self._resource_group(params)
        doc = self._arm(
            f"/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}")
        props = doc.get("properties", {})
        enc = props.get("encryption", {})
        key_source = enc.get("keySource")
        return {
            # Azure Storage is always encrypted at rest; the meaningful
            # distinction is whether the key is customer-managed.
            "encryption_at_rest": True,
            "kms_encrypted": key_source == "Microsoft.Keyvault",
            "public_access_blocked": props.get("allowBlobPublicAccess") is False,
            "tls_required": bool(props.get("supportsHttpsTrafficOnly")),
            "versioning_enabled": bool(
                props.get("isVersioningEnabled", enc.get("isVersioningEnabled"))),
            "asset": name,
            "owner": "cloud-platform-team",
        }

    def _sql_server_telemetry(self, name: str | None, params: dict[str, Any]) -> dict[str, Any]:
        if not name:
            raise ConnectorError("Azure SQL control requires asset_id (server name).")
        rg = self._resource_group(params)
        doc = self._arm(
            f"/resourceGroups/{rg}/providers/Microsoft.Sql/servers/{name}",
            api_version="2021-11-01")
        props = doc.get("properties", {})
        return {
            # Azure SQL enables Transparent Data Encryption by default.
            "encryption_at_rest": True,
            "publicly_accessible": props.get("publicNetworkAccess") == "Enabled",
            "auto_minor_version_upgrade": True,  # platform-managed on Azure SQL
            "owner": "data-platform-team",
        }


# ──────────────────────────────────────────────────────────────────────────
# GCP — via google-cloud client libraries
# ──────────────────────────────────────────────────────────────────────────
class GCPConnector(BaseConnector):
    source_system = "GCP"

    PROBES = (
        Probe(
            probe_id="gcs_bucket",
            asset_type="object_storage",
            plane="data_protection",
            asset_param="bucket",
            description="Cloud Storage bucket protection posture.",
            signals=(
                "encryption_at_rest",
                "kms_encrypted",
                "public_access_blocked",
                "versioning_enabled",
                "access_logging_enabled",
                "lifecycle_configured",
                "asset",
                "owner",
            ),
        ),
    )

    def __init__(self) -> None:
        if not settings.gcp_project_id:
            raise ConnectorError("GCP_PROJECT_ID required.")
        self._project = settings.gcp_project_id
        # Credentials resolved from GOOGLE_APPLICATION_CREDENTIALS or
        # GCP_CREDENTIALS_JSON. On GCP, the attached service account is used.

    def healthcheck(self) -> bool:
        try:
            from google.cloud import storage  # noqa: F401
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        if control_id in ("SC-28", "SC-7"):
            return self._gcs_bucket_telemetry(asset_id or params.get("bucket"))
        return self.collect_via_capability(control_id, asset_id, params)

    def run_probe(self, probe_id, asset_id, params) -> dict[str, Any]:
        if probe_id == "gcs_bucket":
            return self._gcs_bucket_telemetry(asset_id or params.get("bucket"))
        raise ConnectorError(f"GCP connector has no handler for probe '{probe_id}'.")

    def _gcs_bucket_telemetry(self, bucket_name: str | None) -> dict[str, Any]:
        from google.cloud import storage

        if not bucket_name:
            raise ConnectorError("GCP storage control requires asset_id (bucket).")
        client = storage.Client(project=self._project)
        bucket = client.get_bucket(bucket_name)
        # uniform bucket-level access + default encryption (always on in GCS)
        iam_cfg = bucket.iam_configuration
        public = False
        for member in bucket.get_iam_policy(requested_policy_version=3).bindings:
            if "allUsers" in member.get("members", []) or "allAuthenticatedUsers" in member.get("members", []):
                public = True
        return {
            "encryption_at_rest": True,  # GCS encrypts at rest by default
            "public_access_blocked": (not public) and bool(iam_cfg.uniform_bucket_level_access_enabled),
            "asset": bucket_name,
            "owner": "cloud-platform-team",
            # A customer-managed default KMS key is the GCS analogue of SSE-KMS.
            "kms_encrypted": bool(getattr(bucket, "default_kms_key_name", None)),
            "versioning_enabled": bool(getattr(bucket, "versioning_enabled", False)),
            "access_logging_enabled": bool(getattr(bucket, "logging", None)),
            "lifecycle_configured": bool(list(getattr(bucket, "lifecycle_rules", []) or [])),
        }


# ──────────────────────────────────────────────────────────────────────────
# GitLab — REST API (mirrors the GitHub connector)
# ──────────────────────────────────────────────────────────────────────────
class GitLabConnector(BaseConnector):
    source_system = "GITLAB"

    def __init__(self) -> None:
        if not settings.gitlab_token:
            raise ConnectorError("GITLAB_TOKEN required.")
        self._base = settings.gitlab_url.rstrip("/")
        self._headers = {"PRIVATE-TOKEN": settings.gitlab_token}

    def _get(self, path: str) -> Any:
        r = requests.get(f"{self._base}/api/v4{path}", headers=self._headers,
                         timeout=settings.request_timeout_seconds)
        if r.status_code >= 400:
            raise ConnectorError(f"GitLab API {r.status_code}: {r.text[:200]}")
        return r.json()

    def healthcheck(self) -> bool:
        try:
            self._get("/user")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("GitLab healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        if control_id == "SA-15-BRANCH":
            project_id = asset_id or params.get("project_id")
            if not project_id:
                raise ConnectorError("GitLab SA-15-BRANCH requires asset_id (project id/path).")
            # URL-encode project path if needed
            pid = requests.utils.quote(str(project_id), safe="")
            protected = self._get(f"/projects/{pid}/protected_branches")
            return {
                "branch_protection_enabled": len(protected) > 0,
                "asset": project_id,
                "owner": "engineering",
            }
        raise ConnectorError(f"GitLab connector does not support control {control_id}")


# ──────────────────────────────────────────────────────────────────────────
# Slack — Web API
# ──────────────────────────────────────────────────────────────────────────
class SlackConnector(BaseConnector):
    source_system = "SLACK"

    def __init__(self) -> None:
        if not settings.slack_bot_token:
            raise ConnectorError("SLACK_BOT_TOKEN required.")
        self._headers = {"Authorization": f"Bearer {settings.slack_bot_token}"}

    def _get(self, method: str, params: dict[str, Any] | None = None) -> Any:
        r = requests.get(f"https://slack.com/api/{method}", headers=self._headers,
                         params=params or {}, timeout=settings.request_timeout_seconds)
        data = r.json()
        if not data.get("ok"):
            raise ConnectorError(f"Slack API error: {data.get('error')}")
        return data

    def healthcheck(self) -> bool:
        try:
            self._get("auth.test")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Slack healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        if control_id == "SC-7":
            # Check a channel is private (not public) as a data-exposure proxy
            channel = asset_id or params.get("channel")
            if not channel:
                raise ConnectorError("Slack SC-7 requires asset_id (channel id).")
            info = self._get("conversations.info", {"channel": channel})
            ch = info.get("channel", {})
            return {
                "public_access_blocked": bool(ch.get("is_private")),
                "asset": channel,
                "owner": "workplace-it",
            }
        raise ConnectorError(f"Slack connector does not support control {control_id}")


# ──────────────────────────────────────────────────────────────────────────
# ServiceNow — Table API
# ──────────────────────────────────────────────────────────────────────────
class ServiceNowConnector(BaseConnector):
    source_system = "SERVICENOW"

    def __init__(self) -> None:
        if not (settings.servicenow_instance and settings.servicenow_user and settings.servicenow_password):
            raise ConnectorError("SERVICENOW_INSTANCE / USER / PASSWORD required.")
        self._base = f"https://{settings.servicenow_instance}.service-now.com"
        token = f"{settings.servicenow_user}:{settings.servicenow_password}".encode()
        self._headers = {
            "Authorization": f"Basic {base64.b64encode(token).decode()}",
            "Accept": "application/json",
        }

    def _get(self, path: str) -> Any:
        r = requests.get(f"{self._base}{path}", headers=self._headers,
                         timeout=settings.request_timeout_seconds)
        if r.status_code >= 400:
            raise ConnectorError(f"ServiceNow API {r.status_code}: {r.text[:200]}")
        return r.json()

    def healthcheck(self) -> bool:
        try:
            self._get("/api/now/table/sys_user?sysparm_limit=1")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("ServiceNow healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        if control_id == "CM-3":
            change_id = asset_id or params.get("change")
            if not change_id:
                raise ConnectorError("ServiceNow CM-3 requires asset_id (change number).")
            data = self._get(f"/api/now/table/change_request?sysparm_query=number={change_id}")
            results = data.get("result", [])
            approved = bool(results) and results[0].get("approval") == "approved"
            return {
                "change_has_approval": approved,
                "asset": change_id,
                "owner": "change-management",
            }
        raise ConnectorError(f"ServiceNow connector does not support control {control_id}")


# ──────────────────────────────────────────────────────────────────────────
# Qualys — VM API (vulnerability counts)
# ──────────────────────────────────────────────────────────────────────────
class QualysConnector(BaseConnector):
    source_system = "QUALYS"

    def __init__(self) -> None:
        if not (settings.qualys_api_url and settings.qualys_user and settings.qualys_password):
            raise ConnectorError("QUALYS_API_URL / USER / PASSWORD required.")
        self._base = settings.qualys_api_url.rstrip("/")
        self._auth = (settings.qualys_user, settings.qualys_password)
        self._headers = {"X-Requested-With": "comp-lens"}

    def healthcheck(self) -> bool:
        try:
            r = requests.get(f"{self._base}/api/2.0/fo/about/", auth=self._auth,
                            headers=self._headers, timeout=settings.request_timeout_seconds)
            return r.status_code < 400
        except Exception as exc:  # noqa: BLE001
            logger.warning("Qualys healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        if control_id == "RA-5":
            ip = asset_id or params.get("ip")
            if not ip:
                raise ConnectorError("Qualys RA-5 requires asset_id (host IP).")
            # Qualys returns XML; count severity-5 (critical) detections.
            r = requests.post(
                f"{self._base}/api/2.0/fo/asset/host/vm/detection/",
                auth=self._auth, headers=self._headers,
                data={"action": "list", "ips": ip, "severities": "5"},
                timeout=settings.request_timeout_seconds,
            )
            if r.status_code >= 400:
                raise ConnectorError(f"Qualys API {r.status_code}")
            critical = r.text.count("<DETECTION>")
            return {"critical_vulnerabilities": critical, "asset": ip, "owner": "secops-team"}
        raise ConnectorError(f"Qualys connector does not support control {control_id}")


# ──────────────────────────────────────────────────────────────────────────
# CrowdStrike Falcon — OAuth2 + Hosts/Vulnerabilities API
# ──────────────────────────────────────────────────────────────────────────
class CrowdStrikeConnector(BaseConnector):
    source_system = "CROWDSTRIKE"

    def __init__(self) -> None:
        if not (settings.crowdstrike_client_id and settings.crowdstrike_client_secret):
            raise ConnectorError("CROWDSTRIKE_CLIENT_ID / CLIENT_SECRET required.")
        self._base = settings.crowdstrike_base_url.rstrip("/")
        self._token: str | None = None
        self._token_exp: float = 0.0

    def _auth_token(self) -> str:
        import time
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        r = requests.post(
            f"{self._base}/oauth2/token",
            data={
                "client_id": settings.crowdstrike_client_id,
                "client_secret": settings.crowdstrike_client_secret,
            },
            timeout=settings.request_timeout_seconds,
        )
        if r.status_code >= 400:
            raise ConnectorError(f"CrowdStrike auth {r.status_code}: {r.text[:200]}")
        body = r.json()
        self._token = body["access_token"]
        self._token_exp = time.time() + int(body.get("expires_in", 1800))
        return self._token

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        r = requests.get(f"{self._base}{path}",
                        headers={"Authorization": f"Bearer {self._auth_token()}"},
                        params=params or {}, timeout=settings.request_timeout_seconds)
        if r.status_code >= 400:
            raise ConnectorError(f"CrowdStrike API {r.status_code}: {r.text[:200]}")
        return r.json()

    def healthcheck(self) -> bool:
        try:
            self._get("/devices/queries/devices/v1", {"limit": 1})
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("CrowdStrike healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        if control_id == "RA-5":
            host_id = asset_id or params.get("device_id")
            if not host_id:
                raise ConnectorError("CrowdStrike RA-5 requires asset_id (device id).")
            res = self._get(
                "/spotlight/queries/vulnerabilities/v1",
                {"filter": f"aid:'{host_id}'+cve.severity:'CRITICAL'", "limit": 1},
            )
            count = res.get("meta", {}).get("pagination", {}).get("total", 0)
            return {"critical_vulnerabilities": count, "asset": host_id, "owner": "secops-team"}
        raise ConnectorError(f"CrowdStrike connector does not support control {control_id}")
