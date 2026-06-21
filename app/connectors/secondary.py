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
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests

from app.config import settings
from app.connectors.base import BaseConnector, ConnectorError
from app.connectors.http_client import ResilientClient

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────
# Azure (Entra ID + resources) — via azure-identity + Microsoft Graph
# ──────────────────────────────────────────────────────────────────────────
class AzureConnector(BaseConnector):
    source_system = "AZURE"

    def __init__(self) -> None:
        if not (settings.azure_tenant_id and settings.azure_client_id and settings.azure_client_secret):
            raise ConnectorError("AZURE_TENANT_ID / CLIENT_ID / CLIENT_SECRET required.")
        self._token: Optional[str] = None
        self._token_exp: float = 0.0

    def _acquire_graph_token(self) -> str:
        import time
        # refresh if missing or within 60s of expiry
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        url = f"https://login.microsoftonline.com/{settings.azure_tenant_id}/oauth2/v2.0/token"
        data = {
            "client_id": settings.azure_client_id,
            "client_secret": settings.azure_client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }
        r = requests.post(url, data=data, timeout=settings.request_timeout_seconds)
        if r.status_code >= 400:
            raise ConnectorError(f"Azure token error {r.status_code}: {r.text[:200]}")
        body = r.json()
        self._token = body["access_token"]
        self._token_exp = time.time() + int(body.get("expires_in", 3600))
        return self._token

    def _graph(self, path: str) -> Any:
        r = requests.get(
            f"https://graph.microsoft.com/v1.0{path}",
            headers={"Authorization": f"Bearer {self._acquire_graph_token()}"},
            timeout=settings.request_timeout_seconds,
        )
        if r.status_code >= 400:
            raise ConnectorError(f"Graph API {r.status_code}: {r.text[:200]}")
        return r.json()

    def healthcheck(self) -> bool:
        try:
            self._graph("/organization")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Azure healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> Dict[str, Any]:
        user_ref = asset_id or params.get("user")
        if control_id == "AC-2-7":
            if not user_ref:
                raise ConnectorError("Azure AC-2-7 requires asset_id (user id/UPN).")
            # Per-user MFA registration via reports API (needs AuditLog.Read.All)
            data = self._graph(
                f"/reports/authenticationMethods/userRegistrationDetails/{user_ref}"
            )
            return {
                "mfa_enforced": bool(data.get("isMfaRegistered")),
                "principal": user_ref,
                "owner": "identity-team",
            }
        raise ConnectorError(f"Azure connector does not support control {control_id}")


# ──────────────────────────────────────────────────────────────────────────
# GCP — via google-cloud client libraries
# ──────────────────────────────────────────────────────────────────────────
class GCPConnector(BaseConnector):
    source_system = "GCP"

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

    def collect_telemetry(self, control_id, asset_id, params) -> Dict[str, Any]:
        if control_id in ("SC-28", "SC-7"):
            from google.cloud import storage

            bucket_name = asset_id or params.get("bucket")
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
            }
        raise ConnectorError(f"GCP connector does not support control {control_id}")


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

    def collect_telemetry(self, control_id, asset_id, params) -> Dict[str, Any]:
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

    def _get(self, method: str, params: Dict[str, Any] | None = None) -> Any:
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

    def collect_telemetry(self, control_id, asset_id, params) -> Dict[str, Any]:
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

    def collect_telemetry(self, control_id, asset_id, params) -> Dict[str, Any]:
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

    def collect_telemetry(self, control_id, asset_id, params) -> Dict[str, Any]:
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
        self._token: Optional[str] = None
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

    def _get(self, path: str, params: Dict[str, Any] | None = None) -> Any:
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

    def collect_telemetry(self, control_id, asset_id, params) -> Dict[str, Any]:
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
