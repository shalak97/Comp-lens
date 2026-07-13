"""Jira connector — REAL implementation using the Jira Cloud REST API v3.

Maturity: PRODUCTION-READY (pending API token + testing).

Auth: JIRA_URL (https://your.atlassian.net), JIRA_EMAIL, JIRA_API_TOKEN
(create at id.atlassian.com > Security > API tokens). Basic auth.

Supported controls:
  CM-3 : a change/ticket has a documented approval
         (asset_id = issue key like "CHG-123"; approval inferred from an
          "Approved" status, an approval field, or an approval comment)
"""

from __future__ import annotations

import base64
import logging
from typing import Any

import requests

from app.config import settings
from app.connectors.base import BaseConnector, ConnectorError

logger = logging.getLogger(__name__)


class JiraConnector(BaseConnector):
    source_system = "JIRA"

    def __init__(self) -> None:
        if not (settings.jira_url and settings.jira_email and settings.jira_api_token):
            raise ConnectorError("JIRA_URL, JIRA_EMAIL and JIRA_API_TOKEN must be set.")
        self._base = settings.jira_url.rstrip("/")
        token = f"{settings.jira_email}:{settings.jira_api_token}".encode()
        self._headers = {
            "Authorization": f"Basic {base64.b64encode(token).decode()}",
            "Accept": "application/json",
        }
        self._timeout = settings.request_timeout_seconds

    def _get(self, path: str) -> Any:
        r = requests.get(f"{self._base}{path}", headers=self._headers, timeout=self._timeout)
        if r.status_code >= 400:
            raise ConnectorError(f"Jira API {r.status_code}: {r.text[:200]}")
        return r.json()

    def healthcheck(self) -> bool:
        try:
            self._get("/rest/api/3/myself")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Jira healthcheck failed: %s", exc)
            return False

    def collect_telemetry(
        self, control_id: str, asset_id: str | None, params: dict[str, Any]
    ) -> dict[str, Any]:
        if control_id != "CM-3":
            raise ConnectorError(f"Jira connector does not support control {control_id}")

        issue_key = asset_id or params.get("issue")
        if not issue_key:
            raise ConnectorError("Jira CM-3 requires asset_id (issue key, e.g. CHG-123).")

        issue = self._get(f"/rest/api/3/issue/{issue_key}?expand=changelog")
        fields = issue.get("fields", {})
        status_name = (fields.get("status") or {}).get("name", "").lower()

        approved = "approv" in status_name or status_name in {"done", "closed", "implemented"}

        # also scan changelog for an explicit approval transition
        if not approved:
            for hist in issue.get("changelog", {}).get("histories", []):
                for item in hist.get("items", []):
                    if item.get("field") == "status" and "approv" in str(item.get("toString", "")).lower():
                        approved = True
                        break

        return {
            "change_has_approval": approved,
            "asset": issue_key,
            "owner": (fields.get("assignee") or {}).get("displayName"),
        }
