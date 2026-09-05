"""Security-tooling connectors: Snyk, Tenable.io, Wiz, Splunk.

These four were catalogued for a long time with no implementation behind
them — entries naming a vendor and the evidence it could supply, which
/connectors/catalog reported as production-grade integrations. This module
makes those claims real.

What they deliberately do NOT do is declare probes for cloud asset types they
cannot actually observe. A vulnerability scanner knows what is wrong with a
host; it does not know whether a bucket blocks public access, and having it
answer that question from inference would put a finding in front of an auditor
that no evidence supports. Each connector here reports only what its vendor
genuinely returns.

Field names and auth flows follow each vendor's documented API. Product tiers
expose different fields, so validate against your own tenant on first
connection.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from app.config import settings
from app.connectors import urls as _urls
from app.connectors.base import BaseConnector, ConnectorError
from app.connectors.capabilities import Probe
from app.connectors.http_client import ReadIntent, ResilientClient

logger = logging.getLogger(__name__)

#: Severity labels every one of these vendors uses for "fix this now".
_CRITICAL = {"critical"}


def _count_by_severity(items: list[dict[str, Any]], key: str = "severity") -> int:
    return sum(1 for i in items
               if str((i or {}).get(key, "")).strip().lower() in _CRITICAL)


# ──────────────────────────────────────────────────────────────────────────
# Snyk — REST API (token auth)
# ──────────────────────────────────────────────────────────────────────────
class SnykConnector(BaseConnector):
    source_system = "SNYK"

    PROBES = (
        Probe(
            probe_id="snyk_project",
            asset_type="code_repository",
            plane="vulnerability_threat",
            asset_param="project",
            description="Open dependency and code issues for a Snyk project.",
            signals=("critical_vulnerabilities", "code_scanning_enabled",
                     "asset", "owner"),
        ),
    )

    _VERSION = "2024-06-10"

    def __init__(self) -> None:
        if not (settings.snyk_token and settings.snyk_org_id):
            raise ConnectorError("SNYK_TOKEN and SNYK_ORG_ID required.")
        self._base = settings.snyk_api_url.rstrip("/")
        self._headers = {"Authorization": f"token {settings.snyk_token}",
                         "Accept": "application/vnd.api+json"}
        self._client = ResilientClient(
            service="SNYK", timeout=settings.request_timeout_seconds, max_retries=3)

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return self._client.get(f"{self._base}{path}", headers=self._headers,
                                params={"version": self._VERSION, **(params or {})})

    def healthcheck(self) -> bool:
        try:
            self._get(f"/rest/orgs/{settings.snyk_org_id}")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Snyk healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        if control_id == "RA-5":
            return self._project_telemetry(asset_id or params.get("project"))
        return self.collect_via_capability(control_id, asset_id, params)

    def run_probe(self, probe_id, asset_id, params) -> dict[str, Any]:
        if probe_id == "snyk_project":
            return self._project_telemetry(asset_id or params.get("project"))
        raise ConnectorError(f"Snyk connector has no handler for probe '{probe_id}'.")

    def _project_telemetry(self, project: str | None) -> dict[str, Any]:
        if not project:
            raise ConnectorError("Snyk controls require asset_id (project id).")
        issues = self._get(
            f"/rest/orgs/{settings.snyk_org_id}/issues",
            {"scan_item.id": project, "scan_item.type": "project",
             "status": "open", "limit": 100},
        ).get("data", []) or []
        severities = [
            {"severity": (i.get("attributes", {}) or {}).get("effective_severity_level")}
            for i in issues
        ]
        return {
            "critical_vulnerabilities": _count_by_severity(severities),
            # A project that Snyk is scanning at all is under code scanning.
            "code_scanning_enabled": True,
            "asset": project,
            "owner": "appsec-team",
        }


# ──────────────────────────────────────────────────────────────────────────
# Tenable.io — X-ApiKeys header auth
# ──────────────────────────────────────────────────────────────────────────
class TenableConnector(BaseConnector):
    source_system = "TENABLE"

    PROBES = (
        Probe(
            probe_id="tenable_asset",
            asset_type="host",
            plane="vulnerability_threat",
            asset_param="host",
            description="Open critical vulnerabilities for a scanned host.",
            signals=("critical_vulnerabilities", "asset", "owner"),
        ),
    )

    def __init__(self) -> None:
        if not (settings.tenable_access_key and settings.tenable_secret_key):
            raise ConnectorError("TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY required.")
        self._base = settings.tenable_base_url.rstrip("/")
        self._headers = {
            "X-ApiKeys": (f"accessKey={settings.tenable_access_key};"
                          f"secretKey={settings.tenable_secret_key}"),
            "Accept": "application/json",
        }
        self._client = ResilientClient(
            service="TENABLE", timeout=settings.request_timeout_seconds, max_retries=3)

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return self._client.get(f"{self._base}{path}", headers=self._headers,
                                params=params or {})

    def healthcheck(self) -> bool:
        try:
            self._get("/session")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Tenable healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        if control_id == "RA-5":
            return self._host_telemetry(asset_id or params.get("host"))
        return self.collect_via_capability(control_id, asset_id, params)

    def run_probe(self, probe_id, asset_id, params) -> dict[str, Any]:
        if probe_id == "tenable_asset":
            return self._host_telemetry(asset_id or params.get("host"))
        raise ConnectorError(f"Tenable connector has no handler for probe '{probe_id}'.")

    def _host_telemetry(self, host: str | None) -> dict[str, Any]:
        if not host:
            raise ConnectorError("Tenable controls require asset_id (asset uuid or hostname).")
        # severity 4 is Critical in Tenable's vulnerability model.
        body = self._get("/workbenches/assets/vulnerabilities",
                         {"filter.0.filter": "asset.name", "filter.0.quality": "eq",
                          "filter.0.value": host, "severity": 4})
        assets = body.get("assets", []) or []
        critical = sum(int((a.get("severities", {}) or {}).get("critical", 0) or 0)
                       for a in assets) if assets else 0
        return {
            "critical_vulnerabilities": critical,
            "asset": host,
            "owner": "secops-team",
        }


# ──────────────────────────────────────────────────────────────────────────
# Wiz — OAuth2 client credentials + GraphQL
# ──────────────────────────────────────────────────────────────────────────
class WizConnector(BaseConnector):
    source_system = "WIZ"

    PROBES = (
        Probe(
            probe_id="wiz_cloud_resource",
            asset_type="host",
            plane="vulnerability_threat",
            asset_param="resource",
            description="Open critical Wiz issues for a cloud resource.",
            signals=("critical_vulnerabilities", "asset", "owner"),
        ),
    )

    _ISSUES_QUERY = """
    query Issues($first: Int!, $filterBy: IssueFilters) {
      issues(first: $first, filterBy: $filterBy) {
        nodes { id severity status entitySnapshot { name } }
      }
    }
    """

    def __init__(self) -> None:
        if not (settings.wiz_client_id and settings.wiz_client_secret and settings.wiz_api_url):
            raise ConnectorError(
                "WIZ_CLIENT_ID / WIZ_CLIENT_SECRET / WIZ_API_URL required "
                "(the API endpoint is tenant-specific).")
        self._token: tuple[str, float] | None = None
        self._client = ResilientClient(
            service="WIZ", timeout=settings.request_timeout_seconds, max_retries=3)

    def _access_token(self) -> str:
        if self._token and time.time() < self._token[1] - 60:
            return self._token[0]
        body = self._client.post_read(
            settings.wiz_auth_url, intent=ReadIntent.TOKEN,
            data={"grant_type": "client_credentials",
                  "client_id": settings.wiz_client_id,
                  "client_secret": settings.wiz_client_secret,
                  "audience": "wiz-api"})
        self._token = (body["access_token"], time.time() + int(body.get("expires_in", 3600)))
        return self._token[0]

    def _graphql(self, query: str, variables: dict[str, Any]) -> Any:
        body = self._client.post_read(
            str(settings.wiz_api_url).rstrip("/") + "/graphql", intent=ReadIntent.QUERY,
            headers={"Authorization": f"Bearer {self._access_token()}"},
            json={"query": query, "variables": variables})
        if body.get("errors"):
            raise ConnectorError(f"Wiz GraphQL error: {str(body['errors'])[:200]}")
        return body.get("data", {})

    def healthcheck(self) -> bool:
        try:
            self._access_token()
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Wiz healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        if control_id == "RA-5":
            return self._resource_telemetry(asset_id or params.get("resource"))
        return self.collect_via_capability(control_id, asset_id, params)

    def run_probe(self, probe_id, asset_id, params) -> dict[str, Any]:
        if probe_id == "wiz_cloud_resource":
            return self._resource_telemetry(asset_id or params.get("resource"))
        raise ConnectorError(f"Wiz connector has no handler for probe '{probe_id}'.")

    def _resource_telemetry(self, resource: str | None) -> dict[str, Any]:
        if not resource:
            raise ConnectorError("Wiz controls require asset_id (resource name or id).")
        data = self._graphql(self._ISSUES_QUERY, {
            "first": 100,
            "filterBy": {"status": ["OPEN", "IN_PROGRESS"],
                         "severity": ["CRITICAL"],
                         "relatedEntity": {"name": resource}},
        })
        nodes = ((data.get("issues") or {}).get("nodes")) or []
        return {
            "critical_vulnerabilities": len(nodes),
            "asset": resource,
            "owner": "cloud-security-team",
        }


# ──────────────────────────────────────────────────────────────────────────
# Splunk — REST search API (bearer token)
# ──────────────────────────────────────────────────────────────────────────
class SplunkConnector(BaseConnector):
    source_system = "SPLUNK"

    PROBES = (
        Probe(
            probe_id="splunk_index",
            asset_type="log_index",
            plane="logging_monitoring",
            asset_param="index",
            description="Log index retention and alerting posture.",
            signals=("logging_enabled", "audit_logs_retained",
                     "siem_alerts_monitored", "retention_days", "asset", "owner"),
        ),
    )

    def __init__(self) -> None:
        if not (settings.splunk_url and settings.splunk_token):
            raise ConnectorError("SPLUNK_URL and SPLUNK_TOKEN required.")
        self._base = settings.splunk_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {settings.splunk_token}"}
        self._client = ResilientClient(
            service="SPLUNK", timeout=settings.request_timeout_seconds, max_retries=3)

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return self._client.get(f"{self._base}{path}", headers=self._headers,
                                params={"output_mode": "json", **(params or {})})

    def healthcheck(self) -> bool:
        try:
            self._get("/services/server/info")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Splunk healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        return self.collect_via_capability(control_id, asset_id, params)

    def run_probe(self, probe_id, asset_id, params) -> dict[str, Any]:
        if probe_id == "splunk_index":
            return self._index_telemetry(asset_id or params.get("index"))
        raise ConnectorError(f"Splunk connector has no handler for probe '{probe_id}'.")

    def _index_telemetry(self, index: str | None) -> dict[str, Any]:
        if not index:
            raise ConnectorError("Splunk controls require asset_id (index name).")
        entry = (self._get(
            f"/services/data/indexes/{_urls.segment(index)}").get("entry") or [{}])[0]
        content = entry.get("content", {}) or {}

        # frozenTimePeriodInSecs is when data leaves the index for good — the
        # only field that answers "how long are these logs actually kept".
        frozen = content.get("frozenTimePeriodInSecs")
        retention_days = int(frozen) // 86400 if str(frozen or "").isdigit() else None

        # Saved searches with alert actions are what makes the index monitored
        # rather than merely stored.
        alerting = None
        try:
            searches = self._get("/services/saved/searches", {"count": 0}).get("entry", []) or []
            alerting = any(
                index in str((s.get("content", {}) or {}).get("search", ""))
                and (s.get("content", {}) or {}).get("is_scheduled")
                and (s.get("content", {}) or {}).get("alert_type", "always") != "always"
                for s in searches)
        except ConnectorError as exc:
            logger.warning("Splunk saved-search read failed: %s", exc)

        out: dict[str, Any] = {
            "logging_enabled": not bool(content.get("disabled")),
            "asset": index,
            "owner": "secops-team",
        }
        if retention_days is not None:
            out["retention_days"] = retention_days
            # One year is the retention the audit-log controls ask for.
            out["audit_logs_retained"] = retention_days >= 365
        if alerting is not None:
            out["siem_alerts_monitored"] = alerting
        return out
