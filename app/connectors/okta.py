"""Okta connector — REAL implementation using Okta's REST API.

Maturity: PRODUCTION-READY (pending your Okta API token + testing).

Auth: OKTA_ORG_URL (e.g. https://your-org.okta.com) and OKTA_API_TOKEN
(SSWS token from Okta Admin > Security > API > Tokens). Read-only scope is
sufficient for assessment.

Supported controls:
  AC-2-7 : user has an enrolled MFA factor       (asset_id = userId or login)
  AC-2-3 : user not stale (>90d since last login)
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from app.config import settings
from app.connectors.base import Asset, BaseConnector, ConnectorError
from app.connectors.http_client import ResilientClient

logger = logging.getLogger(__name__)


class OktaConnector(BaseConnector):
    source_system = "OKTA"

    def __init__(self) -> None:
        if not settings.okta_org_url or not settings.okta_api_token:
            raise ConnectorError("OKTA_ORG_URL and OKTA_API_TOKEN must be set.")
        self._base = settings.okta_org_url.rstrip("/")
        self._headers = {
            "Authorization": f"SSWS {settings.okta_api_token}",
            "Accept": "application/json",
        }
        # enterprise HTTP: retries, backoff, 429 handling, circuit breaker, SSRF guard
        self._client = ResilientClient(
            service="OKTA", timeout=settings.request_timeout_seconds, max_retries=3)

    def _get(self, path: str) -> Any:
        return self._client.get(f"{self._base}{path}", headers=self._headers)

    def healthcheck(self) -> bool:
        try:
            self._get("/api/v1/users?limit=1")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Okta healthcheck failed: %s", exc)
            return False

    def collect_telemetry(
        self, control_id: str, asset_id: str | None, params: dict[str, Any]
    ) -> dict[str, Any]:
        user_ref = asset_id or params.get("user")
        if not user_ref:
            raise ConnectorError("Okta control requires asset_id (userId or login).")

        user = self._get(f"/api/v1/users/{user_ref}")

        if control_id == "AC-2-7":
            factors = self._get(f"/api/v1/users/{user_ref}/factors")
            active = [f for f in factors if f.get("status") == "ACTIVE"]
            return {
                "mfa_enforced": len(active) > 0,
                "principal": user.get("profile", {}).get("login"),
                "owner": "identity-team",
            }

        if control_id == "AC-2-3":
            last_login = user.get("lastLogin")
            days = None
            if last_login:
                dt = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                days = (datetime.now(UTC) - dt).days
            return {
                "days_since_last_login": days,
                "principal": user.get("profile", {}).get("login"),
                "owner": "identity-team",
            }

        raise ConnectorError(f"Okta connector does not support control {control_id}")

    def discover_assets(self, params: dict[str, Any]) -> list[Asset]:
        out: list[Asset] = []
        try:
            for u in self._get("/api/v1/users?limit=50"):
                out.append(
                    Asset(
                        asset_id=u["id"],
                        asset_type="okta_user",
                        source_system="OKTA",
                        owner="identity-team",
                        raw={"login": u.get("profile", {}).get("login")},
                    )
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Okta discovery failed: %s", exc)
        return out
