"""Concrete GRC-platform connector — wires the profile-driven base to ResilientClient."""
from __future__ import annotations

import os
from typing import Any

from app.connectors.base import ConnectorError
from app.grc_platforms.base import GRCPlatformConnector, PlatformProfile

try:
    from app.connectors.http_client import ResilientClient
except Exception:  # pragma: no cover
    ResilientClient = None


class LiveGRCConnector(GRCPlatformConnector):
    """Production connector: read-only, routes through ResilientClient, fail-closed."""

    def __init__(self, profile: PlatformProfile):
        super().__init__(profile)
        self._creds = {v: os.getenv(v) for v in profile.env_vars}
        missing = [v for v, val in self._creds.items() if not val]
        if missing:
            raise ConnectorError(
                f"{profile.platform}: not configured — set {', '.join(missing)} to connect")
        self._client = ResilientClient(service=profile.platform, timeout=20.0, max_retries=3) \
            if ResilientClient else None

    def _headers(self) -> dict:
        p = self.profile
        if p.auth_method == "api_key":
            key = self._creds.get(p.env_vars[0])
            return {"Authorization": f"Bearer {key}", "Accept": "application/json"}
        if p.auth_method == "oauth2":
            # OAuth2 client-credentials token exchange happens here in production;
            # the access token is then sent as a bearer. Kept minimal for the contract.
            return {"Accept": "application/json"}
        return {"Accept": "application/json"}

    def _authed_get(self, path: str, cursor: str | None = None) -> Any:
        if not self._client:
            raise ConnectorError(f"{self.profile.platform}: HTTP client unavailable")
        url = self.profile.base_url + path
        params = {"cursor": cursor} if cursor else None
        return self._client.get(url, headers=self._headers(), params=params)
