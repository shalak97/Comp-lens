"""Legacy connector — talks to mainframes, legacy databases, SOAP services,
flat-file/SFTP exports, and LDAP directories that have no modern REST API.

It implements the same BaseConnector contract as every other connector, so the
assessment engine treats a 1995 mainframe exactly like AWS.

Usage: source_system="LEGACY", and params={"source": "<configured source name>"}.
The named source (server-side config) defines the transport, query/operation,
and the field_map that normalizes the legacy record into control telemetry.
"""

from __future__ import annotations

import logging
from typing import Any

from app.connectors.base import Asset, BaseConnector, ConnectorError
from app.legacy import transports
from app.legacy.mapping import normalize
from app.legacy.sources import get_source, list_sources

logger = logging.getLogger(__name__)


class LegacyConnector(BaseConnector):
    source_system = "LEGACY"

    def healthcheck(self) -> bool:
        # healthy if at least one legacy source is configured
        return len(list_sources()) > 0

    def _resolve(self, params: dict[str, Any]):
        name = (params or {}).get("source")
        if not name:
            raise ConnectorError("LEGACY requires params.source naming a configured legacy source.")
        source = get_source(name)
        if not source:
            available = ", ".join(s["name"] for s in list_sources()) or "(none configured)"
            raise ConnectorError(f"unknown legacy source '{name}'. Configured: {available}")
        return source

    def collect_telemetry(self, control_id: str, asset_id: str | None,
                          params: dict[str, Any]) -> dict[str, Any]:
        source = self._resolve(params)
        raw = transports.fetch_raw(source, asset_id)
        if not raw:
            raise ConnectorError(f"legacy source '{source.name}' returned no record for asset '{asset_id}'")
        telemetry = normalize(raw, source.field_map)
        telemetry.setdefault("asset", asset_id)
        telemetry.setdefault("owner", telemetry.get("owner") or f"legacy:{source.name}")
        return telemetry

    def discover_assets(self, params: dict[str, Any]) -> list[Asset]:
        source = self._resolve(params)
        ids = transports.discover(source)
        return [Asset(asset_id=i, asset_type=f"legacy_{source.type}", source_system="LEGACY",
                      owner=f"legacy:{source.name}") for i in ids]
