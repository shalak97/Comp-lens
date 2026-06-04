"""Connector registry.

Maps a source_system id -> connector class. Connectors are instantiated lazily
(only when first used) so the app boots even if some credentials are missing.
A connector that can't initialize (missing creds) surfaces a clear error only
when something actually tries to use it.
"""

from __future__ import annotations

import logging
import time
from typing import Dict, Optional, Type

from app.connectors.base import BaseConnector, ConnectorError

logger = logging.getLogger(__name__)

HEALTH_TTL_SECONDS = 60


def _load_registry() -> Dict[str, Type[BaseConnector]]:
    from app.connectors.aws import AWSConnector
    from app.connectors.github import GitHubConnector
    from app.connectors.jira import JiraConnector
    from app.connectors.okta import OktaConnector
    from app.connectors.secondary import (
        AzureConnector,
        CrowdStrikeConnector,
        GCPConnector,
        GitLabConnector,
        QualysConnector,
        ServiceNowConnector,
        SlackConnector,
    )
    from app.connectors.ai_governance import AIGovernanceConnector
    from app.connectors.legacy import LegacyConnector
    from app.connectors.mock import MockConnector
    from app.connectors.ssh_linux import SSHLinuxConnector

    return {
        "DEMO": MockConnector,
        "LEGACY": LegacyConnector,
        "AIGOV": AIGovernanceConnector,
        "AWS": AWSConnector,
        "OKTA": OktaConnector,
        "GITHUB": GitHubConnector,
        "SSH": SSHLinuxConnector,
        "JIRA": JiraConnector,
        "AZURE": AzureConnector,
        "GCP": GCPConnector,
        "GITLAB": GitLabConnector,
        "SLACK": SlackConnector,
        "SERVICENOW": ServiceNowConnector,
        "QUALYS": QualysConnector,
        "CROWDSTRIKE": CrowdStrikeConnector,
    }


class ConnectorRegistry:
    def __init__(self) -> None:
        self._classes = _load_registry()
        # DEMO fabricates results; never expose it in production.
        from app.config import settings
        if not settings.demo_enabled():
            self._classes.pop("DEMO", None)
            logger.info("DEMO connector disabled (app_env=%s)", settings.app_env)
        self._instances: Dict[str, BaseConnector] = {}
        self._health: Dict[str, tuple] = {}  # name -> (timestamp, value)

    def supported(self) -> list[str]:
        return sorted(self._classes.keys())

    def get(self, source_system: str) -> BaseConnector:
        key = source_system.upper()
        if key not in self._classes:
            raise ConnectorError(
                f"Unsupported source_system '{source_system}'. "
                f"Supported: {', '.join(self.supported())}"
            )
        if key not in self._instances:
            try:
                self._instances[key] = self._classes[key]()
            except ConnectorError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise ConnectorError(f"Failed to init {key} connector: {exc}") from exc
        return self._instances[key]

    def healthcheck(self, source_system: str) -> Optional[bool]:
        # cache results for HEALTH_TTL_SECONDS so /connectors doesn't fire an
        # external API call per connector on every request.
        key = source_system.upper()
        now = time.time()
        hit = self._health.get(key)
        if hit and now - hit[0] < HEALTH_TTL_SECONDS:
            return hit[1]
        try:
            val: Optional[bool] = self.get(source_system).healthcheck()
        except ConnectorError:
            val = None
        self._health[key] = (now, val)
        return val


registry = ConnectorRegistry()
