"""Base connector contract.

Every connector — cloud, identity, code, endpoint, ticketing, on-prem, SaaS —
implements the same interface. The assessment service never knows which vendor
it is talking to; it just asks the connector to collect normalized telemetry
for a given control.

`collect_telemetry` MUST return a flat dict whose keys match what the policy
rules in app/policy/engine.py expect, e.g.:
    mfa_enforced: bool
    encryption_at_rest: bool
    public_access_blocked: bool
    branch_protection_enabled: bool
    critical_vulnerabilities: int
    ...
This normalization is the connector's job and is what makes the platform
vendor-agnostic.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Asset:
    asset_id: str
    asset_type: str
    source_system: str
    owner: str | None = None
    criticality: str = "medium"
    raw: dict[str, Any] = field(default_factory=dict)


class ConnectorError(RuntimeError):
    """Raised when a connector cannot collect telemetry (auth, network, etc.)."""


class BaseConnector(abc.ABC):
    #: short uppercase id, e.g. "AWS", "OKTA", "GITHUB"
    source_system: str = "BASE"

    @abc.abstractmethod
    def healthcheck(self) -> bool:
        """Return True if credentials/connectivity are valid."""

    @abc.abstractmethod
    def collect_telemetry(
        self, control_id: str, asset_id: str | None, params: dict[str, Any]
    ) -> dict[str, Any]:
        """Collect and NORMALIZE telemetry for one control against one asset.

        Returns a flat dict of normalized fields the policy engine understands.
        Raise ConnectorError on failure.
        """

    def discover_assets(self, params: dict[str, Any]) -> list[Asset]:  # optional
        return []
