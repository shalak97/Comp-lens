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

from app.connectors.capabilities import CapabilitySurface, Probe, build_surface


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

    #: Capability surface — the probes this connector can run, declared as data.
    #: Connectors that still use a hardcoded control_id if-chain leave this
    #: empty and keep working unchanged; declaring probes is what opts a
    #: connector into declarative (data-driven) control coverage.
    PROBES: tuple[Probe, ...] = ()

    # ── capability surface ──
    @classmethod
    def surface(cls) -> CapabilitySurface:
        """This connector's capability surface.

        Built from the class-level PROBES declaration, so it can be inspected
        without instantiating the connector — which matters because
        instantiation requires live credentials.
        """
        cached = cls.__dict__.get("_surface_cache")
        if cached is None:
            cached = build_surface(cls.source_system, cls.PROBES)
            cls._surface_cache = cached
        return cached

    def run_probe(
        self, probe_id: str, asset_id: str | None, params: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute one declared probe and return its normalized signals.

        Connectors that declare PROBES must implement this. The default exists
        so legacy if-chain connectors don't have to.
        """
        raise ConnectorError(
            f"{self.source_system} connector does not implement probe '{probe_id}'.")

    def collect_via_capability(
        self, control_id: str, asset_id: str | None, params: dict[str, Any]
    ) -> dict[str, Any]:
        """Serve a control from the declarative check pack via a probe.

        This is the inverted path: look up what the control *needs* (asset type
        + signals), find a local probe that emits them, run it. The connector
        never has to know the control exists.

        Call this as the fallthrough at the end of `collect_telemetry` so
        hand-written control handling still takes precedence where it exists.
        """
        from app.services import control_checks

        check = control_checks.get(control_id)
        if check is None:
            raise ConnectorError(
                f"{self.source_system} connector does not support control {control_id}")

        probe = self.surface().resolve(check.asset_type, check.requires)
        if probe is None:
            raise ConnectorError(
                f"{self.source_system} cannot satisfy control {control_id}: no probe emits "
                f"{', '.join(check.requires)} for asset type '{check.asset_type}'.")

        if probe.requires_asset and not (asset_id or params.get(probe.asset_param or "")):
            raise ConnectorError(
                f"Control {control_id} requires an asset_id "
                f"({probe.asset_type}) for the {self.source_system} connector.")

        return self.run_probe(probe.probe_id, asset_id, params)

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
