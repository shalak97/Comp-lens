"""Connector capability surface — the inverted seam.

THE PROBLEM THIS SOLVES
-----------------------
Historically every connector decided which controls it supported by branching
on control_id inside `collect_telemetry`::

    if control_id in ("AC-2-7", "AC-2-3"): ...
    if control_id == "SC-28": ...
    raise ConnectorError(f"...does not support control {control_id}")

That makes control coverage scale with *engineering headcount*: every new
control needs a code change in every connector that could satisfy it, plus a
hand-written evaluator in the policy engine. Coverage stalled at 10 controls
against a 1,196-control catalog for exactly this reason.

THE INVERSION
-------------
Connectors no longer know about controls at all. Instead each declares a
capability surface: a set of PROBES. A probe is a reusable telemetry collector
bound to an *asset type*, not to a control, and it advertises the normalized
SIGNALS it emits.

Controls are then declared as data (see app/data/control_checks.json): each
check names the asset type it applies to, the signals it needs, and a boolean
expression over them. A resolver matches a check to any probe — on any
connector — whose asset type matches and whose signal set covers what the check
requires.

The payoff is leverage. One `s3_bucket` probe emitting 8 signals satisfies 8
different controls with zero additional connector code, and the same check runs
unchanged against AWS, Azure or GCP as soon as those connectors declare a probe
emitting the same signals. Adding a control becomes a data edit; adding a
connector makes every existing check that its probes cover work immediately.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# Telemetry planes — the ontology the rest of the platform already speaks
# (see app/data/telemetry_ontology.json and the control bindings' "plane" key).
PLANES = frozenset({
    "identity_access",
    "configuration",
    "change_delivery",
    "vulnerability_threat",
    "host_runtime",
    "data_protection",
    "network_boundary",
    "logging_monitoring",
    "attestation_document",
})


@dataclass(frozen=True)
class Probe:
    """One reusable telemetry collector on a connector.

    A probe is deliberately control-agnostic. It answers "what is true about
    this kind of asset right now", and the declarative checks decide what that
    means for compliance.
    """

    probe_id: str                      # unique within a connector, e.g. "s3_bucket"
    asset_type: str                    # what it inspects, e.g. "s3_bucket", "account"
    plane: str                         # which telemetry plane it reports on
    signals: tuple[str, ...]           # normalized field names it emits
    requires_asset: bool = True        # False for account/tenant-wide probes
    description: str = ""
    #: optional param name the probe accepts as an alias for asset_id
    asset_param: str | None = None

    def __post_init__(self) -> None:
        if self.plane not in PLANES:
            # Not fatal — an unknown plane still works, it just won't group in
            # the ontology views. Surface it loudly at import so it gets fixed.
            logger.warning(
                "probe %s declares unknown plane %r (known: %s)",
                self.probe_id, self.plane, ", ".join(sorted(PLANES)),
            )

    def covers(self, required: tuple[str, ...] | list[str]) -> bool:
        """True if this probe emits every signal a check requires."""
        return set(required).issubset(self.signals)


@dataclass
class CapabilitySurface:
    """Everything one connector can observe, as data."""

    source_system: str
    probes: dict[str, Probe] = field(default_factory=dict)

    def add(self, probe: Probe) -> None:
        if probe.probe_id in self.probes:
            raise ValueError(
                f"{self.source_system}: duplicate probe id {probe.probe_id!r}")
        self.probes[probe.probe_id] = probe

    def for_asset_type(self, asset_type: str) -> list[Probe]:
        return [p for p in self.probes.values() if p.asset_type == asset_type]

    def resolve(self, asset_type: str, required: tuple[str, ...] | list[str]) -> Probe | None:
        """Find a probe on this connector that can satisfy a check.

        Picks the probe with the *smallest* signal set that still covers the
        requirement, so a check asking for one field doesn't trigger an
        expensive wide probe when a narrow one would do.
        """
        candidates = [p for p in self.for_asset_type(asset_type) if p.covers(required)]
        if not candidates:
            return None
        return min(candidates, key=lambda p: len(p.signals))

    def signals(self) -> set[str]:
        out: set[str] = set()
        for p in self.probes.values():
            out.update(p.signals)
        return out

    def asset_types(self) -> set[str]:
        return {p.asset_type for p in self.probes.values()}

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_system": self.source_system,
            "probes": [
                {
                    "probe_id": p.probe_id,
                    "asset_type": p.asset_type,
                    "plane": p.plane,
                    "signals": list(p.signals),
                    "requires_asset": p.requires_asset,
                    "description": p.description,
                }
                for p in sorted(self.probes.values(), key=lambda x: x.probe_id)
            ],
        }


def build_surface(source_system: str, probes: tuple[Probe, ...] | list[Probe]) -> CapabilitySurface:
    surface = CapabilitySurface(source_system=source_system.upper())
    for p in probes:
        surface.add(p)
    return surface
