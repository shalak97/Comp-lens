"""GRC-platform connectors — a separate, mutually-exclusive connector set.

This set is deliberately partitioned from the native connectors (AWS, Okta, …):
  - different base class (GRCPlatformConnector, bulk ingest — not per-control collect)
  - different registry (GRC_PLATFORM_REGISTRY)
  - different category ("grc_platform")
  - different endpoints (/v1/grc-sync/*)
  - evidence tagged source_kind="grc_platform"

A GRC platform (Vanta, Drata, OneTrust) has ALREADY collected and normalized
evidence. We don't re-collect it — we ingest their already-evaluated results and
re-express them as Comp-Lens trust telemetry. The two sets never compete for the
same evidence lane; when both attest a control, the trust graph shows them as
separate, independently-labeled attestations.
"""
from app.grc_platforms.base import GRCPlatformConnector, PlatformProfile, ControlAttestation
from app.grc_platforms.registry import GRC_PLATFORM_REGISTRY, get_grc_connector

__all__ = ["GRCPlatformConnector", "PlatformProfile", "ControlAttestation",
           "GRC_PLATFORM_REGISTRY", "get_grc_connector"]
