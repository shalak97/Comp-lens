"""Separate registry for GRC-platform connectors — NOT mixed with native connectors."""
from __future__ import annotations

from typing import Dict
from app.grc_platforms.profiles import ALL_PROFILES
from app.grc_platforms.connector import LiveGRCConnector
from app.connectors.base import ConnectorError

# the mutually-exclusive set of GRC-platform keys
GRC_PLATFORM_REGISTRY: Dict[str, str] = {k: p.name for k, p in ALL_PROFILES.items()}


def get_grc_connector(platform: str) -> LiveGRCConnector:
    key = platform.upper()
    profile = ALL_PROFILES.get(key)
    if not profile:
        raise ConnectorError(f"unknown GRC platform '{platform}'; "
                             f"available: {list(ALL_PROFILES.keys())}")
    return LiveGRCConnector(profile)  # raises ConnectorError if not configured
