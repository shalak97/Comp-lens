"""Separate registry for GRC-platform connectors — NOT mixed with native connectors.

Profiles come from the loader (built-in + any YAML profiles), so the set of
available platforms is data-driven: drop a YAML file in the profile dir and it
appears here automatically. Still mutually-exclusive from native connectors.
"""
from __future__ import annotations

from typing import Dict
from app.grc_platforms.loader import load_all_profiles
from app.grc_platforms.connector import LiveGRCConnector
from app.connectors.base import ConnectorError


def all_profiles() -> Dict[str, object]:
    return load_all_profiles()


def _registry() -> Dict[str, str]:
    return {k: p.name for k, p in load_all_profiles().items()}


# computed at import for back-compat; call refresh() after dropping new YAML files
GRC_PLATFORM_REGISTRY: Dict[str, str] = _registry()


def refresh() -> Dict[str, str]:
    """Re-scan profiles (e.g. after a new YAML file is added) without a restart."""
    global GRC_PLATFORM_REGISTRY
    GRC_PLATFORM_REGISTRY = _registry()
    return GRC_PLATFORM_REGISTRY


def get_grc_connector(platform: str) -> LiveGRCConnector:
    key = platform.upper()
    profile = load_all_profiles().get(key)
    if not profile:
        raise ConnectorError(f"unknown GRC platform '{platform}'; "
                             f"available: {list(load_all_profiles().keys())}")
    return LiveGRCConnector(profile)  # raises ConnectorError if not configured
