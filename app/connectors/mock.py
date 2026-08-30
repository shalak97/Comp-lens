"""MOCK connector — for demos, local testing, and the dashboard's "DEMO"
source system. Returns deterministic synthetic telemetry so you can exercise
every control and policy path without any real credentials.

Use source_system="DEMO" in an assessment request. NEVER use this for real
compliance — it does not touch any real system.

It declares the same capability surface (PROBES) as the real cloud connectors,
emitting the same normalized signal names, so every declarative control in
app/data/control_checks.json is reachable in demo mode. Without that surface the
dashboard's demo could only exercise the ten hand-written controls, and the
product silently demonstrated a fraction of the coverage it advertises.
"""

from __future__ import annotations

from typing import Any

from app.connectors.base import Asset, BaseConnector
from app.connectors.capabilities import Probe

#: Signals a healthy demo estate reports, grouped by the asset type that owns
#: them. Booleans are stated in the *compliant* direction; `fail` inverts them.
_COMPLIANT: dict[str, dict[str, Any]] = {
    "cloud_account": {
        "root_mfa_enabled": True,
        "root_access_keys_present": False,
        "password_min_length": 16,
        "password_requires_symbols": True,
        "password_requires_numbers": True,
        "password_requires_uppercase": True,
        "password_requires_lowercase": True,
        "password_reuse_prevention": 24,
        "password_max_age_days": 90,
        "logging_enabled": True,
        "multi_region_enabled": True,
        "log_file_validation_enabled": True,
        "trail_kms_encrypted": True,
        "cloudwatch_logs_integrated": True,
        "threat_detection_enabled": True,
        "config_recording_enabled": True,
        "config_records_all_resources": True,
    },
    "iam_user": {
        "mfa_enabled": True,
        "mfa_enforced": True,
        "days_since_last_login": 5,
        "days_since_key_rotation": 30,
        "access_key_count": 1,
        "has_inline_policy": False,
        "has_admin_policy": False,
        "console_access_enabled": True,
    },
    "object_storage": {
        "encryption_at_rest": True,
        "kms_encrypted": True,
        "public_access_blocked": True,
        "versioning_enabled": True,
        "access_logging_enabled": True,
        "tls_required": True,
        "lifecycle_configured": True,
    },
    "compute_instance": {
        "imdsv2_required": True,
        "public_ip_assigned": False,
        "detailed_monitoring_enabled": True,
        "ebs_optimized": True,
        "instance_state": "running",
    },
    "block_storage": {
        "encryption_at_rest": True,
        "kms_encrypted": True,
        "volume_state": "in-use",
    },
    "managed_database": {
        "encryption_at_rest": True,
        "publicly_accessible": False,
        "backup_retention_days": 30,
        "multi_az_enabled": True,
        "deletion_protection_enabled": True,
        "auto_minor_version_upgrade": True,
        "log_exports_enabled": True,
        "iam_auth_enabled": True,
    },
    "network_ruleset": {
        "unrestricted_ingress": False,
        "ssh_open_to_world": False,
        "rdp_open_to_world": False,
        "open_ingress_rule_count": 0,
    },
    "encryption_key": {
        "key_rotation_enabled": True,
        "key_enabled": True,
    },
    "virtual_network": {
        "flow_logs_enabled": True,
    },
}

#: Numeric signals where a *higher* reading is the compliant one, so `fail`
#: has to drive them down rather than up.
_HIGHER_IS_BETTER = frozenset({
    "password_min_length", "password_reuse_prevention", "password_max_age_days",
    "backup_retention_days",
})

_PLANES = {
    "cloud_account": "identity_access",
    "iam_user": "identity_access",
    "object_storage": "data_protection",
    "compute_instance": "host_runtime",
    "block_storage": "data_protection",
    "managed_database": "data_protection",
    "network_ruleset": "network_boundary",
    "encryption_key": "data_protection",
    "virtual_network": "network_boundary",
}


def _failing(signals: dict[str, Any]) -> dict[str, Any]:
    """The same estate, non-compliant — so remediation paths are demoable too."""
    out: dict[str, Any] = {}
    for k, v in signals.items():
        if isinstance(v, bool):
            out[k] = not v
        elif isinstance(v, int):
            out[k] = 0 if k in _HIGHER_IS_BETTER else 999
        else:
            out[k] = v
    return out


class MockConnector(BaseConnector):
    source_system = "DEMO"

    PROBES = tuple(
        Probe(
            probe_id=f"demo_{asset_type}",
            asset_type=asset_type,
            plane=_PLANES[asset_type],
            requires_asset=asset_type != "cloud_account",
            description=f"Synthetic {asset_type.replace('_', ' ')} posture.",
            signals=tuple(sorted(signals)),
        )
        for asset_type, signals in sorted(_COMPLIANT.items())
    )

    def healthcheck(self) -> bool:
        return True

    def collect_telemetry(
        self, control_id: str, asset_id: str | None, params: dict[str, Any]
    ) -> dict[str, Any]:
        # Synthetic but realistic telemetry per control. `fail` param can force
        # a failing result for testing remediation paths.
        force_fail = bool(params.get("fail"))

        base = {"owner": "demo-team", "asset": asset_id or "demo-asset"}
        mapping = {
            "AC-2-7": {"mfa_enforced": not force_fail},
            "AC-2-3": {"days_since_last_login": 120 if force_fail else 5},
            "CM-3": {"change_has_approval": not force_fail},
            "SC-28": {"encryption_at_rest": not force_fail},
            "SC-7": {"public_access_blocked": not force_fail},
            "AU-2": {"logging_enabled": not force_fail},
            "RA-5": {"critical_vulnerabilities": 3 if force_fail else 0},
            "SA-15-BRANCH": {"branch_protection_enabled": not force_fail},
            "SA-15-SECRETS": {"secret_scanning_enabled": not force_fail},
            "SC-28-HOST": {"disk_encrypted": not force_fail},
        }
        if control_id in mapping:
            telemetry = dict(base)
            telemetry.update(mapping[control_id])
            return telemetry
        # Everything else is served from the declarative check pack, exactly as
        # a real cloud connector serves it.
        return self.collect_via_capability(control_id, asset_id, params)

    def run_probe(
        self, probe_id: str, asset_id: str | None, params: dict[str, Any]
    ) -> dict[str, Any]:
        probe = self.surface().probes.get(probe_id)
        signals = _COMPLIANT.get(probe.asset_type, {}) if probe else {}
        telemetry: dict[str, Any] = {"owner": "demo-team", "asset": asset_id or "demo-asset"}
        telemetry.update(_failing(signals) if params.get("fail") else signals)
        return telemetry

    def discover_assets(self, params: dict[str, Any]) -> list[Asset]:
        """One representative asset per demo asset type, so the inventory and
        bulk-assessment paths are explorable without real credentials."""
        return [
            Asset(asset_id=f"demo-{asset_type.replace('_', '-')}-1", asset_type=asset_type,
                  source_system="DEMO", owner="demo-team")
            for asset_type in sorted(_COMPLIANT)
        ]
