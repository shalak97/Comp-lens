"""MOCK connector — for demos, local testing, and the dashboard's "DEMO"
source system. Returns deterministic synthetic telemetry so you can exercise
every control and policy path without any real credentials.

Use source_system="DEMO" in an assessment request. NEVER use this for real
compliance — it does not touch any real system.
"""

from __future__ import annotations

from typing import Any

from app.connectors.base import BaseConnector


class MockConnector(BaseConnector):
    source_system = "DEMO"

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
        telemetry = dict(base)
        telemetry.update(mapping.get(control_id, {}))
        return telemetry
