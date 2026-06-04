"""SSH / Linux on-prem connector — REAL implementation using paramiko.

Maturity: PRODUCTION-READY (pending host access + testing).

Auth: SSH key (SSH_KEY_PATH) or password in params. Connects to a host and
runs read-only commands to assess configuration.

Supported controls:
  SC-28-HOST : root/data disk encryption (LUKS) active
  AU-2       : auditd logging service running

params: { "host": "1.2.3.4", "user": "ubuntu", "password": "...", "port": 22 }
asset_id may be used as the host.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.config import settings
from app.connectors.base import BaseConnector, ConnectorError

logger = logging.getLogger(__name__)


class SSHLinuxConnector(BaseConnector):
    source_system = "SSH"

    def _client(self, params: Dict[str, Any], asset_id: Optional[str]):
        try:
            import paramiko
        except ImportError as exc:  # pragma: no cover
            raise ConnectorError("paramiko is not installed.") from exc

        host = asset_id or params.get("host")
        if not host:
            raise ConnectorError("SSH control requires 'host' (or asset_id).")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs: Dict[str, Any] = {
            "hostname": host,
            "port": int(params.get("port", 22)),
            "username": params.get("user", settings.ssh_default_user),
            "timeout": settings.request_timeout_seconds,
        }
        if params.get("password"):
            connect_kwargs["password"] = params["password"]
        elif settings.ssh_key_path:
            connect_kwargs["key_filename"] = settings.ssh_key_path
        client.connect(**connect_kwargs)
        return client

    def _run(self, client, cmd: str) -> str:
        _stdin, stdout, _stderr = client.exec_command(cmd, timeout=settings.request_timeout_seconds)
        return stdout.read().decode("utf-8", "ignore").strip()

    def healthcheck(self) -> bool:
        # Healthcheck without a host is meaningless for SSH; assume reachable.
        return True

    def collect_telemetry(
        self, control_id: str, asset_id: Optional[str], params: Dict[str, Any]
    ) -> Dict[str, Any]:
        client = None
        try:
            client = self._client(params, asset_id)

            if control_id == "SC-28-HOST":
                out = self._run(client, "lsblk -o NAME,TYPE | grep -i crypt || true")
                return {
                    "disk_encrypted": bool(out.strip()),
                    "asset": asset_id or params.get("host"),
                    "owner": "infra-team",
                }

            if control_id == "AU-2":
                out = self._run(client, "systemctl is-active auditd 2>/dev/null || true")
                return {
                    "logging_enabled": out.strip() == "active",
                    "asset": asset_id or params.get("host"),
                    "owner": "infra-team",
                }

            raise ConnectorError(f"SSH connector does not support control {control_id}")
        except ConnectorError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ConnectorError(f"SSH error: {exc}") from exc
        finally:
            if client:
                client.close()
