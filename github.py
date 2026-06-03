"""GitHub connector — REAL implementation using the GitHub REST API.

Maturity: PRODUCTION-READY (pending your PAT + testing).

Auth: GITHUB_TOKEN (a fine-grained or classic PAT with repo + org read).
GITHUB_ORG optional, used for discovery.

Supported controls:
  SA-15-BRANCH  : default branch is protected   (asset_id = "owner/repo")
  SA-15-SECRETS : secret scanning enabled        (asset_id = "owner/repo")
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import requests

from app.config import settings
from app.connectors.base import Asset, BaseConnector, ConnectorError

logger = logging.getLogger(__name__)
_API = "https://api.github.com"


class GitHubConnector(BaseConnector):
    source_system = "GITHUB"

    def __init__(self) -> None:
        if not settings.github_token:
            raise ConnectorError("GITHUB_TOKEN must be set.")
        self._headers = {
            "Authorization": f"Bearer {settings.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self._timeout = settings.request_timeout_seconds

    def _get(self, path: str, ok_404: bool = False) -> Any:
        r = requests.get(f"{_API}{path}", headers=self._headers, timeout=self._timeout)
        if r.status_code == 404 and ok_404:
            return None
        if r.status_code >= 400:
            raise ConnectorError(f"GitHub API {r.status_code}: {r.text[:200]}")
        return r.json()

    def healthcheck(self) -> bool:
        try:
            self._get("/user")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("GitHub healthcheck failed: %s", exc)
            return False

    def collect_telemetry(
        self, control_id: str, asset_id: Optional[str], params: Dict[str, Any]
    ) -> Dict[str, Any]:
        repo = asset_id or params.get("repo")
        if not repo or "/" not in repo:
            raise ConnectorError("GitHub control requires asset_id as 'owner/repo'.")

        if control_id == "SA-15-BRANCH":
            meta = self._get(f"/repos/{repo}")
            default_branch = meta.get("default_branch", "main")
            prot = self._get(
                f"/repos/{repo}/branches/{default_branch}/protection", ok_404=True
            )
            return {
                "branch_protection_enabled": prot is not None,
                "asset": repo,
                "owner": meta.get("owner", {}).get("login"),
            }

        if control_id == "SA-15-SECRETS":
            meta = self._get(f"/repos/{repo}")
            sec = meta.get("security_and_analysis", {}) or {}
            scanning = sec.get("secret_scanning", {}).get("status") == "enabled"
            return {
                "secret_scanning_enabled": scanning,
                "asset": repo,
                "owner": meta.get("owner", {}).get("login"),
            }

        raise ConnectorError(f"GitHub connector does not support control {control_id}")

    def discover_assets(self, params: Dict[str, Any]) -> List[Asset]:
        org = params.get("org") or settings.github_org
        if not org:
            return []
        out: List[Asset] = []
        try:
            for r in self._get(f"/orgs/{org}/repos?per_page=50") or []:
                out.append(
                    Asset(
                        asset_id=r["full_name"],
                        asset_type="github_repo",
                        source_system="GITHUB",
                        owner=org,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("GitHub discovery failed: %s", exc)
        return out
