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
from typing import Any

from app.config import settings
from app.connectors import urls as _urls
from app.connectors.base import Asset, BaseConnector, ConnectorError
from app.connectors.http_client import ResilientClient

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
        self._client = ResilientClient(
            service="GITHUB", timeout=settings.request_timeout_seconds, max_retries=3)

    def _get(self, path: str, ok_404: bool = False) -> Any:
        return self._client.get(f"{_API}{path}", headers=self._headers,
                                not_found_ok=ok_404)

    def _get_all_pages(self, path: str) -> list[Any]:
        """Every page of a collection, following GitHub's Link cursor.

        The loop, the cycle detection and the refusal to return a truncated
        inventory all live in ResilientClient now, shared with Okta — GitHub
        and Okta page the same RFC 5988 way, so there is no reason for two
        implementations to drift apart.
        """
        return self._client.get_all_pages(f"{_API}{path}", headers=self._headers)

    def healthcheck(self) -> bool:
        try:
            self._get("/user")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("GitHub healthcheck failed: %s", exc)
            return False

    def collect_telemetry(
        self, control_id: str, asset_id: str | None, params: dict[str, Any]
    ) -> dict[str, Any]:
        repo = asset_id or params.get("repo")
        if not repo or "/" not in repo:
            raise ConnectorError("GitHub control requires asset_id as 'owner/repo'.")

        if control_id == "SA-15-BRANCH":
            ref = _urls.multi_segment(repo, expected_parts=2)
            meta = self._get(f"/repos/{ref}")
            default_branch = meta.get("default_branch", "main")
            prot = self._get(
                f"/repos/{ref}/branches/{_urls.segment(default_branch)}/protection",
                ok_404=True,
            )
            return {
                "branch_protection_enabled": prot is not None,
                "asset": repo,
                "owner": meta.get("owner", {}).get("login"),
            }

        if control_id == "SA-15-SECRETS":
            meta = self._get(f"/repos/{_urls.multi_segment(repo, expected_parts=2)}")
            sec = meta.get("security_and_analysis", {}) or {}
            scanning = sec.get("secret_scanning", {}).get("status") == "enabled"
            return {
                "secret_scanning_enabled": scanning,
                "asset": repo,
                "owner": meta.get("owner", {}).get("login"),
            }

        raise ConnectorError(f"GitHub connector does not support control {control_id}")

    def discover_assets(self, params: dict[str, Any]) -> list[Asset]:
        org = params.get("org") or settings.github_org
        if not org:
            return []
        # Every repo in the org, or an error. Fetching one page of 50 and
        # swallowing failures into an empty list meant a 400-repo org was
        # assessed on 50 of them, and an API outage reported an org with no
        # repositories — both presented as a complete inventory. GitHub pages
        # with a Link header; discovery follows it.
        repos = self._get_all_pages(f"/orgs/{_urls.segment(org)}/repos?per_page=100")
        return [
            Asset(
                asset_id=r["full_name"],
                asset_type="github_repo",
                source_system="GITHUB",
                owner=org,
            )
            for r in repos
        ]
