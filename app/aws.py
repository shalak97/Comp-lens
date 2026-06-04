"""AWS connector — REAL implementation using boto3.

Maturity: PRODUCTION-READY (pending your IAM permissions + testing).

Auth: uses the default boto3 credential chain. On EC2/ECS, attach an IAM role
(instance profile / task role) and set NO keys — boto3 picks the role up
automatically. Locally, set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or use
`aws configure`. Required read-only permissions: SecurityAudit + IAMReadOnly.

Supported controls (control_id -> what it checks):
  AC-2-7  : IAM user has MFA enabled            (param: username or asset_id)
  AC-2-3  : IAM user not stale (>90d no login)  (param: username or asset_id)
  SC-28   : S3 bucket encrypted at rest         (param: bucket or asset_id)
  SC-7    : S3 bucket public access blocked     (param: bucket or asset_id)
  AU-2    : CloudTrail logging enabled (account level)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.config import settings
from app.connectors.base import Asset, BaseConnector, ConnectorError

logger = logging.getLogger(__name__)


class AWSConnector(BaseConnector):
    source_system = "AWS"

    def __init__(self) -> None:
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover
            raise ConnectorError("boto3 is not installed.") from exc

        kwargs: Dict[str, Any] = {"region_name": settings.aws_region}
        if settings.aws_access_key_id and settings.aws_secret_access_key:
            kwargs["aws_access_key_id"] = settings.aws_access_key_id
            kwargs["aws_secret_access_key"] = settings.aws_secret_access_key
        self._session = boto3.session.Session(**kwargs)

    # ── health ──
    def healthcheck(self) -> bool:
        try:
            self._session.client("sts").get_caller_identity()
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("AWS healthcheck failed: %s", exc)
            return False

    # ── telemetry ──
    def collect_telemetry(
        self, control_id: str, asset_id: Optional[str], params: Dict[str, Any]
    ) -> Dict[str, Any]:
        try:
            if control_id in ("AC-2-7", "AC-2-3"):
                return self._iam_user_telemetry(asset_id or params.get("username"))
            if control_id in ("SC-28", "SC-7"):
                return self._s3_bucket_telemetry(asset_id or params.get("bucket"))
            if control_id == "AU-2":
                return self._cloudtrail_telemetry()
            raise ConnectorError(f"AWS connector does not support control {control_id}")
        except ConnectorError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ConnectorError(f"AWS API error: {exc}") from exc

    # ── IAM ──
    def _iam_user_telemetry(self, username: Optional[str]) -> Dict[str, Any]:
        if not username:
            raise ConnectorError("IAM control requires 'username' (or asset_id).")
        iam = self._session.client("iam")

        mfa = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
        mfa_enforced = len(mfa) > 0

        # last login / access-key usage
        days_since = None
        try:
            user = iam.get_user(UserName=username)["User"]
            pwd_last = user.get("PasswordLastUsed")
            if pwd_last:
                days_since = (datetime.now(timezone.utc) - pwd_last).days
        except Exception:  # noqa: BLE001
            pass

        return {
            "mfa_enforced": mfa_enforced,
            "days_since_last_login": days_since,
            "principal": username,
            "owner": "identity-team",
        }

    # ── S3 ──
    def _s3_bucket_telemetry(self, bucket: Optional[str]) -> Dict[str, Any]:
        if not bucket:
            raise ConnectorError("S3 control requires 'bucket' (or asset_id).")
        s3 = self._session.client("s3")

        # encryption at rest
        enc = False
        try:
            s3.get_bucket_encryption(Bucket=bucket)
            enc = True
        except Exception:  # noqa: BLE001
            enc = False

        # public access block
        blocked = False
        try:
            cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
            blocked = all(
                cfg.get(k, False)
                for k in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            )
        except Exception:  # noqa: BLE001
            blocked = False

        return {
            "encryption_at_rest": enc,
            "public_access_blocked": blocked,
            "asset": bucket,
            "owner": "cloud-platform-team",
        }

    # ── CloudTrail ──
    def _cloudtrail_telemetry(self) -> Dict[str, Any]:
        ct = self._session.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        logging_on = False
        for trail in trails:
            try:
                status = ct.get_trail_status(Name=trail["TrailARN"])
                if status.get("IsLogging"):
                    logging_on = True
                    break
            except Exception:  # noqa: BLE001
                continue
        return {"logging_enabled": logging_on, "owner": "secops-team"}

    # ── discovery ──
    def discover_assets(self, params: Dict[str, Any]) -> List[Asset]:
        assets: List[Asset] = []
        try:
            iam = self._session.client("iam")
            for u in iam.list_users().get("Users", []):
                assets.append(
                    Asset(
                        asset_id=u["UserName"],
                        asset_type="iam_user",
                        source_system="AWS",
                        owner="identity-team",
                    )
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("AWS discovery failed: %s", exc)
        return assets
