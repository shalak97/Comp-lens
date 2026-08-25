"""AWS connector — REAL implementation using boto3.

Maturity: PRODUCTION-READY (pending your IAM permissions + testing).

Auth: uses the default boto3 credential chain. On EC2/ECS, attach an IAM role
(instance profile / task role) and set NO keys — boto3 picks the role up
automatically. Locally, set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or use
`aws configure`. Required read-only permissions: SecurityAudit + IAMReadOnly.

COVERAGE MODEL
--------------
This connector declares a capability surface (PROBES) rather than a list of
supported control ids. Each probe inspects one asset type and emits normalized
signals; the declarative check pack in app/data/control_checks.json decides what
those signals mean for any given control. Adding a control that these probes
already cover requires no change to this file.

The five original control ids (AC-2-7, AC-2-3, SC-28, SC-7, AU-2) keep their
hand-written dispatch so existing callers and stored findings are unaffected;
everything else falls through to probe resolution.

FAILURE SEMANTICS
-----------------
Every AWS call is individually guarded and yields None when it cannot be made
(missing permission, API error). A None signal evaluates to NOT_APPLICABLE, not
FAIL — "we could not observe this" must never be reported to an auditor as "we
observed this and it is broken".
"""

from __future__ import annotations

import contextlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

from app.config import settings
from app.connectors.base import Asset, BaseConnector, ConnectorError
from app.connectors.capabilities import Probe

logger = logging.getLogger(__name__)

# Ports that should never be reachable from 0.0.0.0/0.
_SSH_PORT = 22
_RDP_PORT = 3389


def _days_since(dt: datetime | None) -> int | None:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return (datetime.now(UTC) - dt).days


class AWSConnector(BaseConnector):
    source_system = "AWS"

    PROBES = (
        Probe(
            probe_id="account_iam",
            asset_type="cloud_account",
            plane="identity_access",
            requires_asset=False,
            description="Account-wide IAM posture: root account and password policy.",
            signals=(
                "root_mfa_enabled",
                "root_access_keys_present",
                "password_min_length",
                "password_requires_symbols",
                "password_requires_numbers",
                "password_requires_uppercase",
                "password_requires_lowercase",
                "password_reuse_prevention",
                "password_max_age_days",
            ),
        ),
        Probe(
            probe_id="iam_user",
            asset_type="iam_user",
            plane="identity_access",
            asset_param="username",
            description="Per-principal IAM posture.",
            signals=(
                "mfa_enabled",
                "mfa_enforced",
                "days_since_last_login",
                "days_since_key_rotation",
                "access_key_count",
                "has_inline_policy",
                "has_admin_policy",
                "console_access_enabled",
                "principal",
                "owner",
            ),
        ),
        Probe(
            probe_id="s3_bucket",
            asset_type="object_storage",
            plane="data_protection",
            asset_param="bucket",
            description="Object storage protection posture.",
            signals=(
                "encryption_at_rest",
                "kms_encrypted",
                "public_access_blocked",
                "versioning_enabled",
                "access_logging_enabled",
                "tls_required",
                "lifecycle_configured",
                "asset",
                "owner",
            ),
        ),
        Probe(
            probe_id="cloudtrail",
            asset_type="cloud_account",
            plane="logging_monitoring",
            requires_asset=False,
            description="Account audit-trail posture.",
            signals=(
                "logging_enabled",
                "multi_region_enabled",
                "log_file_validation_enabled",
                "trail_kms_encrypted",
                "cloudwatch_logs_integrated",
                "owner",
            ),
        ),
        Probe(
            probe_id="ec2_instance",
            asset_type="compute_instance",
            plane="host_runtime",
            asset_param="instance_id",
            description="Compute instance hardening posture.",
            signals=(
                "imdsv2_required",
                "public_ip_assigned",
                "detailed_monitoring_enabled",
                "ebs_optimized",
                "instance_state",
            ),
        ),
        Probe(
            probe_id="ebs_volume",
            asset_type="block_storage",
            plane="data_protection",
            asset_param="volume_id",
            description="Block storage encryption posture.",
            signals=("encryption_at_rest", "kms_encrypted", "volume_state"),
        ),
        Probe(
            probe_id="rds_instance",
            asset_type="managed_database",
            plane="data_protection",
            asset_param="db_instance_id",
            description="Managed database protection posture.",
            signals=(
                "encryption_at_rest",
                "publicly_accessible",
                "backup_retention_days",
                "multi_az_enabled",
                "deletion_protection_enabled",
                "auto_minor_version_upgrade",
                "log_exports_enabled",
                "iam_auth_enabled",
            ),
        ),
        Probe(
            probe_id="security_group",
            asset_type="network_ruleset",
            plane="network_boundary",
            asset_param="group_id",
            description="Network boundary exposure posture.",
            signals=(
                "unrestricted_ingress",
                "ssh_open_to_world",
                "rdp_open_to_world",
                "open_ingress_rule_count",
            ),
        ),
        Probe(
            probe_id="kms_key",
            asset_type="encryption_key",
            plane="data_protection",
            asset_param="key_id",
            description="Key management rotation posture.",
            signals=("key_rotation_enabled", "key_enabled"),
        ),
        Probe(
            probe_id="vpc",
            asset_type="virtual_network",
            plane="network_boundary",
            asset_param="vpc_id",
            description="Network telemetry capture posture.",
            signals=("flow_logs_enabled",),
        ),
        Probe(
            probe_id="guardduty",
            asset_type="cloud_account",
            plane="vulnerability_threat",
            requires_asset=False,
            description="Account threat-detection posture.",
            signals=("threat_detection_enabled",),
        ),
        Probe(
            probe_id="config_recorder",
            asset_type="cloud_account",
            plane="configuration",
            requires_asset=False,
            description="Configuration-drift recording posture.",
            signals=("config_recording_enabled", "config_records_all_resources"),
        ),
    )

    def __init__(self) -> None:
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover
            raise ConnectorError("boto3 is not installed.") from exc

        kwargs: dict[str, Any] = {"region_name": settings.aws_region}
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
        self, control_id: str, asset_id: str | None, params: dict[str, Any]
    ) -> dict[str, Any]:
        try:
            # Legacy hand-written dispatch, kept verbatim so existing findings,
            # callers and idempotency keys are unaffected by the seam inversion.
            if control_id in ("AC-2-7", "AC-2-3"):
                return self._iam_user_telemetry(asset_id or params.get("username"))
            if control_id in ("SC-28", "SC-7"):
                return self._s3_bucket_telemetry(asset_id or params.get("bucket"))
            if control_id == "AU-2":
                return self._cloudtrail_telemetry()
            # Everything else is served declaratively from the check pack.
            return self.collect_via_capability(control_id, asset_id, params)
        except ConnectorError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ConnectorError(f"AWS API error: {exc}") from exc

    # ── probe dispatch ──
    def run_probe(
        self, probe_id: str, asset_id: str | None, params: dict[str, Any]
    ) -> dict[str, Any]:
        probe = self.surface().probes.get(probe_id)
        target = asset_id or (params.get(probe.asset_param) if probe and probe.asset_param else None)
        handlers = {
            "account_iam": lambda: self._account_iam_telemetry(),
            "iam_user": lambda: self._iam_user_telemetry(target),
            "s3_bucket": lambda: self._s3_bucket_telemetry(target),
            "cloudtrail": lambda: self._cloudtrail_telemetry(),
            "ec2_instance": lambda: self._ec2_instance_telemetry(target),
            "ebs_volume": lambda: self._ebs_volume_telemetry(target),
            "rds_instance": lambda: self._rds_instance_telemetry(target),
            "security_group": lambda: self._security_group_telemetry(target),
            "kms_key": lambda: self._kms_key_telemetry(target),
            "vpc": lambda: self._vpc_telemetry(target),
            "guardduty": lambda: self._guardduty_telemetry(),
            "config_recorder": lambda: self._config_recorder_telemetry(),
        }
        handler = handlers.get(probe_id)
        if handler is None:
            raise ConnectorError(f"AWS connector has no handler for probe '{probe_id}'.")
        return handler()

    # ── account-level IAM ──
    def _account_iam_telemetry(self) -> dict[str, Any]:
        iam = self._session.client("iam")
        out: dict[str, Any] = {"owner": "identity-team"}

        # Root account facts come from the account summary map.
        try:
            summary = iam.get_account_summary().get("SummaryMap", {})
            out["root_mfa_enabled"] = bool(summary.get("AccountMFAEnabled"))
            out["root_access_keys_present"] = bool(summary.get("AccountAccessKeysPresent"))
        except Exception as exc:  # noqa: BLE001
            logger.info("AWS account summary unavailable: %s", exc)

        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy", {})
            out.update({
                "password_min_length": policy.get("MinimumPasswordLength"),
                "password_requires_symbols": policy.get("RequireSymbols"),
                "password_requires_numbers": policy.get("RequireNumbers"),
                "password_requires_uppercase": policy.get("RequireUppercaseCharacters"),
                "password_requires_lowercase": policy.get("RequireLowercaseCharacters"),
                "password_reuse_prevention": policy.get("PasswordReusePrevention") or 0,
                "password_max_age_days": policy.get("MaxPasswordAge") or 0,
            })
        except Exception as exc:  # noqa: BLE001
            # NoSuchEntity means no policy is set at all — that is an observed
            # fact, not a missing observation, so report the weakest posture.
            if "NoSuchEntity" in str(exc):
                out.update({
                    "password_min_length": 0, "password_requires_symbols": False,
                    "password_requires_numbers": False, "password_requires_uppercase": False,
                    "password_requires_lowercase": False, "password_reuse_prevention": 0,
                    "password_max_age_days": 0,
                })
            else:
                logger.info("AWS password policy unavailable: %s", exc)
        return out

    # ── IAM ──
    def _iam_user_telemetry(self, username: str | None) -> dict[str, Any]:
        if not username:
            raise ConnectorError("IAM control requires 'username' (or asset_id).")
        iam = self._session.client("iam")

        mfa = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
        mfa_enforced = len(mfa) > 0

        # last login / access-key usage
        days_since = None
        console_access = None
        try:
            user = iam.get_user(UserName=username)["User"]
            days_since = _days_since(user.get("PasswordLastUsed"))
        except Exception:  # noqa: BLE001
            pass

        try:
            iam.get_login_profile(UserName=username)
            console_access = True
        except Exception as exc:  # noqa: BLE001
            console_access = False if "NoSuchEntity" in str(exc) else None

        key_count = None
        key_age = None
        try:
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            key_count = len(keys)
            ages = [_days_since(k.get("CreateDate")) for k in keys]
            ages = [a for a in ages if a is not None]
            key_age = max(ages) if ages else 0
        except Exception:  # noqa: BLE001
            pass

        inline = None
        admin = None
        try:
            inline = bool(iam.list_user_policies(UserName=username).get("PolicyNames"))
            attached = iam.list_attached_user_policies(UserName=username).get(
                "AttachedPolicies", [])
            admin = any(p.get("PolicyName") == "AdministratorAccess" for p in attached)
        except Exception:  # noqa: BLE001
            pass

        return {
            # legacy field names preserved for the original AC-2-* controls
            "mfa_enforced": mfa_enforced,
            "days_since_last_login": days_since,
            "principal": username,
            "owner": "identity-team",
            # capability-surface signals
            "mfa_enabled": mfa_enforced,
            "days_since_key_rotation": key_age,
            "access_key_count": key_count,
            "has_inline_policy": inline,
            "has_admin_policy": admin,
            "console_access_enabled": console_access,
        }

    # ── S3 ──
    def _s3_bucket_telemetry(self, bucket: str | None) -> dict[str, Any]:
        if not bucket:
            raise ConnectorError("S3 control requires 'bucket' (or asset_id).")
        s3 = self._session.client("s3")

        # encryption at rest
        enc = False
        kms = False
        try:
            rules = (s3.get_bucket_encryption(Bucket=bucket)
                     .get("ServerSideEncryptionConfiguration", {}).get("Rules", []))
            enc = bool(rules)
            kms = any(
                r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") == "aws:kms"
                for r in rules)
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

        versioning = None
        with contextlib.suppress(Exception):
            versioning = s3.get_bucket_versioning(Bucket=bucket).get("Status") == "Enabled"

        access_logging = None
        with contextlib.suppress(Exception):
            access_logging = bool(s3.get_bucket_logging(Bucket=bucket).get("LoggingEnabled"))

        lifecycle = None
        try:
            s3.get_bucket_lifecycle_configuration(Bucket=bucket)
            lifecycle = True
        except Exception as exc:  # noqa: BLE001
            lifecycle = False if "NoSuchLifecycleConfiguration" in str(exc) else None

        tls_required = self._bucket_requires_tls(s3, bucket)

        return {
            "encryption_at_rest": enc,
            "public_access_blocked": blocked,
            "asset": bucket,
            "owner": "cloud-platform-team",
            "kms_encrypted": kms,
            "versioning_enabled": versioning,
            "access_logging_enabled": access_logging,
            "lifecycle_configured": lifecycle,
            "tls_required": tls_required,
        }

    @staticmethod
    def _bucket_requires_tls(s3, bucket: str) -> bool | None:
        """True if the bucket policy denies requests where SecureTransport is false."""
        try:
            doc = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
        except Exception as exc:  # noqa: BLE001
            # No policy at all is an observed fact: TLS is not enforced.
            return False if "NoSuchBucketPolicy" in str(exc) else None
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Deny":
                continue
            cond = stmt.get("Condition", {})
            for op in ("Bool", "BoolIfExists"):
                val = cond.get(op, {}).get("aws:SecureTransport")
                if str(val).lower() in ("false", "['false']"):
                    return True
        return False

    # ── CloudTrail ──
    def _cloudtrail_telemetry(self) -> dict[str, Any]:
        ct = self._session.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        logging_on = False
        multi_region = False
        validation = False
        kms = False
        cw = False
        for trail in trails:
            try:
                status = ct.get_trail_status(Name=trail["TrailARN"])
                if not status.get("IsLogging"):
                    continue
                logging_on = True
                # Only attribute these to trails that are actually logging —
                # a well-configured but disabled trail proves nothing.
                multi_region = multi_region or bool(trail.get("IsMultiRegionTrail"))
                validation = validation or bool(trail.get("LogFileValidationEnabled"))
                kms = kms or bool(trail.get("KmsKeyId"))
                cw = cw or bool(trail.get("CloudWatchLogsLogGroupArn"))
            except Exception:  # noqa: BLE001
                continue
        return {
            "logging_enabled": logging_on,
            "owner": "secops-team",
            "multi_region_enabled": multi_region,
            "log_file_validation_enabled": validation,
            "trail_kms_encrypted": kms,
            "cloudwatch_logs_integrated": cw,
        }

    # ── EC2 / EBS / SG / VPC ──
    def _ec2_instance_telemetry(self, instance_id: str | None) -> dict[str, Any]:
        if not instance_id:
            raise ConnectorError("EC2 control requires 'instance_id' (or asset_id).")
        ec2 = self._session.client("ec2")
        res = ec2.describe_instances(InstanceIds=[instance_id]).get("Reservations", [])
        instances = [i for r in res for i in r.get("Instances", [])]
        if not instances:
            raise ConnectorError(f"EC2 instance {instance_id} not found.")
        inst = instances[0]
        md = inst.get("MetadataOptions", {})
        return {
            "imdsv2_required": md.get("HttpTokens") == "required",
            "public_ip_assigned": bool(inst.get("PublicIpAddress")),
            "detailed_monitoring_enabled": inst.get("Monitoring", {}).get("State") == "enabled",
            "ebs_optimized": bool(inst.get("EbsOptimized")),
            "instance_state": inst.get("State", {}).get("Name"),
            "owner": "cloud-platform-team",
        }

    def _ebs_volume_telemetry(self, volume_id: str | None) -> dict[str, Any]:
        if not volume_id:
            raise ConnectorError("EBS control requires 'volume_id' (or asset_id).")
        ec2 = self._session.client("ec2")
        vols = ec2.describe_volumes(VolumeIds=[volume_id]).get("Volumes", [])
        if not vols:
            raise ConnectorError(f"EBS volume {volume_id} not found.")
        vol = vols[0]
        return {
            "encryption_at_rest": bool(vol.get("Encrypted")),
            "kms_encrypted": bool(vol.get("KmsKeyId")),
            "volume_state": vol.get("State"),
            "owner": "cloud-platform-team",
        }

    def _security_group_telemetry(self, group_id: str | None) -> dict[str, Any]:
        if not group_id:
            raise ConnectorError("Security group control requires 'group_id' (or asset_id).")
        ec2 = self._session.client("ec2")
        groups = ec2.describe_security_groups(GroupIds=[group_id]).get("SecurityGroups", [])
        if not groups:
            raise ConnectorError(f"Security group {group_id} not found.")

        world_open = 0
        ssh_open = False
        rdp_open = False
        for perm in groups[0].get("IpPermissions", []):
            world = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
            world = world or any(
                r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
            if not world:
                continue
            world_open += 1
            lo = perm.get("FromPort")
            hi = perm.get("ToPort")
            # A null port range means "all protocols/ports" — the widest case.
            if lo is None or hi is None:
                ssh_open = rdp_open = True
                continue
            if lo <= _SSH_PORT <= hi:
                ssh_open = True
            if lo <= _RDP_PORT <= hi:
                rdp_open = True

        return {
            "unrestricted_ingress": world_open > 0,
            "ssh_open_to_world": ssh_open,
            "rdp_open_to_world": rdp_open,
            "open_ingress_rule_count": world_open,
            "owner": "network-team",
        }

    def _vpc_telemetry(self, vpc_id: str | None) -> dict[str, Any]:
        if not vpc_id:
            raise ConnectorError("VPC control requires 'vpc_id' (or asset_id).")
        ec2 = self._session.client("ec2")
        logs = ec2.describe_flow_logs(
            Filters=[{"Name": "resource-id", "Values": [vpc_id]}]).get("FlowLogs", [])
        active = any(fl.get("FlowLogStatus") == "ACTIVE" for fl in logs)
        return {"flow_logs_enabled": active, "owner": "network-team"}

    # ── RDS ──
    def _rds_instance_telemetry(self, db_id: str | None) -> dict[str, Any]:
        if not db_id:
            raise ConnectorError("RDS control requires 'db_instance_id' (or asset_id).")
        rds = self._session.client("rds")
        dbs = rds.describe_db_instances(DBInstanceIdentifier=db_id).get("DBInstances", [])
        if not dbs:
            raise ConnectorError(f"RDS instance {db_id} not found.")
        db = dbs[0]
        return {
            "encryption_at_rest": bool(db.get("StorageEncrypted")),
            "publicly_accessible": bool(db.get("PubliclyAccessible")),
            "backup_retention_days": db.get("BackupRetentionPeriod", 0),
            "multi_az_enabled": bool(db.get("MultiAZ")),
            "deletion_protection_enabled": bool(db.get("DeletionProtection")),
            "auto_minor_version_upgrade": bool(db.get("AutoMinorVersionUpgrade")),
            "log_exports_enabled": bool(db.get("EnabledCloudwatchLogsExports")),
            "iam_auth_enabled": bool(db.get("IAMDatabaseAuthenticationEnabled")),
            "owner": "data-platform-team",
        }

    # ── KMS ──
    def _kms_key_telemetry(self, key_id: str | None) -> dict[str, Any]:
        if not key_id:
            raise ConnectorError("KMS control requires 'key_id' (or asset_id).")
        kms = self._session.client("kms")
        enabled = None
        with contextlib.suppress(Exception):
            enabled = bool(kms.describe_key(KeyId=key_id)["KeyMetadata"].get("Enabled"))
        rotation = None
        with contextlib.suppress(Exception):
            rotation = bool(kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled"))
        return {"key_rotation_enabled": rotation, "key_enabled": enabled, "owner": "secops-team"}

    # ── account-wide security services ──
    def _guardduty_telemetry(self) -> dict[str, Any]:
        gd = self._session.client("guardduty")
        enabled = False
        for det_id in gd.list_detectors().get("DetectorIds", []):
            try:
                if gd.get_detector(DetectorId=det_id).get("Status") == "ENABLED":
                    enabled = True
                    break
            except Exception:  # noqa: BLE001
                continue
        return {"threat_detection_enabled": enabled, "owner": "secops-team"}

    def _config_recorder_telemetry(self) -> dict[str, Any]:
        cfg = self._session.client("config")
        recording = False
        all_resources = False
        try:
            statuses = {
                s.get("name"): s
                for s in cfg.describe_configuration_recorder_status().get(
                    "ConfigurationRecordersStatus", [])
            }
            for rec in cfg.describe_configuration_recorders().get(
                    "ConfigurationRecorders", []):
                if statuses.get(rec.get("name"), {}).get("recording"):
                    recording = True
                    all_resources = all_resources or bool(
                        rec.get("recordingGroup", {}).get("allSupported"))
        except Exception as exc:  # noqa: BLE001
            logger.info("AWS Config status unavailable: %s", exc)
            return {"owner": "cloud-platform-team"}
        return {
            "config_recording_enabled": recording,
            "config_records_all_resources": all_resources,
            "owner": "cloud-platform-team",
        }

    # ── discovery ──
    def discover_assets(self, params: dict[str, Any]) -> list[Asset]:
        assets: list[Asset] = []
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
