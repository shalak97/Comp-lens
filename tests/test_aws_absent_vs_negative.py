"""An AWS call we were not allowed to make is not a control failure.

AWS answers "this bucket has no encryption configuration" with an error, and
answers "you may not ask" with a different error. Three signals in the S3 and
CloudTrail paths treated both the same way and defaulted to False, which the
check engine reads as an observed negative:

    encryption_at_rest     -> SC-28-OBJSTORE / -BLOCKSTORE / -DATABASE   (high)
    public_access_blocked  -> AC-3-OBJSTORE-PUBLIC                   (CRITICAL)
    logging_enabled        -> AU-2-ACCOUNT-LOGGING                   (CRITICAL)

So an IAM role missing s3:GetEncryptionConfiguration,
s3:GetBucketPublicAccessBlock or cloudtrail:GetTrailStatus — ordinary
under-provisioning, not an attack — reported the whole estate as unencrypted,
publicly readable and unaudited. Fabricated critical violations in a product
whose output is meant to be evidence.

This is the mirror of the defect the rest of this codebase keeps hitting.
Elsewhere absence was read as compliance; here it was read as breach. Both
claim more than the evidence supports, and both are fixed the same way: say
"we could not observe this" and let the engine render NOT_APPLICABLE.

The module already knew the distinction — `console_access`, `lifecycle` and
`_bucket_requires_tls` each check for their specific "not configured" error
and return None otherwise, and one of them carries a comment explaining
exactly why. Three signals in the same file had simply not been written that
way.

boto3 is not exercised here: the telemetry methods are driven against fake
clients that raise the two kinds of error, which is the distinction under test.
"""
from __future__ import annotations

import ast
import contextlib
import json
import logging
import pathlib
import textwrap

import pytest

AWS_SRC = pathlib.Path(__file__).resolve().parent.parent / "app" / "connectors" / "aws.py"
PACK = pathlib.Path(__file__).resolve().parent.parent / "app" / "data" / "control_checks.json"


def _load():
    """Lift the telemetry methods out of the class so they can run without boto3."""
    src = AWS_SRC.read_text()
    tree = ast.parse(src)
    ns: dict = {"contextlib": contextlib, "json": json,
                "logger": logging.getLogger("test.aws")}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "_absent":
            exec(ast.get_source_segment(src, node), ns)  # noqa: S102
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef))
    for node in cls.body:
        if isinstance(node, ast.FunctionDef) and node.name in (
                "_s3_bucket_telemetry", "_cloudtrail_telemetry", "_bucket_requires_tls"):
            code = textwrap.dedent(ast.get_source_segment(src, node)).replace("@staticmethod\n", "")
            exec(code, ns)  # noqa: S102
    return ns


NS = _load()


class _AwsError(Exception):
    pass


class _FakeS3:
    """`mode` selects which kind of failure the account produces."""

    def __init__(self, mode):
        self.mode = mode

    def get_bucket_encryption(self, Bucket):  # noqa: N803 — boto3's own casing
        if self.mode == "denied":
            raise _AwsError("AccessDenied: not authorized for s3:GetEncryptionConfiguration")
        if self.mode == "unset":
            raise _AwsError("ServerSideEncryptionConfigurationNotFoundError")
        return {"ServerSideEncryptionConfiguration": {"Rules": [
            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}}

    def get_public_access_block(self, Bucket):  # noqa: N803
        if self.mode == "denied":
            raise _AwsError("AccessDenied: s3:GetBucketPublicAccessBlock")
        if self.mode == "unset":
            raise _AwsError("NoSuchPublicAccessBlockConfiguration")
        return {"PublicAccessBlockConfiguration": dict.fromkeys(("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), True)}

    def get_bucket_versioning(self, Bucket):  # noqa: N803
        return {"Status": "Enabled"}

    def get_bucket_logging(self, Bucket):  # noqa: N803
        return {"LoggingEnabled": {}}

    def get_bucket_lifecycle_configuration(self, Bucket):  # noqa: N803
        return {}

    def get_bucket_policy(self, Bucket):  # noqa: N803
        raise _AwsError("NoSuchBucketPolicy")


class _FakeCT:
    def __init__(self, mode):
        self.mode = mode

    def describe_trails(self):
        if self.mode == "no-trails":
            return {"trailList": []}
        return {"trailList": [{"TrailARN": "arn:1", "Name": "t1", "IsMultiRegionTrail": True,
                               "LogFileValidationEnabled": True, "KmsKeyId": "k",
                               "CloudWatchLogsLogGroupArn": "lg"}]}

    def get_trail_status(self, Name):  # noqa: N803
        if self.mode == "denied":
            raise _AwsError("AccessDenied: cloudtrail:GetTrailStatus")
        return {"IsLogging": self.mode != "off"}


class _Conn:
    def __init__(self, client):
        self._session = type("S", (), {"client": lambda _s, _n: client})()

    _bucket_requires_tls = staticmethod(NS["_bucket_requires_tls"])
    _s3_bucket_telemetry = NS["_s3_bucket_telemetry"]
    _cloudtrail_telemetry = NS["_cloudtrail_telemetry"]


# ── the distinction itself ──
@pytest.mark.parametrize("signal", ["encryption_at_rest", "kms_encrypted",
                                    "public_access_blocked"])
def test_a_denied_s3_read_reports_nothing_rather_than_a_breach(signal):
    """The regression. Any failure used to mean False, so a permissions gap
    announced every bucket as unencrypted and publicly readable."""
    telemetry = _Conn(_FakeS3("denied"))._s3_bucket_telemetry("b1")
    assert telemetry[signal] is None, (
        f"{signal} is {telemetry[signal]!r} after a denied read — that is an "
        f"assertion about the bucket we have no evidence for")


@pytest.mark.parametrize("signal", ["encryption_at_rest", "kms_encrypted",
                                    "public_access_blocked"])
def test_a_genuinely_unconfigured_bucket_is_still_a_finding(signal):
    """The other half, and the one a lazy fix would break: AWS reports 'no
    configuration exists' as an error too, and that IS an observed failure."""
    telemetry = _Conn(_FakeS3("unset"))._s3_bucket_telemetry("b1")
    assert telemetry[signal] is False


@pytest.mark.parametrize("signal", ["encryption_at_rest", "kms_encrypted",
                                    "public_access_blocked"])
def test_a_configured_bucket_still_passes(signal):
    assert _Conn(_FakeS3("ok"))._s3_bucket_telemetry("b1")[signal] is True


def test_a_denied_trail_status_reports_nothing_about_logging():
    """AU-2-ACCOUNT-LOGGING is CRITICAL and reads `logging_enabled == true`.
    Skipping an unreadable trail left the False default in place, so the
    control failed on evidence that was never collected."""
    telemetry = _Conn(_FakeCT("denied"))._cloudtrail_telemetry()
    for signal in ("logging_enabled", "multi_region_enabled",
                   "log_file_validation_enabled", "trail_kms_encrypted",
                   "cloudwatch_logs_integrated"):
        assert signal not in telemetry, (
            f"{signal} was reported despite no trail being readable")


def test_an_account_with_no_trails_at_all_is_still_a_finding():
    """The distinction that matters: no trails is an observation. Trails we
    cannot read is not. A fix that returned None for both would hide the real
    failure this control exists to catch."""
    telemetry = _Conn(_FakeCT("no-trails"))._cloudtrail_telemetry()
    assert telemetry["logging_enabled"] is False


def test_a_trail_that_exists_but_is_switched_off_is_a_finding():
    assert _Conn(_FakeCT("off"))._cloudtrail_telemetry()["logging_enabled"] is False


def test_a_logging_trail_passes_and_carries_its_attributes():
    telemetry = _Conn(_FakeCT("on"))._cloudtrail_telemetry()
    assert telemetry["logging_enabled"] is True
    assert telemetry["multi_region_enabled"] is True
    assert telemetry["log_file_validation_enabled"] is True


# ── the helper, and the reason it exists ──
def test_absent_discriminates_on_the_named_code():
    absent = NS["_absent"]
    assert absent(_AwsError("NoSuchBucketPolicy: none"), "NoSuchBucketPolicy") is False
    assert absent(_AwsError("AccessDenied"), "NoSuchBucketPolicy") is None
    assert absent(_AwsError("ThrottlingException"), "NoSuchBucketPolicy") is None


def test_the_signals_these_feed_are_the_ones_worth_protecting():
    """Documents the blast radius, and fails if the pack stops reading them —
    at which point this test would be guarding nothing."""
    checks = json.loads(PACK.read_text())["checks"]
    by_signal: dict[str, list[str]] = {}
    for c in checks:
        for s in c.get("requires", []):
            by_signal.setdefault(s, []).append(c["control_id"])
    assert "AC-3-OBJSTORE-PUBLIC" in by_signal.get("public_access_blocked", [])
    assert "AU-2-ACCOUNT-LOGGING" in by_signal.get("logging_enabled", [])
    assert len(by_signal.get("encryption_at_rest", [])) >= 3


def test_no_connector_asserts_a_negative_from_a_failure():
    """The class, not just these instances: an except handler that assigns a
    bare False is turning "the call failed" into "we looked and it is off"."""
    offenders = []
    for path in (AWS_SRC.parent).rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            for stmt in ast.walk(node):
                if (isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Constant)
                        and stmt.value.value in (False, 0)):
                    names = ", ".join(ast.unparse(t) for t in stmt.targets)
                    offenders.append(f"{path.name}:{stmt.lineno} {names} = {stmt.value.value!r}")
    assert not offenders, (
        "a connector turns a failed call into an observed negative; return None "
        f"so the control reports NOT_APPLICABLE instead: {offenders}")
