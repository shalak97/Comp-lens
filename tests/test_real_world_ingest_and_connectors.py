"""Real-world scenario tests: messy inputs from real scanners and real clouds.

Two things reliably go wrong in production for a platform like this:

  1. The cloud account it is pointed at has narrower IAM permissions than the
     connector expects, so some signals simply cannot be read.
  2. The security tool feeding it emits a document that is valid JSON but not
     quite the shape the spec describes — a truncated export, a tool-specific
     dialect, an empty run.

Neither should produce a wrong compliance answer, and neither should 500.
"""
from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_rw_ing.db")
os.environ.setdefault("EVIDENCE_LOCAL_PATH", "./test_rw_ing_evidence")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import init_db  # noqa: E402


@pytest.fixture(scope="module")
def client():
    init_db()
    from app.main import app
    with TestClient(app) as c:
        yield c


# ──────────────────────────────────────────────────────────────────────────
# Scenario: the connector's IAM role is narrower than the probe assumes
# ──────────────────────────────────────────────────────────────────────────
def test_unreadable_signal_is_not_applicable_never_a_failure():
    """A permission gap must read as "unobserved", never as a violation.

    This is the guarantee that keeps the tool honest: reporting
    "we could not check your password policy" as "your password policy is
    non-compliant" would put a fabricated finding in front of an auditor.
    """
    from app.models import ControlStatus
    from app.services import control_checks

    check = control_checks.get("IA-5-PW-LENGTH")
    assert check is not None

    # AccessDenied on GetAccountPasswordPolicy -> the signal is absent
    status, reason, _ = control_checks.evaluate(check, {"owner": "identity-team"})
    assert status is ControlStatus.NOT_APPLICABLE
    assert "unavailable" in reason.lower()


def test_partially_readable_probe_still_answers_what_it_can():
    """One unreadable signal must not poison the checks that only need the
    signals that *were* readable."""
    from app.models import ControlStatus
    from app.services import control_checks

    # A real partial read: root MFA visible, password policy denied.
    telemetry = {"root_mfa_enabled": True, "root_access_keys_present": False}

    root_mfa = control_checks.get("IA-2-ROOT-MFA")
    pw_len = control_checks.get("IA-5-PW-LENGTH")

    assert control_checks.evaluate(root_mfa, telemetry)[0] is ControlStatus.PASS
    assert control_checks.evaluate(pw_len, telemetry)[0] is ControlStatus.NOT_APPLICABLE


def test_a_false_signal_is_a_real_failure_not_a_missing_one():
    """The mirror of the above: False must stay a genuine violation, or the
    fail-safe would swallow every real finding."""
    from app.models import ControlStatus
    from app.services import control_checks

    check = control_checks.get("IA-2-ROOT-MFA")
    status, _, _ = control_checks.evaluate(check, {"root_mfa_enabled": False})
    assert status is ControlStatus.FAIL


def test_zero_is_a_real_reading_not_a_missing_signal():
    """0 is falsy in Python but is a legitimate observation — a password policy
    minimum length of 0 means "no policy", which is a failure, not an unknown."""
    from app.models import ControlStatus
    from app.services import control_checks

    check = control_checks.get("IA-5-PW-LENGTH")
    status, _, _ = control_checks.evaluate(check, {"password_min_length": 0})
    assert status is ControlStatus.FAIL, (
        "a zero reading was treated as an absent signal; a missing password "
        "policy would silently disappear from the report")


def test_false_is_a_real_reading_not_a_missing_signal():
    from app.models import ControlStatus
    from app.services import control_checks

    check = control_checks.get("AC-6-NO-DIRECT-ADMIN")
    # has_admin_policy=True is the violating case; False is compliant.
    assert control_checks.evaluate(check, {"has_admin_policy": False})[0] is ControlStatus.PASS
    assert control_checks.evaluate(check, {"has_admin_policy": True})[0] is ControlStatus.FAIL


# ──────────────────────────────────────────────────────────────────────────
# Scenario: a real scanner emits a document that isn't textbook-shaped
# ──────────────────────────────────────────────────────────────────────────
def test_unknown_format_is_a_client_error(client):
    r = client.post("/v1/evidence/ingest?format=notareal&tenant_id=ing",
                    json={"anything": 1})
    assert r.status_code == 400


@pytest.mark.parametrize("fmt,doc", [
    # An empty-but-valid document from a scan that found nothing.
    ("sarif", {"version": "2.1.0", "runs": []}),
    ("cyclonedx", {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}),
    ("spdx", {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "empty"}),
    ("stix", {"type": "bundle", "id": "bundle--x", "spec_version": "2.1", "objects": []}),
    ("ocsf", {}),
])
def test_empty_but_valid_documents_ingest_cleanly(client, fmt, doc):
    """A clean scan is the most common real result. It must report zero
    findings, not fail the upload."""
    r = client.post(f"/v1/evidence/ingest?format={fmt}&tenant_id=ing-empty", json=doc)
    assert r.status_code == 200, f"{fmt} empty document failed: {r.text}"
    assert r.json()["ingested"] == 0


@pytest.mark.parametrize("fmt,doc", [
    # Structurally wrong in ways real exports actually are: wrong types for
    # container fields, missing required children, nulls where objects go.
    ("sarif", {"version": "2.1.0", "runs": "not-a-list"}),
    ("sarif", {"version": "2.1.0", "runs": [{"results": None}]}),
    ("cyclonedx", {"bomFormat": "CycloneDX", "vulnerabilities": "nope"}),
    ("cyclonedx", {"bomFormat": "CycloneDX", "vulnerabilities": [None]}),
    ("spdx", {"spdxVersion": "SPDX-2.3", "packages": {"not": "a list"}}),
    ("stix", {"type": "bundle", "objects": [{"type": "vulnerability"}]}),
    ("intoto", {"_type": "https://in-toto.io/Statement/v1", "subject": "wrong"}),
    ("ocsf", {"metadata": None, "compliance": "not-an-object"}),
])
def test_malformed_documents_do_not_500(client, fmt, doc):
    """A malformed upload is the user's mistake and should be reported as such.

    A 500 tells the operator nothing actionable, and — because the endpoint
    catches every exception into a generic server error — hides which part of
    their document was wrong.
    """
    r = client.post(f"/v1/evidence/ingest?format={fmt}&tenant_id=ing-bad", json=doc)
    assert r.status_code != 500, (
        f"malformed {fmt} document produced a server error instead of a "
        f"client error: {r.text}")
    assert r.status_code in (200, 400, 422), f"unexpected status {r.status_code}: {r.text}"


def test_ingest_is_tenant_scoped(client):
    """Evidence ingested for one tenant must not appear in another's findings."""
    sarif = {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": [
            {"id": "py/sql-injection", "shortDescription": {"text": "SQL injection"},
             "properties": {"security-severity": "9.8", "tags": ["security", "cwe-89"]}}]}},
        "results": [{"ruleId": "py/sql-injection", "level": "error",
                     "message": {"text": "User input flows to a SQL query."},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": "app/db.py"},
                         "region": {"startLine": 42}}}]}]}]}

    r = client.post("/v1/evidence/ingest?format=sarif&tenant_id=ing-owner", json=sarif)
    assert r.status_code == 200, r.text

    other = client.get("/findings?tenant_id=ing-stranger").json()
    assert other == []
