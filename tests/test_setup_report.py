"""The setup report tells you what is connected. It must never tell you a secret.

Someone who has just cloned the repo gets a dashboard full of demo data and no
way to tell what is real. `GET /setup` is the answer: for each thing the
platform can be connected to — database, evidence storage, auth, every
connector — is it configured, what would configure it, and what happens if it
is left alone.

That report is only useful if it can be read on the screen of whoever is doing
the setup, which makes one property non-negotiable: **credentials are reported
as set/not-set against the environment variable's NAME, and no value is ever
returned.** A screenshot of this page in a support thread must not be a
credential leak. Most of this file is that one property, checked from several
directions, because it is the kind of thing a well-meaning "why not show the
first 4 characters" change would quietly undo.

The rest pins the reasoning that was wrong on the first pass: one connector
implementation backs several catalog entries and they do NOT declare the same
variables, so reporting the first entry found understated the requirement and
called AWS configured one variable early.
"""
from __future__ import annotations

import json

import pytest

from app.services import setup_status

#: Values that must never appear in a report, whatever the environment holds.
SECRETS = {
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
    "OKTA_API_TOKEN": "00xSuperSecretOktaToken",
    "GITHUB_TOKEN": "ghp_averyrealisticlookingtoken1234",
    "COMP_LENS_API_KEYS": "adminkey-that-is-secret:*",
    "EVIDENCE_SIGNING_KEY": "cafebabecafebabecafebabecafebabe",
}


@pytest.fixture
def loaded_env(monkeypatch):
    for name, value in SECRETS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("OKTA_ORG_URL", "https://example.okta.com")
    return SECRETS


# ── the property that matters ──
def test_no_credential_value_ever_reaches_the_report(loaded_env):
    """The whole report, serialised, must not contain any secret it can see."""
    blob = json.dumps(setup_status.report())
    leaked = [name for name, value in loaded_env.items() if value in blob]
    assert not leaked, (
        f"the setup report leaked the VALUE of {leaked}. It may only ever "
        "report whether a variable is set, keyed by its name.")


def test_the_database_password_is_not_in_the_report(monkeypatch):
    """DATABASE_URL carries its password inline, so the item describing the
    database is the easiest place to leak one by accident."""
    monkeypatch.setattr(setup_status.settings, "database_url",
                        "postgresql+psycopg://u:hunter2@db.example.com:5432/complens")
    blob = json.dumps(setup_status.report())
    assert "hunter2" not in blob


def test_env_flags_are_booleans_not_values(loaded_env):
    """A string here would be a value; the type is the guarantee."""
    report = setup_status.report()
    for item in [*report["platform"], *report["connectors"]]:
        for name, flag in item["env"].items():
            assert isinstance(flag, bool), f"{item['key']}.{name} is {flag!r}, not a bool"


def test_a_configured_connector_is_reported_as_set_without_saying_what(loaded_env):
    okta = next(c for c in setup_status.connectors() if c["key"] == "OKTA")
    assert okta["env"]["OKTA_API_TOKEN"] is True
    assert SECRETS["OKTA_API_TOKEN"] not in json.dumps(okta)


# ── the reasoning that was wrong first time ──
def test_a_connector_requires_the_union_of_every_catalog_entry(monkeypatch):
    """AWS_IAM, AWS_CONFIG and AWS_SECURITY_HUB all resolve to the same
    implementation and declare DIFFERENT variables — AWS_CONFIG also needs
    AWS_REGION. Reporting the first entry found understated the requirement
    and would call AWS ready while a sync still failed."""
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(name, "x")
    monkeypatch.delenv("AWS_REGION", raising=False)

    aws = next(c for c in setup_status.connectors() if c["key"] == "AWS")
    assert "AWS_REGION" in aws["env"], (
        "AWS_REGION is declared by AWS_CONFIG and missing from the report, so "
        "the requirement was taken from one catalog entry instead of all of them")
    assert aws["env"]["AWS_REGION"] is False
    assert aws["state"] != setup_status.READY
    assert "AWS_REGION" in aws["fix"]


def test_each_implementation_appears_once(loaded_env):
    keys = [c["key"] for c in setup_status.connectors()]
    assert len(keys) == len(set(keys)), f"duplicate connector rows: {keys}"


# ── states mean what they say ──
def test_credentials_without_an_allowlist_entry_is_not_ready(monkeypatch):
    """The fail-closed default: credentials alone do not make live calls
    happen, and calling that state 'ready' would send someone hunting for a
    problem that is really an unset allowlist."""
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    monkeypatch.setenv("GITHUB_ORG", "x")
    monkeypatch.setattr(setup_status, "connectors", setup_status.connectors)
    from app.connectors import safety

    monkeypatch.setattr(safety, "safety_state",
                        lambda: {"live_enabled": True, "allowlist": []})
    github = next((c for c in setup_status.connectors() if c["key"] == "GITHUB"), None)
    if github and all(github["env"].values()):
        assert github["state"] == setup_status.ATTENTION
        assert "allowlist" in github["fix"].lower()


def test_an_unconfigured_connector_is_optional_not_broken(monkeypatch):
    """Not connecting Jira is a choice, not a fault. Reporting it as blocking
    would bury the things that genuinely are."""
    for var in ("JIRA_URL", "JIRA_EMAIL", "JIRA_API_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    jira = next((c for c in setup_status.connectors() if c["key"] == "JIRA"), None)
    if jira:
        assert jira["state"] == setup_status.OPTIONAL


def test_ephemeral_evidence_is_flagged_rather_than_called_ready(monkeypatch):
    """A deployment writing evidence to /tmp is working exactly as configured
    and losing data on every deploy. Silence there is what let it run for
    weeks."""
    monkeypatch.setattr(setup_status.settings, "evidence_backend", "local")
    monkeypatch.setattr(setup_status.settings, "evidence_local_path", "/tmp/evidence_store")
    item = setup_status._evidence()
    assert item["state"] == setup_status.ATTENTION
    assert item["durable"] is False
    assert "wipe" in item["detail"] or "restart" in item["detail"]


def test_object_storage_is_reported_durable(monkeypatch):
    monkeypatch.setattr(setup_status.settings, "evidence_backend", "s3")
    monkeypatch.setattr(setup_status.settings, "evidence_s3_bucket", "my-bucket")
    monkeypatch.setattr(setup_status.settings, "evidence_s3_endpoint", None)
    item = setup_status._evidence()
    assert item["state"] == setup_status.READY
    assert item["durable"] is True


def test_s3_without_a_bucket_is_blocking(monkeypatch):
    """That combination makes the app refuse to start, so it is not a warning."""
    monkeypatch.setattr(setup_status.settings, "evidence_backend", "s3")
    monkeypatch.setattr(setup_status.settings, "evidence_s3_bucket", None)
    assert setup_status._evidence()["state"] == setup_status.BLOCKED


def test_open_auth_is_blocking_in_production_only(monkeypatch):
    """No API keys on a laptop is convenience; on a public address it is an
    open compliance database."""
    monkeypatch.delenv("COMP_LENS_API_KEYS", raising=False)
    monkeypatch.setattr(setup_status.settings, "is_production", True)
    assert setup_status._auth()["state"] == setup_status.BLOCKED
    monkeypatch.setattr(setup_status.settings, "is_production", False)
    assert setup_status._auth()["state"] == setup_status.ATTENTION


# ── the report as a whole ──
def test_every_item_that_is_not_ready_says_what_to_do(loaded_env):
    report = setup_status.report()
    silent = [i["key"] for i in [*report["platform"], *report["connectors"]]
              if i["state"] != setup_status.READY and not i["fix"].strip()]
    assert not silent, f"these report a problem with no remedy: {silent}"


def test_blocking_items_sort_first(monkeypatch):
    """Whoever opens this page should see what stops it working, first."""
    monkeypatch.setattr(setup_status.settings, "evidence_backend", "s3")
    monkeypatch.setattr(setup_status.settings, "evidence_s3_bucket", None)
    states = [i["state"] for i in setup_status.report()["platform"]]
    assert states[0] == setup_status.BLOCKED


def test_the_summary_is_honest_when_nothing_is_connected(monkeypatch):
    from app.connectors import safety

    monkeypatch.setattr(safety, "safety_state",
                        lambda: {"live_enabled": False, "allowlist": []})
    assert "demo data" in setup_status.report()["summary"]
