"""Comp-Lens can run against a database its authors never see.

That is a promise about deployment, so the things that would quietly break it
are what this file pins:

  * **The URL your provider gave you works.** Every managed Postgres hands out
    a different spelling and none of them is the one SQLAlchemy 2.x wants. If
    normalisation regresses, the failure lands on a new operator in their first
    five minutes, as a driver import error naming a package they never chose.

  * **The two compose files do not drift.** docker-compose.byodb.yml inherits
    the app service via `extends` precisely so a credential added to the
    bundled file reaches the BYO deployment too. If someone ever copy-pastes
    the service instead, that stops being true silently, and the person who
    finds out is a self-hoster whose connector stopped working.

  * **A bad URL is diagnosed, not stack-traced.** The whole point of the
    preflight is that "I cannot reach your database" is a sentence, not an
    OperationalError.

  * **Passwords stay out of logs.** Connection failures are exactly when
    someone pastes the output into an issue.
"""
from __future__ import annotations

import pathlib
import re

import pytest

from app.db_url import POSTGRES_DRIVER, format_report, inspect, normalize, redact

ROOT = pathlib.Path(__file__).resolve().parent.parent


# ── the URL your provider actually gives you ──
@pytest.mark.parametrize(("given", "reason"), [
    ("postgres://u:pw@host:5432/db", "Heroku and Render hand out the legacy scheme"),
    ("postgresql://u:pw@ep-x.neon.tech/neondb?sslmode=require", "Neon"),
    ("postgresql://postgres:pw@db.x.supabase.co:5432/postgres", "Supabase"),
    ("postgresql://admin:pw@x.eu-west-1.rds.amazonaws.com:5432/complens", "RDS console"),
])
def test_a_provider_url_is_usable_as_pasted(given, reason):
    """None of these name a driver, so SQLAlchemy 2.x either rejects the URL
    outright or reaches for psycopg2, which is not in requirements.txt."""
    assert normalize(given).startswith(POSTGRES_DRIVER + "://"), reason


def test_an_explicit_driver_is_left_alone():
    """Overriding a driver the operator chose on purpose would be its own bug."""
    for url in (f"{POSTGRES_DRIVER}://u:p@h/d", "postgresql+asyncpg://u:p@h/d",
                "postgresql+psycopg2://u:p@h/d"):
        assert normalize(url) == url


def test_sqlite_is_untouched():
    assert normalize("sqlite:///./complens.db") == "sqlite:///./complens.db"


def test_normalizing_preserves_everything_but_the_scheme():
    """A dropped query string would silently disable TLS."""
    out = normalize("postgres://u:pw@h:5432/db?sslmode=require&application_name=cl")
    assert out.endswith("//u:pw@h:5432/db?sslmode=require&application_name=cl")


# ── refusing to start, with a reason ──
@pytest.mark.parametrize(("url", "expect"), [
    ("", "not set"),
    ("nonsense", "does not look like a URL"),
    ("mysql://u:p@h/d", "PostgreSQL"),
    ("postgresql://u:p@host:5432", "names no database"),
])
def test_a_url_that_cannot_work_is_refused_with_an_explanation(url, expect):
    ins = inspect(url, production=True)
    assert not ins.ok
    assert any(expect in e for e in ins.errors), ins.errors


def test_sqlite_is_fine_locally_and_refused_in_production():
    assert inspect("sqlite:///./x.db", production=False).ok
    prod = inspect("sqlite:///./x.db", production=True)
    assert not prod.ok
    assert "SQLite is not supported in production" in prod.errors[0]


# ── advice, not refusal ──
def test_a_remote_host_without_tls_is_flagged_but_still_starts():
    """Refusing would strand anyone on a private network where it is fine.
    Saying nothing would ship credentials in clear text. So: warn and run."""
    ins = inspect("postgresql://u:pw@db.example.com:5432/complens", production=True)
    assert ins.ok
    assert any("without requiring TLS" in w for w in ins.warnings)


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "db"])
def test_the_bundled_database_is_not_nagged_about_tls(host):
    """`db` is the compose service name — that traffic never leaves the host."""
    ins = inspect(f"postgresql://u:pw@{host}:5432/complens", production=True)
    assert not any("TLS" in w for w in ins.warnings), ins.warnings


def test_requiring_tls_silences_the_warning():
    ins = inspect("postgresql://u:pw@db.example.com/c?sslmode=require", production=True)
    assert not any("TLS" in w for w in ins.warnings)


# ── never leak the password ──
@pytest.mark.parametrize("url", [
    "postgresql://user:hunter2@host:5432/db",
    "postgres://user:hunter2@host/db?sslmode=require",
    f"{POSTGRES_DRIVER}://user:hunter2@host:5432/db",
])
def test_a_redacted_url_carries_no_password(url):
    assert "hunter2" not in redact(url)
    assert "***" in redact(url)


def test_redaction_keeps_the_query_string():
    """sslmode lives there, and it is what someone debugging TLS is looking for."""
    assert "sslmode=require" in redact("postgresql://u:pw@h/d?sslmode=require")


def test_no_report_ever_prints_a_password():
    """format_report is what reaches the container log on every boot."""
    for prod in (True, False):
        report = format_report(inspect("postgres://user:hunter2@h.example.com/db",
                                       production=prod))
        assert "hunter2" not in report


# ── the deployment files themselves ──
def _compose(name: str) -> str:
    return (ROOT / name).read_text()


def _parsed(name: str) -> dict:
    """Parse the compose file rather than grepping it.

    The first version of this test asserted `"postgres:" not in text` and
    failed on a COMMENT explaining that a 'postgres://' URL is accepted. Prose
    about the configuration is not the configuration, and a test that cannot
    tell them apart blocks the next person for no reason.
    """
    import yaml
    return yaml.safe_load(_compose(name)) or {}


def test_the_byo_compose_file_starts_no_database():
    """The whole point: no Postgres image, no volume holding customer data."""
    doc = _parsed("docker-compose.byodb.yml")
    services = doc.get("services", {})
    assert "db" not in services, "a database service would defeat the purpose"
    images = [s.get("image", "") for s in services.values() if isinstance(s, dict)]
    assert not any("postgres" in i for i in images), images
    assert "complens_pgdata" not in (doc.get("volumes") or {}), (
        "no volume in this deployment should hold their data")


def test_the_byo_compose_file_inherits_rather_than_copies_the_app():
    """Copying would drift: a credential added to the bundled file would not
    reach BYO deployments, and nobody would notice until a connector broke."""
    byo = _compose("docker-compose.byodb.yml")
    assert "extends:" in byo
    assert "file: docker-compose.yml" in byo
    assert "service: app" in byo
    # A copied service would carry these; an inherited one must not.
    for copied in ("OKTA_API_TOKEN", "AWS_SECRET_ACCESS_KEY", "build:"):
        assert copied not in byo, (
            f"{copied} appears in the BYO file, so the app service was copied "
            "rather than inherited — the two files will drift")


def test_the_byo_compose_file_demands_a_database_url():
    """With no bundled database to fall back on, an unset URL has to stop the
    stack with a sentence rather than start it against nothing."""
    byo = _compose("docker-compose.byodb.yml")
    assert re.search(r"DATABASE_URL:\s*\$\{DATABASE_URL:\?", byo), (
        "DATABASE_URL must use the ${VAR:?message} form so compose refuses to "
        "start and says why")


def test_the_bundled_file_still_defaults_to_its_own_database():
    """Existing self-hosters run `git pull && docker compose up -d`. That has
    to keep working with no .env change."""
    bundled = _compose("docker-compose.yml")
    assert "postgres:16-alpine" in bundled
    assert "DATABASE_URL:" in bundled
    assert "@db:5432/" in bundled, "the bundled default must survive"
    assert "${DATABASE_URL:-" in bundled, (
        "but DATABASE_URL should still be overridable from .env")


def test_the_container_verifies_the_database_before_migrating():
    """Without this, a misconfigured URL surfaces as an alembic traceback."""
    dockerfile = (ROOT / "Dockerfile").read_text()
    cmd = [ln for ln in dockerfile.splitlines() if ln.startswith("CMD")]
    assert cmd, "Dockerfile has no CMD"
    assert "app.dbcheck" in cmd[0]
    assert cmd[0].index("app.dbcheck") < cmd[0].index("alembic"), (
        "the check has to run BEFORE migrations, or it explains nothing")


def test_the_env_template_documents_both_options():
    env = (ROOT / ".env.example").read_text()
    assert "DATABASE_URL" in env
    assert "docker-compose.byodb.yml" in env
    assert "sslmode=require" in env, "TLS guidance belongs where the URL is set"


# ── the preflight's own behaviour ──
def test_the_preflight_refuses_a_bad_url_without_retrying():
    """Waiting cannot turn a missing DATABASE_URL into a good one, and a
    60-second pause before a config error is just a worse config error."""
    import app.dbcheck as dbcheck

    calls = []
    original = dbcheck.probe
    dbcheck.probe = lambda *a, **k: (calls.append(1), (False, RuntimeError("x")))[1]
    original_url = dbcheck.settings.database_url
    try:
        dbcheck.settings.database_url = "mysql://u:p@h/d"
        assert dbcheck.main(["--wait", "300", "--quiet"]) == 2
        assert not calls, "a URL that cannot work must not be dialled at all"
    finally:
        dbcheck.probe = original
        dbcheck.settings.database_url = original_url


def test_migrations_resolve_the_url_through_config_not_the_raw_environment():
    """`alembic upgrade head` runs BEFORE the app, in its own process.

    If env.py read os.environ["DATABASE_URL"] directly it would miss the
    driver normalisation and fail on exactly the pasted-from-provider URLs
    this feature exists to accept — and it would fail first, so the app's
    friendlier diagnosis would never be reached.
    """
    env_py = (ROOT / "alembic" / "env.py").read_text()
    assert "from app.config import settings" in env_py
    assert "settings.database_url" in env_py
    assert 'environ["DATABASE_URL"]' not in env_py
    assert "environ.get(\"DATABASE_URL\"" not in env_py


@pytest.mark.parametrize(("error_text", "expect"), [
    ("could not translate host name \"nope\"", "does not resolve"),
    ("connection refused", "nothing accepted"),
    ("timeout expired", "firewall"),
    ("no pg_hba.conf entry for host", "pg_hba.conf"),
    ("password authentication failed for user", "percent-encoded"),
])
def test_a_connection_failure_is_translated_into_an_action(error_text, expect):
    """psycopg's message says what happened; these say what to do about it."""
    from app.dbcheck import _hint_for

    hint = _hint_for(RuntimeError(error_text))
    assert hint and expect in hint, f"no useful hint for {error_text!r}"
