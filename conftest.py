"""Shared pytest configuration.

Historically every test module set its own DATABASE_URL and re-declared a
`client` fixture, which is why test isolation was fragile. This conftest sets
the common environment defaults ONCE, before any test module imports app.main,
so behaviour is consistent no matter which file pytest loads first.

It deliberately does NOT override the per-module `client` fixtures that already
exist — those keep working unchanged. What this adds:
  - one authoritative set of test env vars (auth disabled path, scheduler off,
    deterministic signing key), applied at import time;
  - an isolated, function-scoped `fresh_db` fixture + `db_session` for new tests
    that want a clean database rather than the shared-file pattern;
  - the `-p no:randomly` default already lives in pyproject.toml.

New tests should prefer `fresh_db`/`db_session`; the legacy shared-file fixtures
remain valid so nothing needs rewriting.
"""
from __future__ import annotations

import os
import tempfile

# ── Environment defaults — set BEFORE app.main is imported anywhere ──
# setdefault so an individual module that wants a different value still wins.
_TMPDB = os.path.join(tempfile.gettempdir(), "complens_pytest.db")
os.environ.setdefault("DATABASE_URL", f"sqlite+pysqlite:///{_TMPDB}")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "test-signing-key")
os.environ.setdefault("COMP_LENS_SECRET_KEY", "test-secret-key")
# Auth: leave COMP_LENS_API_KEYS unset so the dev-mode admin principal is used
# (require_principal returns an admin principal when no keys are configured and
# APP_ENV != production), which is what the existing suite relies on.

import pytest  # noqa: E402  (must follow the env setup above)


@pytest.fixture()
def fresh_db(tmp_path, monkeypatch):
    """Function-scoped, fully isolated database on a per-test file.

    Points DATABASE_URL at a unique file, rebuilds the schema from the models,
    and yields the engine. Use for tests that must not see state from any other
    test. Note: modules that import app.main at collection time already bound
    the original engine, so this is for new tests written against it directly.
    """
    db_path = tmp_path / "isolated.db"
    url = f"sqlite+pysqlite:///{db_path}"
    monkeypatch.setenv("DATABASE_URL", url)

    from sqlalchemy import create_engine, event

    import app.models  # noqa: F401 — ensure all models are registered on Base
    from app.database import Base

    engine = create_engine(url, connect_args={"check_same_thread": False})

    # Mirror app/database.py's SQLite setup exactly, not just the transaction-
    # control half of it. Holding a real, correctly-scoped transaction open
    # (see below) means SQLite's writer lock is now actually held for the
    # transaction's full duration instead of pysqlite eagerly releasing it —
    # so without WAL mode + a busy timeout, ordinary sequential use of the
    # same engine (e.g. run_due() opening its own connection from the pool
    # while another connection from an earlier statement hasn't been
    # returned yet) starts failing with "database is locked" instead of
    # waiting the way production configures it to.
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _rec):  # noqa: ANN001
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()

    # Mirror app/database.py's pysqlite transaction-control fix: without it,
    # releasing a SAVEPOINT (db.begin_nested(), used throughout the write path
    # for idempotency-race handling) can behave like an early commit of the
    # whole transaction under pysqlite's own implicit transaction management,
    # so a later session.rollback() can't undo it. Tests against this fixture
    # need the same real transactional semantics production SQLite gets, or
    # they validate rollback behavior that doesn't actually hold.
    @event.listens_for(engine, "connect")
    def _disable_pysqlite_txn_control(dbapi_conn, _rec):  # noqa: ANN001
        dbapi_conn.isolation_level = None

    @event.listens_for(engine, "begin")
    def _explicit_begin(conn):  # noqa: ANN001
        conn.exec_driver_sql("BEGIN")

    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture()
def db_session(fresh_db):
    """A SQLAlchemy session bound to an isolated `fresh_db`."""
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=fresh_db)
    session = Session()
    try:
        yield session
    finally:
        session.close()
