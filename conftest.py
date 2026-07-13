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

    from sqlalchemy import create_engine

    import app.models  # noqa: F401 — ensure all models are registered on Base
    from app.database import Base

    engine = create_engine(url, connect_args={"check_same_thread": False})
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
