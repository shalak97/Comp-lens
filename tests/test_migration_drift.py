"""The schema production runs must be the schema the code was written against.

Two different things build this database. Alembic builds it in production, one
migration at a time. `Base.metadata.create_all()` builds it in the test suite,
straight from the model classes. Nothing compared them.

That gap is invisible exactly until it matters. Add a column to a model and
forget the migration: every test still passes, because `create_all` reads the
model. The first query in production hits a table that does not have the
column. CI already runs `alembic upgrade head`, but that only proves the
migrations execute — it says nothing about whether they arrive at the same
place the models describe.

The comparison is deliberately one-sided. A table or column the models expect
and the migrations do not create is a fault: the running code will query
something that is not there. The reverse — a migration leaving behind a table
or column no model mentions any more — is untidy but harmless, so it is
reported in the failure message rather than being a failure of its own.
"""
from __future__ import annotations

import pathlib

import pytest

pytest.importorskip("alembic")

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Every module that defines tables. alembic/env.py imports only app.models,
#: so anything here that a migration does not create simply will not exist in
#: production, however complete the model looks.
MODEL_MODULES = (
    "app.models",
    "app.audit_models",
    "app.crawler_models",
    "app.policy_models",
    "app.ai_governance_models",
    "app.grc_tprm_models",
)


def _model_schema() -> dict[str, set[str]]:
    import importlib

    from app.database import Base

    for mod in MODEL_MODULES:
        importlib.import_module(mod)
    return {name: {c.name for c in table.columns}
            for name, table in Base.metadata.tables.items()}


def _migrated_schema(tmp_path) -> dict[str, set[str]]:
    """Build a database the way production does, and read back what exists."""
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    from alembic import command
    from app.config import settings

    db = tmp_path / "migrated.db"
    url = f"sqlite+pysqlite:///{db}"

    # alembic/env.py reads settings.database_url directly rather than the ini
    # option, so pointing it at a scratch database means setting that.
    original = settings.database_url
    try:
        settings.database_url = url
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.set_main_option("script_location", str(ROOT / "alembic"))
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "head")
    finally:
        settings.database_url = original

    engine = create_engine(url)
    try:
        insp = inspect(engine)
        return {t: {c["name"] for c in insp.get_columns(t)}
                for t in insp.get_table_names() if t != "alembic_version"}
    finally:
        engine.dispose()


@pytest.fixture(scope="module")
def schemas(tmp_path_factory):
    return _model_schema(), _migrated_schema(tmp_path_factory.mktemp("drift"))


def test_migrations_create_every_table_the_models_declare(schemas):
    """A table the code queries but production never built.

    This is the failure that only ever happens to a customer: the suite is
    green because create_all read the same model the query did.
    """
    models, migrated = schemas
    missing = sorted(set(models) - set(migrated))
    extra = sorted(set(migrated) - set(models))
    assert not missing, (
        f"tables declared by models but never created by a migration: {missing}"
        + (f" (migrations also have unused tables: {extra})" if extra else ""))


def test_migrations_create_every_column_the_models_declare(schemas):
    models, migrated = schemas
    gaps = {}
    for table in sorted(set(models) & set(migrated)):
        missing = sorted(models[table] - migrated[table])
        if missing:
            gaps[table] = missing
    assert not gaps, f"columns declared by models but missing from the migrated schema: {gaps}"


def test_the_migrated_schema_is_not_empty(schemas):
    """A self-check: if the migration run silently did nothing, the two tests
    above would compare against an empty schema and could pass vacuously in a
    future refactor. This fails first and points at the right thing."""
    _, migrated = schemas
    assert len(migrated) >= 10, f"migrations produced only {len(migrated)} tables"
