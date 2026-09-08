"""The migrations must build the schema the models describe.

Iteration 7 of a fault-finding sweep, instrument: schema and migration
integrity. The finding is not a defect in the schema — it is a hole in the net
that would let one through without anybody noticing.

Today CI does this:

    alembic upgrade head        # proves the migrations RUN
    pytest                      # conftest builds its own schema with
                                # Base.metadata.create_all()

So the migrations are exercised, and the models are exercised, and **nothing
compares them**. Every test runs against the schema the models describe;
production runs against the schema the migrations built. A column added to a
model without a migration passes the entire suite and fails on the first
request after deploy — the failure mode that never appears in CI, only in the
thing CI was supposed to protect.

Checked at the time of writing: 31 model tables, 334 model columns, and zero
drift in either direction. This file exists so that stays true. It is the same
move as the signal registry and the absence-of-evidence detectors: check the
shape, so the next instance cannot arrive quietly.

If this test fails, the fix is almost always to write the missing migration —
not to relax the test. `alembic revision --autogenerate` will draft it from the
difference, and the message will name the tables and columns involved.
"""
from __future__ import annotations

import pathlib

import pytest
from sqlalchemy import create_engine, inspect

from app.database import Base

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Alembic's own bookkeeping, which no model declares and none should.
ALEMBIC_TABLES = {"alembic_version"}


@pytest.fixture(scope="module")
def migrated_schema(tmp_path_factory):
    """Every table and column `alembic upgrade head` actually produces."""
    alembic_config = pytest.importorskip("alembic.config")
    alembic_command = pytest.importorskip("alembic.command")

    from app.config import settings

    db_path = tmp_path_factory.mktemp("migrated") / "schema.db"
    url = f"sqlite:///{db_path}"

    cfg = alembic_config.Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)

    # env.py does `config.set_main_option("sqlalchemy.url",
    # settings.database_url)`, which overrides whatever is set above — so
    # without this the migrations run against the CI database and this
    # temporary one stays empty, making every table look unmigrated. The
    # settings object is the only lever env.py actually reads.
    original = settings.database_url
    settings.database_url = url
    try:
        alembic_command.upgrade(cfg, "head")
    finally:
        settings.database_url = original

    engine = create_engine(url)
    try:
        insp = inspect(engine)
        return {t: {c["name"] for c in insp.get_columns(t)}
                for t in insp.get_table_names() if t not in ALEMBIC_TABLES}
    finally:
        engine.dispose()


@pytest.fixture(scope="module")
def model_schema():
    """Every table and column the ORM models declare.

    Base.metadata is only as complete as what has been imported, which is the
    same trap alembic/env.py fell into: app.models pulls in four of the model
    modules transitively but not crawler_models or policy_models, so anything
    reading Base.metadata after importing only app.models is missing three
    tables and will report them as orphans that ought to be dropped.
    """
    import app.crawler_models  # noqa: F401
    import app.models  # noqa: F401
    import app.policy_models  # noqa: F401
    return {name: {c.name for c in table.columns}
            for name, table in Base.metadata.tables.items()}


def test_every_model_table_is_built_by_a_migration(model_schema, migrated_schema):
    """A table with no migration exists in every test and in no deployment."""
    missing = sorted(set(model_schema) - set(migrated_schema))
    assert not missing, (
        "these tables are declared by a model but no migration creates them, "
        "so they exist in the test database and not in production: "
        f"{missing}")


def test_every_model_column_is_built_by_a_migration(model_schema, migrated_schema):
    """The common shape: a column added to a model, the migration forgotten.
    Every test passes; the first query after deploy raises."""
    drift = {}
    for table, columns in model_schema.items():
        if table not in migrated_schema:
            continue
        missing = sorted(columns - migrated_schema[table])
        if missing:
            drift[table] = missing
    assert not drift, (
        "model columns with no migration — these will be missing in "
        f"production: {drift}")


def test_no_migration_builds_something_the_models_abandoned(model_schema, migrated_schema):
    """The other direction. A column the models stopped declaring is dead
    weight that still has to be maintained, and usually means a model change
    landed without its migration."""
    orphans = {}
    for table, columns in migrated_schema.items():
        if table not in model_schema:
            orphans[table] = "whole table"
            continue
        extra = sorted(columns - model_schema[table])
        if extra:
            orphans[table] = extra
    assert not orphans, (
        f"the migrations build things no model declares: {orphans}")


def test_the_migration_chain_has_exactly_one_head():
    """Two heads mean `alembic upgrade head` is ambiguous, and which schema you
    get depends on which branch alembic picks."""
    import re

    revisions, downs = {}, set()
    for path in (ROOT / "alembic" / "versions").glob("*.py"):
        src = path.read_text()
        rev = re.search(r'^revision(?::.*?)?\s*=\s*["\']([^"\']+)', src, re.M)
        down = re.search(r'^down_revision(?::.*?)?\s*=\s*["\']([^"\']+)', src, re.M)
        if rev:
            revisions[rev.group(1)] = path.name
        if down:
            downs.add(down.group(1))
    heads = [r for r in revisions if r not in downs]
    assert len(heads) == 1, (
        f"expected one migration head, found {len(heads)}: "
        f"{[(h, revisions[h]) for h in heads]}")


def test_every_migration_can_be_identified():
    """A revision file with no revision id is silently skipped by alembic."""
    import re

    nameless = []
    for path in (ROOT / "alembic" / "versions").glob("*.py"):
        if not re.search(r'^revision(?::.*?)?\s*=\s*["\']', path.read_text(), re.M):
            nameless.append(path.name)
    assert not nameless, f"migration files with no revision id: {nameless}"


def test_alembic_env_registers_every_module_that_defines_a_table():
    """`--autogenerate` diffs the live database against Base.metadata, and
    Base.metadata holds only what has been imported. env.py imported app.models
    alone, which reaches four of the six model modules transitively — so
    crawl_targets, crawl_results and obligation_dispatches looked like tables
    no model declares, and the ordinary workflow would have drafted
    op.drop_table for all three.

    A destructive migration produced by running the documented command is a
    worse failure than a missing column, because it looks like the tool
    agreeing with you.
    """
    import ast

    env_src = (ROOT / "alembic" / "env.py").read_text()
    imported = {ast.unparse(node) for node in ast.walk(ast.parse(env_src))
                if isinstance(node, (ast.Import, ast.ImportFrom))}

    defining = {path.stem for path in (ROOT / "app").glob("*.py")
                if "__tablename__" in path.read_text()}
    # app.models re-exports these, so importing it registers them too.
    transitive = {"ai_governance_models", "audit_models", "grc_tprm_models"}

    missing = sorted(module for module in defining - transitive
                     if not any(f"app.{module}" in line for line in imported))
    assert not missing, (
        "these modules define tables but alembic/env.py never imports them, so "
        "their tables are invisible to --autogenerate and it will propose "
        f"dropping them: {missing}")
