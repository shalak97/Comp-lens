"""Alembic environment — wires migrations to the app's models + DATABASE_URL."""
from logging.config import fileConfig

# Every module that defines a table has to be imported here, because
# target_metadata below is only as complete as what has been imported by the
# time it is read. app.models pulls in ai_governance_models, audit_models,
# grc_platforms.models and grc_tprm_models transitively — but NOT
# crawler_models or policy_models, so `alembic revision --autogenerate` saw
# crawl_targets, crawl_results and obligation_dispatches sitting in the
# database with no model behind them and would have drafted op.drop_table for
# all three. A data-destroying migration produced by the ordinary workflow.
import app.crawler_models  # noqa: F401  register tables
import app.models  # noqa: F401  register tables
import app.policy_models  # noqa: F401  register tables
from alembic import context
from app.config import settings
from app.database import Base

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)
config.set_main_option("sqlalchemy.url", settings.database_url)
target_metadata = Base.metadata

def run_migrations_offline():
    context.configure(url=settings.database_url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    from sqlalchemy import create_engine
    engine = create_engine(settings.database_url)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
