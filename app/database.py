"""Database engine and session management (SQLAlchemy 2.x).

Local: SQLite. Production: PostgreSQL via DATABASE_URL.
"""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings


class Base(DeclarativeBase):
    pass


_connect_args = {}
_engine_kwargs: dict = {"pool_pre_ping": True, "future": True}

if settings.database_url.startswith("sqlite"):
    # allow cross-thread use and wait (don't error) when another writer holds
    # the lock — needed now that each assessment also upserts the posture row.
    _connect_args = {"check_same_thread": False, "timeout": 30}
    if settings.is_production:
        raise RuntimeError(
            "Refusing to start: SQLite is not allowed in production. "
            "Set DATABASE_URL to PostgreSQL (postgresql+psycopg://...)."
        )
else:
    _engine_kwargs["pool_size"] = settings.db_pool_size
    _engine_kwargs["max_overflow"] = settings.db_max_overflow

engine = create_engine(settings.database_url, connect_args=_connect_args, **_engine_kwargs)

if settings.database_url.startswith("sqlite"):
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _rec):  # noqa: ANN001
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")   # concurrent readers + one writer
        cur.execute("PRAGMA busy_timeout=30000")  # wait up to 30s for the lock
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a DB session and always closes it."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """Create all tables. For real migrations use Alembic; this is for dev/bootstrap."""
    import app.models  # noqa: F401  (ensure models are registered)

    Base.metadata.create_all(bind=engine)
