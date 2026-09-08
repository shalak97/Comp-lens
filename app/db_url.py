"""Understand a database URL the operator pasted, before we try to connect.

Comp-Lens can run against a database you own and we never see. That option is
only real if pointing it at your own Postgres is *easy*, and the thing that
makes it hard is that no two providers hand you the same URL:

    Neon / Supabase   postgresql://user:pass@host/db?sslmode=require
    Heroku / Render   postgres://user:pass@host/db
    RDS console       postgresql://user:pass@host:5432/db
    SQLAlchemy wants  postgresql+psycopg://user:pass@host:5432/db

Paste any of the first three straight into DATABASE_URL and SQLAlchemy 2.x
either refuses the URL or reaches for psycopg2, which is not installed — and
the error it raises names neither the real problem nor the fix. So this module
normalises the driver, and separately reports the things that are worth saying
out loud (no TLS to a remote host, credentials that will not survive, a
password in a place that gets logged).

Nothing here connects to anything. It is string reasoning about a URL, kept
apart from ``app.database`` because that module builds an engine at import
time — which needs a URL that already works.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

#: Driver we ship. ``psycopg[binary]>=3.1`` is in requirements.txt; psycopg2 is
#: not, so a bare ``postgresql://`` URL (which SQLAlchemy maps to psycopg2)
#: fails at connect time with an import error about a package the operator
#: never asked for.
POSTGRES_DRIVER = "postgresql+psycopg"

#: Schemes a provider might hand you that mean "PostgreSQL" without naming a
#: driver. ``postgres://`` is the legacy libpq spelling; SQLAlchemy 1.4+
#: rejects it outright.
_BARE_POSTGRES = ("postgres://", "postgresql://")

#: Hosts where an unencrypted connection is not a finding — the database is
#: either in this container network or on this machine.
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "db", "postgres", ""})


def normalize(url: str) -> str:
    """Return ``url`` with a driver SQLAlchemy can actually load.

    Only the scheme is touched, and only when it names no driver. A URL that
    already specifies one (``postgresql+asyncpg://``, ``postgresql+psycopg2://``)
    is returned unchanged — the operator chose that, and silently overriding it
    would be its own bug.
    """
    text = (url or "").strip()
    for prefix in _BARE_POSTGRES:
        if text.startswith(prefix):
            return POSTGRES_DRIVER + "://" + text[len(prefix):]
    return text


def redact(url: str) -> str:
    """``url`` with the password replaced, safe to log or put in an error.

    Connection failures are exactly when someone pastes the message into a
    chat window or an issue, so the message must not carry the credential.
    """
    text = (url or "").strip()
    if not text:
        return "(unset)"
    split = urlsplit(text)
    if not split.password:
        return text
    host = split.hostname or ""
    if split.port:
        host = f"{host}:{split.port}"
    user = split.username or ""
    # Keep the query: sslmode lives there, and it is the parameter someone
    # reading this line in a log is most likely trying to confirm.
    query = f"?{split.query}" if split.query else ""
    return f"{split.scheme}://{user}:***@{host}{split.path}{query}"


@dataclass
class Inspection:
    """What we can tell about a URL without opening a socket."""

    url: str
    """The normalised URL — what will actually be handed to SQLAlchemy."""

    dialect: str
    """``postgresql``, ``sqlite``, or whatever scheme was given."""

    is_sqlite: bool
    is_postgres: bool
    host: str | None
    is_local: bool
    """True when the host is this machine or the compose network."""

    errors: list[str] = field(default_factory=list)
    """Reasons this URL cannot work. Startup should refuse."""

    warnings: list[str] = field(default_factory=list)
    """Things that will work but the operator should know. Startup continues."""

    @property
    def ok(self) -> bool:
        return not self.errors


def inspect(url: str, *, production: bool) -> Inspection:
    """Read a URL and say what is wrong with it, in the operator's terms.

    ``production`` changes what counts as an error rather than a warning: a
    bundled SQLite file is the right default on a laptop and a data-loss
    incident on a server.
    """
    raw = (url or "").strip()
    normalized = normalize(raw)
    split = urlsplit(normalized) if normalized else urlsplit("")
    scheme = split.scheme or ""
    dialect = scheme.split("+", 1)[0]
    host = split.hostname
    is_sqlite = dialect == "sqlite"
    is_postgres = dialect in ("postgres", "postgresql")
    is_local = (host or "") in _LOCAL_HOSTS

    out = Inspection(url=normalized, dialect=dialect or "(none)", is_sqlite=is_sqlite,
                     is_postgres=is_postgres, host=host, is_local=is_local)

    if not raw:
        out.errors.append(
            "DATABASE_URL is not set. Point it at a PostgreSQL database you "
            "control, e.g. postgresql://user:password@your-host:5432/complens — "
            "or run the bundled database instead (see DEPLOY.md).")
        return out

    if not scheme:
        out.errors.append(
            f"DATABASE_URL does not look like a URL: {redact(raw)}. Expected "
            "something like postgresql://user:password@host:5432/dbname.")
        return out

    if is_sqlite:
        if production:
            out.errors.append(
                "SQLite is not supported in production: it is a single file with "
                "one writer, so a second worker or a container restart on "
                "ephemeral disk loses data. Set DATABASE_URL to PostgreSQL.")
        return out

    if not is_postgres:
        out.errors.append(
            f"Unsupported database '{dialect}'. Comp-Lens targets PostgreSQL — "
            "the schema uses Postgres-specific migrations, so another engine "
            "will fail at 'alembic upgrade head' rather than at a query.")
        return out

    # ── Postgres, from here down ──
    if not host:
        out.errors.append(f"DATABASE_URL names no host: {redact(normalized)}")
    if not split.path.strip("/"):
        out.errors.append(
            f"DATABASE_URL names no database: {redact(normalized)}. Add the "
            "database name as the path, e.g. .../complens")

    if raw.startswith("postgres://"):
        out.warnings.append(
            "Rewrote the legacy 'postgres://' scheme to "
            f"'{POSTGRES_DRIVER}://' — SQLAlchemy 2.x rejects the short form. "
            "Nothing to do; noting it so the connection log matches your .env.")
    elif raw.startswith("postgresql://"):
        out.warnings.append(
            f"Added the '{POSTGRES_DRIVER}' driver to DATABASE_URL. A bare "
            "'postgresql://' means psycopg2, which is not installed.")

    sslmode = parse_qs(split.query).get("sslmode", [None])[0]
    if not is_local and sslmode in (None, "disable", "allow", "prefer"):
        out.warnings.append(
            f"Connecting to {host} without requiring TLS"
            + (f" (sslmode={sslmode})" if sslmode else " (no sslmode set)")
            + ". Credentials and compliance evidence would cross the network in "
              "the clear. Managed providers all support it — append "
              "'?sslmode=require' to DATABASE_URL.")

    if not split.username:
        out.warnings.append(
            "DATABASE_URL carries no username, so libpq will fall back to the "
            "OS user inside the container ('root'), which is unlikely to exist "
            "in your database.")

    return out


def format_report(ins: Inspection) -> str:
    """Render an inspection as something worth reading in a container log."""
    lines = [f"database: {redact(ins.url)}"]
    for w in ins.warnings:
        lines.append(f"  warning: {w}")
    for e in ins.errors:
        lines.append(f"  ERROR:   {e}")
    return "\n".join(lines)
