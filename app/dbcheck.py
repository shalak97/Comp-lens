"""Startup gate: prove the database is reachable before anything else runs.

    python -m app.dbcheck --wait 60

Runs ahead of ``alembic upgrade head`` in the container's start command. Both
deployment shapes need it, for different reasons:

  bundled database  Postgres and the app start together, so the first few
                    connection attempts lose a race that resolves itself.

  your own database Everything that can be misconfigured, is: a host that does
                    not resolve, a security group that drops the packet, a
                    password with a shell metacharacter in it, TLS required at
                    one end and not the other. Without this the operator's
                    first experience of Comp-Lens is an alembic stack trace
                    ending in OperationalError, which names none of those.

So: retry the transient case, and when time runs out say which of them it was
and what to do about it. Exit 0 means the next command in the chain can rely
on a live connection.
"""
from __future__ import annotations

import argparse
import sys
import time

from app import db_url
from app.config import settings

#: Substrings psycopg puts in the failure that map to something actionable.
#: Matched case-insensitively against the whole exception text.
_HINTS: tuple[tuple[str, str], ...] = (
    ("could not translate host name",
     "The hostname does not resolve. Check DATABASE_URL for a typo, and that "
     "this container can reach your DNS (a private/VPC-only endpoint is not "
     "resolvable from outside the VPC)."),
    ("connection refused",
     "The host resolved but nothing accepted the connection. Check the port, "
     "and that the database is running and listening on it."),
    ("timeout expired",
     "The connection timed out rather than being refused — that is usually a "
     "firewall or security group silently dropping traffic. Allow this "
     "server's IP on the database's inbound rules."),
    ("no pg_hba.conf entry",
     "The server rejected this client. Its pg_hba.conf has no rule for your "
     "IP, user, or the TLS mode you connected with. If the message mentions "
     "SSL, append '?sslmode=require' to DATABASE_URL."),
    ("server does not support ssl",
     "TLS was required but the server does not offer it. Remove "
     "'?sslmode=require' only if the connection is on a trusted private "
     "network — otherwise enable TLS on the database."),
    ("password authentication failed",
     "The credentials were rejected. If the password contains @ : / or ?, it "
     "must be percent-encoded inside the URL (e.g. @ becomes %40)."),
    ("database \"", "The server is up and the credentials work, but that "
     "database does not exist. Create it, or correct the name at the end of "
     "DATABASE_URL."),
    ("role \"", "The server is up but that user does not exist. Create the "
     "role, or correct the username in DATABASE_URL."),
)


def _hint_for(exc: BaseException) -> str | None:
    text = str(exc).lower()
    for needle, advice in _HINTS:
        if needle in text:
            return advice
    return None


def probe(url: str, timeout: int = 5) -> tuple[bool, BaseException | None]:
    """One connection attempt. Never raises — the caller decides about retries."""
    from sqlalchemy import create_engine, text

    engine = None
    try:
        engine = create_engine(
            url, pool_pre_ping=True,
            connect_args={} if url.startswith("sqlite")
            else {"connect_timeout": timeout})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, None
    except Exception as exc:  # noqa: BLE001 — reporting it *is* the job
        return False, exc
    finally:
        if engine is not None:
            engine.dispose()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify the database is reachable.")
    ap.add_argument("--wait", type=int, default=0, metavar="SECONDS",
                    help="keep retrying for this long before giving up (default: "
                         "one attempt)")
    ap.add_argument("--interval", type=float, default=2.0,
                    help="seconds between attempts (default: 2)")
    ap.add_argument("--quiet", action="store_true",
                    help="print only on failure")
    args = ap.parse_args(argv)

    ins = db_url.inspect(settings.database_url, production=settings.is_production)

    # Configuration errors are not worth retrying: no amount of waiting turns
    # a missing DATABASE_URL into a good one.
    if not ins.ok:
        print("Comp-Lens cannot start.\n", file=sys.stderr)
        print(db_url.format_report(ins), file=sys.stderr)
        print("\nSee DEPLOY.md for both options: bring your own PostgreSQL, or "
              "run the bundled one.", file=sys.stderr)
        return 2

    if not args.quiet:
        print(db_url.format_report(ins))

    deadline = time.monotonic() + max(args.wait, 0)
    attempt = 0
    while True:
        attempt += 1
        ok, exc = probe(ins.url)
        if ok:
            if not args.quiet:
                where = "attempt" if attempt == 1 else "attempts"
                print(f"  connected ({attempt} {where})")
            return 0
        if time.monotonic() >= deadline:
            break
        if not args.quiet and attempt == 1:
            print(f"  not up yet, retrying for up to {args.wait}s…")
        time.sleep(args.interval)

    print(f"\nCould not connect to the database after {attempt} attempt(s).",
          file=sys.stderr)
    print(f"  url:   {db_url.redact(ins.url)}", file=sys.stderr)
    print(f"  error: {exc}", file=sys.stderr)
    hint = _hint_for(exc) if exc else None
    if hint:
        print(f"\n  → {hint}", file=sys.stderr)
    for w in ins.warnings:
        print(f"\n  note: {w}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
