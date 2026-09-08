# Deploying Comp-Lens on your own server

One command. On any Linux server with Docker installed:

```bash
git clone https://github.com/shalak97/Comp-lens-2.0.git
cd Comp-lens-2.0
./install.sh
```

The installer asks one question — where your compliance data should live — then:
1. Checks Docker + Compose are present
2. Generates an evidence signing key (and a database password, if you use the bundled database)
3. Writes them to `.env` (mode 600, gitignored — never committed)
4. Builds the app image and starts the stack
5. Verifies the database is reachable, then runs migrations
6. Waits until the app reports healthy, then prints your dashboard URL

When it finishes you'll have Comp-Lens at `http://your-server:8000/dashboard`.

## Where your data lives

Comp-Lens is self-hosted. Your findings, evidence and attestations go into a
PostgreSQL database, and **nothing is sent anywhere else** — there is no
telemetry, no phone-home, and no hosted account. You choose which database.

### Option A — bundled PostgreSQL (default)

A Postgres container runs alongside the app, storing data in a Docker volume on
this machine. Nothing else to set up.

```bash
./install.sh          # choose 1
```

Back it up yourself — `make backup` writes a dump to the working directory.
Nothing else will.

### Option B — bring your own PostgreSQL

Point Comp-Lens at a database you already operate: RDS, Cloud SQL, Neon,
Supabase, or your own server. **No database container starts**, and your
compliance data stays on infrastructure you already back up, monitor and
retain under your own policy.

```bash
./install.sh          # choose 2, then paste your connection URL
```

or non-interactively:

```bash
DATABASE_URL='postgresql://user:pass@host:5432/complens?sslmode=require' ./install.sh
```

or by hand in `.env`:

```ini
DATABASE_URL=postgresql://user:pass@host:5432/complens?sslmode=require
COMPOSE_FILE=docker-compose.byodb.yml
```

`COMPOSE_FILE` is what stops the unused Postgres container from starting; with
it set, plain `docker compose up -d` does the right thing.

**Requirements for your database**

- PostgreSQL 13 or newer.
- An empty database that exists already — Comp-Lens creates its own tables via
  Alembic on first boot, so the user needs `CREATE TABLE` on it.
- Network reach from this host, and `sslmode=require` unless the database is on
  a trusted private network.

**Paste the URL your provider gave you.** These are all accepted and corrected
at startup:

| Provider | URL you get | What Comp-Lens uses |
|---|---|---|
| Heroku, Render | `postgres://…` | `postgresql+psycopg://…` |
| Neon, Supabase, RDS | `postgresql://…` | `postgresql+psycopg://…` |
| already explicit | `postgresql+psycopg://…` | unchanged |

A bare `postgresql://` means psycopg2 to SQLAlchemy, which isn't installed, and
`postgres://` is rejected outright — neither error names the fix, so the app
fixes it for you and logs that it did.

**If the password contains `@ : / ?`** it must be percent-encoded in the URL
(`@` becomes `%40`). A password rejected for no obvious reason is almost always
this.

### Checking the connection

Startup refuses to continue on a database it cannot reach, and says why in
plain language rather than raising an alembic traceback. You can run the same
check yourself any time:

```bash
make dbcheck
# or: docker compose run --rm app python -m app.dbcheck
```

It distinguishes the causes that look identical from a stack trace — DNS,
firewall, `pg_hba.conf`, TLS mismatch, wrong password, missing database — and
tells you which one you have. Passwords are redacted from all of its output, so
it is safe to paste into an issue.

### Switching later

Moving from the bundled database to your own is a dump and a restore:

```bash
make backup                                    # writes backup-<date>.sql
psql "$YOUR_DATABASE_URL" < backup-<date>.sql  # load it into your database
# then set DATABASE_URL and COMPOSE_FILE in .env, and:
docker compose down && docker compose up -d
```

The bundled Docker volume is left untouched, so you can switch back by undoing
the two `.env` lines.

## Day-two operations

```bash
make logs      # tail application logs
make update    # pull latest code, rebuild, restart
make backup    # dump the database
make down      # stop (data is preserved in Docker volumes)
```

## Connecting your tools

Edit `.env`, uncomment the connector credentials you need, set `LIVE_CONNECTORS_ALLOWLIST=OKTA,GITHUB`, then re-run `./install.sh` (safe — it won't regenerate secrets or wipe data).

## Putting it behind HTTPS

The stack serves plain HTTP on the port you chose. For a public deployment, put a reverse proxy (Caddy, nginx, or Traefik) in front for TLS termination. Example with Caddy — a one-line `Caddyfile`:

```
compliance.yourcompany.com {
    reverse_proxy localhost:8000
}
```

## Requirements

- Any Linux server (or macOS) with Docker Engine + Docker Compose
- 1 GB RAM minimum, 2 GB recommended
- A database: either the bundled PostgreSQL (nothing to provide) or one of your
  own — see [Where your data lives](#where-your-data-lives)
