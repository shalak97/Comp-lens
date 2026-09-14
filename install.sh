#!/usr/bin/env bash
#
# Comp-Lens self-hosted installer.
# Brings up the full stack (app + PostgreSQL) on your own server with one command:
#
#     ./install.sh
#
# It checks prerequisites, generates secrets, writes .env, builds and starts the
# containers, runs database migrations, waits for health, and prints your URL.
# Re-running it is safe — it won't overwrite an existing .env or wipe data.

set -euo pipefail

# ── pretty output ───────────────────────────────────────────────────
c_reset=$'\033[0m'; c_blue=$'\033[34m'; c_green=$'\033[32m'
c_yellow=$'\033[33m'; c_red=$'\033[31m'; c_bold=$'\033[1m'
say()  { printf "%s\n" "$*"; }
info() { printf "${c_blue}→${c_reset} %s\n" "$*"; }
ok()   { printf "${c_green}✓${c_reset} %s\n" "$*"; }
warn() { printf "${c_yellow}!${c_reset} %s\n" "$*"; }
die()  { printf "${c_red}✗ %s${c_reset}\n" "$*" >&2; exit 1; }

HOST_PORT="${HOST_PORT:-8000}"
ENV_FILE=".env"

printf "\n${c_bold}Comp-Lens installer${c_reset}\n"
printf "Self-hosted GRC / compliance-as-code platform\n\n"

# ── 1. prerequisites ────────────────────────────────────────────────
info "Checking prerequisites…"

if ! command -v docker >/dev/null 2>&1; then
  die "Docker is not installed. Install it from https://docs.docker.com/engine/install/ and re-run."
fi

# docker compose v2 (plugin) or v1 (standalone)?
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  die "Docker Compose not found. Install the Compose plugin: https://docs.docker.com/compose/install/"
fi

if ! docker info >/dev/null 2>&1; then
  die "Docker daemon is not running (or you lack permission). Start Docker, or add your user to the 'docker' group."
fi
ok "Docker and Compose are ready ($COMPOSE)"

# need the app source — Dockerfile must be present
[ -f Dockerfile ] || die "Dockerfile not found. Run this script from the Comp-Lens repository root."
[ -f docker-compose.yml ] || die "docker-compose.yml not found. Run from the repository root."

# ── 2a. which database? ─────────────────────────────────────────────
# Asked before secrets are generated, because the answer decides whether a
# database password is even meaningful. Non-interactive callers (CI, an
# unattended install) can skip the prompt with:
#     DATABASE_URL=postgresql://... ./install.sh
#     COMPLENS_DB=bundled ./install.sh
DB_CHOICE="${COMPLENS_DB:-}"
if [ -z "$DB_CHOICE" ]; then
  if [ -n "${DATABASE_URL:-}" ]; then
    DB_CHOICE="own"
    info "DATABASE_URL is set in the environment — using your own database."
  elif [ -f "$ENV_FILE" ]; then
    DB_CHOICE="keep"          # existing install; don't second-guess it
  elif [ -t 0 ]; then
    printf "\n${c_bold}Where should Comp-Lens store your compliance data?${c_reset}\n\n"
    printf "  ${c_bold}1)${c_reset} Bundled PostgreSQL  — a database container runs here. Nothing\n"
    printf "     else to set up; backups and upgrades are yours to run.\n\n"
    printf "  ${c_bold}2)${c_reset} Your own PostgreSQL — RDS, Cloud SQL, Neon, Supabase, or your\n"
    printf "     own server. No database container starts, and your findings stay\n"
    printf "     on infrastructure you already back up.\n\n"
    printf "Choice [1]: "
    read -r reply || reply=""
    case "$reply" in
      2) DB_CHOICE="own" ;;
      *) DB_CHOICE="bundled" ;;
    esac
  else
    DB_CHOICE="bundled"       # no tty and nothing specified: keep the old default
  fi
fi

if [ "$DB_CHOICE" = "own" ] && [ -z "${DATABASE_URL:-}" ]; then
  printf "\nPaste your PostgreSQL connection URL.\n"
  printf "  ${c_bold}postgresql://user:password@host:5432/complens?sslmode=require${c_reset}\n"
  printf "(a 'postgres://' URL from your provider is fine — it gets corrected)\n\n"
  printf "DATABASE_URL: "
  read -r DATABASE_URL || DATABASE_URL=""
  [ -n "$DATABASE_URL" ] || die "No URL given. Re-run and choose 1 for the bundled database, or paste a URL."
fi

# ── 2b. secret generation + .env ────────────────────────────────────
gen_secret() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 32
  else head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}

if [ -f "$ENV_FILE" ]; then
  ok "Using existing $ENV_FILE (not overwriting)"
  # An .env written by an earlier version of this script pairs APP_ENV=production
  # with a blank COMP_LENS_API_KEYS, which app/main.py refuses to start on. Say
  # so here, with the fix, rather than letting it surface as a health-check
  # timeout three minutes from now.
  if grep -q '^APP_ENV=production' "$ENV_FILE" 2>/dev/null \
     && ! grep -qE '^COMP_LENS_API_KEYS=.+' "$ENV_FILE" 2>/dev/null; then
    warn "$ENV_FILE sets APP_ENV=production but COMP_LENS_API_KEYS is empty."
    say  "Comp-Lens refuses to start in production without authentication,"
    say  "because an empty key list would make every request an all-tenant admin."
    say  ""
    say  "Add a key to $ENV_FILE, for example:"
    say  "  ${c_bold}COMP_LENS_API_KEYS=$(gen_secret):*${c_reset}"
    say  ""
    say  "Then re-run ./install.sh"
    exit 1
  fi
elif [ "$DB_CHOICE" = "own" ]; then
  info "Generating secrets and writing $ENV_FILE (using your database)…"
  SIGNING_KEY="$(gen_secret)"
  # APP_ENV=production below makes app/main.py refuse to start without an API
  # key, so the installer mints one rather than writing a blank it will reject.
  ADMIN_KEY="$(gen_secret)"
  cat > "$ENV_FILE" <<ENVEOF
# ─── Comp-Lens configuration (generated $(date -u +%Y-%m-%dT%H:%MZ)) ───
# Secrets below were auto-generated. Keep this file private — do NOT commit it.

# Database: your own PostgreSQL. No database container is started, and no
# compliance data is stored anywhere but here.
DATABASE_URL=${DATABASE_URL}
COMPOSE_FILE=docker-compose.byodb.yml

# Evidence chain-of-custody signing key (HMAC). Rotating this invalidates old signatures.
EVIDENCE_SIGNING_KEY=${SIGNING_KEY}

# App
APP_ENV=production
HOST_PORT=${HOST_PORT}
ENABLE_SCHEDULER=false
EVIDENCE_BACKEND=local

# ─── API auth (required when APP_ENV=production) ──────────────────
# Format: "key:tenant,key2:*" — ":*" grants access to every tenant.
# This admin key was generated for you. Add more keys by appending them,
# comma-separated. Blanking this line will stop the app from starting.
COMP_LENS_API_KEYS=${ADMIN_KEY}:*

# ─── Optional: activate live connectors ───────────────────────────
# Only connectors listed here make real API calls. e.g. OKTA,GITHUB,AWS
LIVE_CONNECTORS_ALLOWLIST=

# Connector credentials (fill the ones you use, then re-run ./install.sh)
# OKTA_ORG_URL=https://your-org.okta.com
# OKTA_API_TOKEN=
# GITHUB_TOKEN=
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=
# AWS_REGION=us-east-1
# NOTIFY_SLACK_WEBHOOK=
ENVEOF
  chmod 600 "$ENV_FILE"
  ok "Wrote $ENV_FILE (mode 600) — pointing at your database"
else
  info "Generating secrets and writing $ENV_FILE…"
  SIGNING_KEY="$(gen_secret)"
  # APP_ENV=production below makes app/main.py refuse to start without an API
  # key, so the installer mints one rather than writing a blank it will reject.
  ADMIN_KEY="$(gen_secret)"
  DB_PASS="$(gen_secret | cut -c1-24)"
  cat > "$ENV_FILE" <<ENVEOF
# ─── Comp-Lens configuration (generated $(date -u +%Y-%m-%dT%H:%MZ)) ───
# Secrets below were auto-generated. Keep this file private — do NOT commit it.

# Database (runs in a container; password is internal to the stack)
POSTGRES_USER=complens
POSTGRES_PASSWORD=${DB_PASS}
POSTGRES_DB=complens

# Evidence chain-of-custody signing key (HMAC). Rotating this invalidates old signatures.
EVIDENCE_SIGNING_KEY=${SIGNING_KEY}

# App
APP_ENV=production
HOST_PORT=${HOST_PORT}
ENABLE_SCHEDULER=false
EVIDENCE_BACKEND=local

# ─── API auth (required when APP_ENV=production) ──────────────────
# Format: "key:tenant,key2:*" — ":*" grants access to every tenant.
# This admin key was generated for you. Add more keys by appending them,
# comma-separated. Blanking this line will stop the app from starting.
COMP_LENS_API_KEYS=${ADMIN_KEY}:*

# ─── Optional: activate live connectors ───────────────────────────
# Only connectors listed here make real API calls. e.g. OKTA,GITHUB,AWS
LIVE_CONNECTORS_ALLOWLIST=

# Connector credentials (fill the ones you use, then re-run ./install.sh)
# OKTA_ORG_URL=https://your-org.okta.com
# OKTA_API_TOKEN=
# GITHUB_TOKEN=
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=
# AWS_REGION=us-east-1
# NOTIFY_SLACK_WEBHOOK=
ENVEOF
  chmod 600 "$ENV_FILE"
  ok "Wrote $ENV_FILE with generated secrets (mode 600)"
fi

# ── 3. build + start ────────────────────────────────────────────────
info "Building the application image (first run can take a few minutes)…"
$COMPOSE build

info "Starting the stack…"
$COMPOSE up -d

# ── 4. wait for health ──────────────────────────────────────────────
info "Waiting for the database and migrations to come up…"
URL="http://localhost:${HOST_PORT}/health/ready"
deadline=$(( $(date +%s) + 180 ))
spin='-\|/'; i=0
until curl -fs "$URL" >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    printf "\n"
    warn "App did not report healthy within 3 minutes."
    say  "Check logs with:  ${c_bold}$COMPOSE logs -f app${c_reset}"
    exit 1
  fi
  i=$(( (i+1) % 4 ))
  printf "\r  ${spin:$i:1} still starting…"
  sleep 2
done
printf "\r%-30s\r" " "
ok "Comp-Lens is up and healthy"

# ── 5. done ─────────────────────────────────────────────────────────
# try to detect a sensible host address
HOST_ADDR="localhost"
if command -v hostname >/dev/null 2>&1; then
  IP="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
  [ -n "${IP:-}" ] && HOST_ADDR="$IP"
fi

printf "\n${c_green}${c_bold}Comp-Lens is running.${c_reset}\n\n"
if grep -q '^COMPOSE_FILE=docker-compose.byodb.yml' "$ENV_FILE" 2>/dev/null; then
  printf "  Database    ${c_bold}your own PostgreSQL${c_reset} — no database container is running,\n"
  printf "              and your compliance data stays on infrastructure you control.\n"
  printf "              Back it up where you already back that server up.\n\n"
else
  printf "  Database    bundled PostgreSQL in a container on this machine.\n"
  printf "              Back it up with ${c_bold}make backup${c_reset} — nothing else will.\n\n"
fi
printf "  Dashboard   ${c_bold}http://%s:%s/dashboard${c_reset}\n" "$HOST_ADDR" "$HOST_PORT"
printf "  Health      http://%s:%s/health/ready\n\n" "$HOST_ADDR" "$HOST_PORT"

# The API key is the one thing here that cannot be recovered from a running
# container, so print it where it cannot be missed.
if [ -n "${ADMIN_KEY:-}" ]; then
  printf "  ${c_bold}Your admin API key${c_reset} (stored in %s — it is not shown again):\n" "$ENV_FILE"
  printf "    ${c_bold}%s${c_reset}\n\n" "$ADMIN_KEY"
  printf "  Try it:\n"
  printf "    curl -H 'X-API-Key: %s' http://%s:%s/health/ready\n\n" \
         "$ADMIN_KEY" "$HOST_ADDR" "$HOST_PORT"
fi
printf "Useful commands:\n"
printf "  View logs       ${c_bold}%s logs -f app${c_reset}\n" "$COMPOSE"
printf "  Stop            ${c_bold}%s down${c_reset}\n" "$COMPOSE"
printf "  Update + redeploy ${c_bold}git pull && ./install.sh${c_reset}\n"
printf "  Connect a tool  edit ${c_bold}.env${c_reset}, then re-run ${c_bold}./install.sh${c_reset}\n\n"
