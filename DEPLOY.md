# Deploying Comp-Lens on your own server

One command. On any Linux server with Docker installed:

```bash
git clone https://github.com/shalak97/Comp-lens-2.0.git
cd Comp-lens-2.0
./install.sh
```

The installer:
1. Checks Docker + Compose are present
2. Generates a random database password and evidence signing key
3. Writes them to `.env` (mode 600, gitignored — never committed)
4. Builds the app image and starts the app + PostgreSQL
5. Runs database migrations automatically
6. Waits until the app reports healthy, then prints your dashboard URL

When it finishes you'll have Comp-Lens at `http://your-server:8000/dashboard`.

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
- No external database needed — PostgreSQL runs in the stack
