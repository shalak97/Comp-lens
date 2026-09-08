# Comp-Lens — common operations. Run `make help` for the list.
.PHONY: help install up down logs restart update ps backup dbcheck

COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")

help:
	@echo "Comp-Lens self-hosted operations:"
	@echo "  make install   First-time setup: secrets, build, start, migrate (runs ./install.sh)"
	@echo "  make up        Start the stack"
	@echo "  make down      Stop the stack (data is preserved)"
	@echo "  make restart   Restart the app container"
	@echo "  make logs      Tail the application logs"
	@echo "  make ps        Show container status"
	@echo "  make update    Pull latest code, rebuild, restart"
	@echo "  make backup    Dump the bundled database to ./backup-<date>.sql"
	@echo "  make dbcheck   Test the database connection and explain any failure"

install:
	@./install.sh

up:
	@$(COMPOSE) up -d

down:
	@$(COMPOSE) down

restart:
	@$(COMPOSE) restart app

logs:
	@$(COMPOSE) logs -f app

ps:
	@$(COMPOSE) ps

update:
	@git pull && $(COMPOSE) build && $(COMPOSE) up -d && echo "Updated and restarted."

dbcheck:
	@$(COMPOSE) run --rm app python -m app.dbcheck

# Only meaningful for the bundled database. When you brought your own, the
# dump belongs wherever you already run backups — and silently writing an
# empty file, or a confusing "no such service: db", would be worse than saying
# so.
backup:
	@if $(COMPOSE) ps --services 2>/dev/null | grep -qx db; then \
	  $(COMPOSE) exec -T db pg_dump -U complens complens > backup-$$(date +%Y%m%d-%H%M%S).sql && echo "Backup written."; \
	else \
	  echo "No bundled database in this deployment — Comp-Lens is using your own PostgreSQL."; \
	  echo "Back it up where you already manage that server, or run pg_dump against your DATABASE_URL:"; \
	  echo "  pg_dump \"\$$DATABASE_URL\" > backup-\$$(date +%Y%m%d-%H%M%S).sql"; \
	  exit 1; \
	fi
