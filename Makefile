# Comp-Lens — common operations. Run `make help` for the list.
.PHONY: help install up down logs restart update ps backup

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
	@echo "  make backup    Dump the database to ./backup-<date>.sql"

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

backup:
	@$(COMPOSE) exec -T db pg_dump -U complens complens > backup-$$(date +%Y%m%d-%H%M%S).sql && echo "Backup written."
