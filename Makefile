# === SLOTH Makefile ===
# Shortcuts for managing the platform.
# Usage: make <command>

.PHONY: setup up down status logs restart reset help

# First-time setup: creates data directories and copies .env
setup:
	@bash scripts/setup.sh

# Start all services
up:
	@docker compose up -d
	@echo ""
	@echo "Sloth is waking up..."
	@echo "Kibana will be available at http://localhost:$${KIBANA_PORT:-5601} (may take ~60s)"

# Stop all services (data is preserved)
down:
	@docker compose down
	@echo "Sloth is sleeping."

# Show running containers and their status
status:
	@docker compose ps

# Follow live logs from all services
logs:
	@docker compose logs -f

# Restart all services
restart:
	@docker compose restart

# Delete all data and start fresh (asks for confirmation)
reset:
	@echo "WARNING: This will delete ALL data (Elasticsearch indices, parsed evidence, everything)."
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 1
	@docker compose down -v
	@rm -rf data/
	@bash scripts/setup.sh
	@echo "Sloth has been reset."

# Show available commands
help:
	@echo "=== SLOTH ==="
	@echo "Chill 2 Kill."
	@echo ""
	@echo "  make setup    - First-time setup (create directories, check dependencies)"
	@echo "  make up       - Start all services"
	@echo "  make down     - Stop all services (data is preserved)"
	@echo "  make status   - Show running containers"
	@echo "  make logs     - Follow live logs"
	@echo "  make restart  - Restart all services"
	@echo "  make reset    - Delete ALL data and start fresh"
	@echo "  make help     - Show this message"
