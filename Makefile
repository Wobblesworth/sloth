# === SLOTH Makefile ===
# Shortcuts for managing the platform.
# Usage: make <command>

.PHONY: setup up down status logs watch restart reset clean-case clean-all-cases list-cases build rebuild help

# First-time setup: creates data directories and copies .env
setup:
	@bash scripts/setup.sh

# Start all services
up:
	@docker compose up -d
	@echo ""
	@echo "Sloth is waking up..."
	@bash scripts/init-kibana.sh
	@echo ""
	@echo "Kibana: http://localhost:$${KIBANA_PORT:-5601}"

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

# Watch pipeline activity (filtered, human-readable)
watch:
	@echo "=== SLOTH Watch ==="
	@echo "Watching pipeline activity... (Ctrl+C to stop)"
	@echo ""
	@docker compose logs -f pipeline 2>&1 | grep --line-buffered -E "(Processing case|Organization|Found .* EVTX|Hayabusa produced|Ingested|Moved .* to completed|Pipeline completed|Pipeline failed|WARNING|ERROR|already exists|Watching)" | sed \
		-e 's/sloth-pipeline  | //' \
		-e 's/\[INFO\] sloth\.[a-z]*: //' \
		-e 's/\[WARNING\] sloth\.[a-z]*: /⚠  /' \
		-e 's/\[ERROR\] sloth\.[a-z]*: /✗  /'

# Restart all services
restart:
	@docker compose restart

# Build custom containers (after code changes)
build:
	@docker compose build
	@echo "Build complete."

# Rebuild and restart (stop + build + restart pipeline)
rebuild:
	@docker compose stop pipeline 2>/dev/null || true
	@docker compose build pipeline
	@docker compose up -d pipeline
	@bash scripts/init-kibana.sh
	@echo "Pipeline rebuilt and restarted."

# List all cases (indices in Elasticsearch)
list-cases:
	@echo "=== Cases in Elasticsearch ==="
	@curl -sf "http://localhost:$${ES_PORT:-9200}/_cat/indices/sloth-*?h=index,docs.count,store.size&s=index" 2>/dev/null || echo "Elasticsearch not reachable"

# Delete a single case: make clean-case CASE=<case_id>
clean-case:
ifndef CASE
	@echo "Usage: make clean-case CASE=<case_id>"
	@echo "Run 'make list-cases' to see available cases."
	@exit 1
endif
	@bash scripts/clean-cases.sh $(CASE)

# Delete all cases but keep Kibana settings and data views intact
clean-all-cases:
	@echo "WARNING: This will delete ALL cases from Elasticsearch and processing data."
	@echo "Kibana settings and data views will be preserved."
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ] || exit 1
	@bash scripts/clean-cases.sh

# Delete all data and start fresh (asks for confirmation)
reset:
	@echo "WARNING: This will delete ALL data (Elasticsearch indices, parsed evidence, everything)."
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ] || exit 1
	@echo "Stopping all services..."
	@docker compose down -v --timeout 30
	@echo "Deleting all data..."
	@docker run --rm -v $$(pwd)/data:/data alpine rm -rf /data
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
	@echo "  make logs     - Follow raw logs (all containers)"
	@echo "  make watch    - Watch pipeline activity (human-readable)"
	@echo "  make restart  - Restart all services"
	@echo "  make build            - Build containers (after code changes)"
	@echo "  make rebuild          - Rebuild + restart pipeline"
	@echo "  make list-cases       - List all cases in Elasticsearch"
	@echo "  make clean-case CASE= - Delete a single case"
	@echo "  make clean-all-cases  - Delete all cases (keeps Kibana settings)"
	@echo "  make reset            - Delete ALL data and start fresh"
	@echo "  make help             - Show this message"
