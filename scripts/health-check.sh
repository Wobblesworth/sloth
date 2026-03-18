#!/bin/bash
# === SLOTH Health Check ===
# Verifies that all services are up and responding.

set -e

# Load config
source .env 2>/dev/null || true
ES_PORT=${ES_PORT:-9200}
KIBANA_PORT=${KIBANA_PORT:-5601}

echo "=== SLOTH Health Check ==="
echo "Chill 2 Kill."
echo ""

ERRORS=0

# --- Elasticsearch ---
printf "Elasticsearch (:%s)... " "$ES_PORT"
if curl -sf "http://localhost:${ES_PORT}/_cluster/health" > /dev/null 2>&1; then
    STATUS=$(curl -sf "http://localhost:${ES_PORT}/_cluster/health" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    echo "OK (cluster: $STATUS)"
else
    echo "FAILED"
    ERRORS=$((ERRORS + 1))
fi

# --- Kibana ---
printf "Kibana (:%s)... " "$KIBANA_PORT"
if curl -sf "http://localhost:${KIBANA_PORT}/api/status" > /dev/null 2>&1; then
    echo "OK"
else
    echo "FAILED (may still be starting, try again in 30s)"
    ERRORS=$((ERRORS + 1))
fi

# --- Docker containers ---
echo ""
echo "Containers:"
docker compose ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null || echo "Could not read container status."

echo ""
if [ "$ERRORS" -eq 0 ]; then
    echo "All services are healthy."
else
    echo "$ERRORS service(s) not responding."
    exit 1
fi
