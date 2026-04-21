#!/usr/bin/env bash
# === SLOTH Kibana Initialization ===
# Creates default data views. Runs after services are up.
# Idempotent: skips data views that already exist.

set -euo pipefail

source .env 2>/dev/null || true
KIBANA_URL="http://localhost:${KIBANA_PORT:-5601}"
MAX_WAIT=120

# --- Wait for Kibana to be ready ---

printf "Waiting for Kibana..."
elapsed=0
while [ "$elapsed" -lt "$MAX_WAIT" ]; do
    if curl -sf "${KIBANA_URL}/api/status" | grep -q '"available"' 2>/dev/null; then
        echo " ready."
        break
    fi
    printf "."
    sleep 3
    elapsed=$((elapsed + 3))
done

if [ "$elapsed" -ge "$MAX_WAIT" ]; then
    echo " timeout after ${MAX_WAIT}s (Kibana not ready). Data views not created."
    exit 0
fi

# --- Create data views ---

create_data_view() {
    local id="$1"
    local name="$2"
    local pattern="$3"

    # Check if it already exists
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -H "kbn-xsrf: true" \
        "${KIBANA_URL}/api/data_views/data_view/${id}" 2>/dev/null || echo "000")

    if [ "$status" = "200" ]; then
        echo "  [OK] ${name} (already exists)"
        return
    fi

    # Create it
    response=$(curl -sf -w "\n%{http_code}" \
        -X POST "${KIBANA_URL}/api/data_views/data_view" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{
            \"data_view\": {
                \"id\": \"${id}\",
                \"title\": \"${pattern}\",
                \"name\": \"${name}\",
                \"timeFieldName\": \"@timestamp\"
            }
        }" 2>/dev/null || echo -e "\n000")

    http_code=$(echo "$response" | tail -1)

    if [ "$http_code" = "200" ]; then
        echo "  [OK] ${name} (created)"
    else
        echo "  [WARN] ${name} — HTTP ${http_code}, may need manual setup"
    fi
}

echo "Setting up Kibana data views..."
create_data_view "sloth-all"      "sloth"    "sloth-*"
create_data_view "sloth-hayabusa" "hayabusa" "sloth-hayabusa-*"

# Set sloth-all as default data view
curl -sf -o /dev/null \
    -X POST "${KIBANA_URL}/api/data_views/default" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d '{"data_view_id": "sloth-all", "force": true}' 2>/dev/null && \
    echo "  [OK] Default data view: sloth" || \
    echo "  [WARN] Could not set default data view"

# --- Apply Kibana settings ---

echo "Applying Kibana settings..."

set_kibana_setting() {
    local key="$1"
    local value="$2"
    local label="$3"

    curl -sf -o /dev/null \
        -X POST "${KIBANA_URL}/api/kibana/settings" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{\"changes\": {\"${key}\": ${value}}}" 2>/dev/null && \
        echo "  [OK] ${label}" || \
        echo "  [WARN] ${label}"
}

set_kibana_setting "format:number:defaultPattern" '"0.[000]"' "Number format: no thousands separator"
set_kibana_setting "theme:darkMode"               '"enabled"'  "Theme: dark mode"

echo "Kibana setup complete."
