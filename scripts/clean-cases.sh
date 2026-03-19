#!/bin/bash
# === SLOTH Case Cleanup ===
# Deletes cases from Elasticsearch and local processing directories.
# Original ZIPs in completed/ are always preserved.
#
# Usage:
#   clean-cases.sh              — delete ALL cases
#   clean-cases.sh <case_id>    — delete a single case

set -e

source .env 2>/dev/null || true
ES_PORT=${ES_PORT:-9200}
ES_URL="http://localhost:${ES_PORT}"

CASE_ID="$1"
ERRORS=0

# --- Check Elasticsearch is reachable ---
if ! curl -sf "${ES_URL}/_cluster/health" > /dev/null 2>&1; then
    echo "ERROR: Elasticsearch is not reachable at ${ES_URL}"
    echo "Make sure services are running (make up)"
    exit 1
fi

if [ -n "$CASE_ID" ]; then
    # --- Delete single case ---
    echo "Stopping pipeline..."
    docker compose stop pipeline 2>/dev/null
    echo "[OK] Pipeline stopped"
    echo ""
    echo "Deleting case: ${CASE_ID}"

    # Delete ES indices
    RESPONSE=$(curl -sf -X DELETE "${ES_URL}/sloth-*-${CASE_ID}" 2>/dev/null || echo "FAIL")
    if echo "$RESPONSE" | grep -q '"acknowledged":true'; then
        echo "[OK] Elasticsearch indices deleted"
    elif echo "$RESPONSE" | grep -q "FAIL\|no such index"; then
        echo "[WARN] No Elasticsearch indices found for this case"
    else
        echo "[ERROR] Failed to delete indices: ${RESPONSE}"
        ERRORS=$((ERRORS + 1))
    fi

    # Delete processing directory
    if [ -d "data/processing/${CASE_ID}" ]; then
        docker run --rm -v "$(pwd)/data:/data" alpine rm -rf "/data/processing/${CASE_ID}"
        if [ $? -eq 0 ]; then
            echo "[OK] Processing data deleted"
        else
            echo "[ERROR] Failed to delete processing data"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo "[OK] No processing data to delete"
    fi

    echo ""
    echo "Restarting pipeline..."
    docker compose start pipeline 2>/dev/null
    echo "Done. Case ${CASE_ID} removed."
    exit $ERRORS

else
    # --- Delete all cases ---
    echo "Stopping pipeline..."
    docker compose stop pipeline 2>/dev/null
    echo "[OK] Pipeline stopped"
    echo ""
    echo "Deleting ALL cases..."

    # Delete ES indices
    RESPONSE=$(curl -sf -X DELETE "${ES_URL}/sloth-*" 2>/dev/null || echo "FAIL")
    if echo "$RESPONSE" | grep -q '"acknowledged":true'; then
        echo "[OK] All Elasticsearch indices deleted"
    elif echo "$RESPONSE" | grep -q "FAIL"; then
        echo "[ERROR] Failed to delete Elasticsearch indices"
        ERRORS=$((ERRORS + 1))
    else
        echo "[OK] No indices to delete"
    fi

    # Move any pending intake files to completed (so they don't reprocess)
    INTAKE_ZIPS=$(find data/intake -name "*.zip" 2>/dev/null | wc -l)
    if [ "$INTAKE_ZIPS" -gt 0 ]; then
        mv data/intake/*.zip data/completed/ 2>/dev/null
        echo "[OK] Moved ${INTAKE_ZIPS} pending file(s) from intake/ to completed/"
    fi

    # Delete all processing directories
    docker run --rm -v "$(pwd)/data:/data" alpine sh -c "rm -rf /data/processing/*"
    if [ $? -eq 0 ]; then
        echo "[OK] Processing data deleted"
    else
        echo "[ERROR] Failed to delete processing data"
        ERRORS=$((ERRORS + 1))
    fi
fi

# --- Verify everything is actually clean ---
echo ""
echo "--- Verification ---"

# Check ES indices
REMAINING=$(curl -sf "${ES_URL}/_cat/indices/sloth-*?h=index" 2>/dev/null | wc -l)
if [ "$REMAINING" -gt 0 ] 2>/dev/null; then
    echo "[FAIL] ${REMAINING} index(es) still in Elasticsearch:"
    curl -sf "${ES_URL}/_cat/indices/sloth-*?h=index,docs.count,store.size&s=index" 2>/dev/null
    ERRORS=$((ERRORS + 1))
else
    echo "[OK] Elasticsearch is clean"
fi

# Check processing directory
PROC_COUNT=$(find data/processing -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
if [ "$PROC_COUNT" -gt 0 ]; then
    echo "[FAIL] ${PROC_COUNT} folder(s) still in data/processing/:"
    ls data/processing/
    ERRORS=$((ERRORS + 1))
else
    echo "[OK] Processing directory is clean"
fi

# Check intake (should be empty after processing)
INTAKE_COUNT=$(find data/intake -name "*.zip" 2>/dev/null | wc -l)
if [ "$INTAKE_COUNT" -gt 0 ]; then
    echo "[WARN] ${INTAKE_COUNT} file(s) still in data/intake/ (will be processed on next cycle)"
fi

# Report completed ZIPs (informational)
COMPLETED_COUNT=$(find data/completed -name "*.zip" 2>/dev/null | wc -l)
if [ "$COMPLETED_COUNT" -gt 0 ]; then
    echo "[INFO] ${COMPLETED_COUNT} original ZIP(s) preserved in data/completed/"
fi

echo ""
if [ "$ERRORS" -gt 0 ]; then
    echo "Cleanup finished with ${ERRORS} error(s). Check messages above."
    # Restart pipeline even on error
    docker compose start pipeline 2>/dev/null
    exit 1
else
    echo "Restarting pipeline..."
    docker compose start pipeline 2>/dev/null
    echo ""
    echo "Done. Sloth is clean and running."
fi
