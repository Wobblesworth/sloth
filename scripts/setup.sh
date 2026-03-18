#!/bin/bash
# === SLOTH First-Time Setup ===
# Creates required directories and validates dependencies.

set -e

echo "=== SLOTH Setup ==="
echo "Chill 2 Kill."
echo ""

# --- Check dependencies ---

if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed."
    echo "Install it with: sudo apt install docker.io -y"
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "ERROR: Docker Compose is not installed."
    echo "Install it with: sudo apt install docker-compose-v2 -y"
    exit 1
fi

if ! docker info &> /dev/null 2>&1; then
    echo "ERROR: Docker is not running or you don't have permission."
    echo "Try: sudo systemctl start docker"
    echo "Or:  sudo usermod -aG docker \$USER  (then log out and back in)"
    exit 1
fi

echo "[OK] Docker and Docker Compose found."

# --- Check .env ---

if [ ! -f .env ]; then
    cp .env.example .env
    echo "[OK] Created .env from .env.example"
else
    echo "[OK] .env already exists."
fi

# --- Create data directories ---

DATA_PATH=$(grep DATA_PATH .env | cut -d '=' -f2)
DATA_PATH=${DATA_PATH:-./data}

mkdir -p "$DATA_PATH/intake"
mkdir -p "$DATA_PATH/processing"
mkdir -p "$DATA_PATH/completed"
mkdir -p "$DATA_PATH/failed"
mkdir -p "$DATA_PATH/elasticsearch"

echo "[OK] Data directories created in $DATA_PATH/"

# --- Check available disk space ---

AVAILABLE_GB=$(df -BG --output=avail . | tail -1 | tr -d ' G')
if [ "$AVAILABLE_GB" -lt 20 ]; then
    echo "WARNING: Only ${AVAILABLE_GB}GB of disk space available. Recommended: 20GB+"
else
    echo "[OK] ${AVAILABLE_GB}GB of disk space available."
fi

# --- Check available RAM ---

TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
if [ "$TOTAL_RAM_MB" -lt 8000 ]; then
    echo "WARNING: Only ${TOTAL_RAM_MB}MB of RAM. Recommended: 8GB+"
else
    echo "[OK] ${TOTAL_RAM_MB}MB of RAM available."
fi

echo ""
echo "Setup complete. Run 'make up' to start Sloth."
