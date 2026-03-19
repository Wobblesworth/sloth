"""
Watcher — monitors the intake directory for new ZIP files and triggers processing.

Uses polling instead of inotify for Docker compatibility across platforms.
Waits for files to stop growing before processing (handles slow copies).
Processes one file at a time (queue model) to respect RAM constraints.
"""

import logging
import os
import sys
import time
from pathlib import Path

from process import process_zip

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("sloth.watcher")

# Configuration from environment
INTAKE_DIR = Path(os.environ.get("DATA_PATH", "./data")) / "intake"
ES_HOST = os.environ.get("ES_HOST", "localhost")
ES_PORT = int(os.environ.get("ES_PORT", "9200"))
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "10"))  # seconds
STABLE_WAIT = int(os.environ.get("STABLE_WAIT", "5"))  # seconds to wait for file stability


def is_file_stable(filepath, wait=STABLE_WAIT):
    """Check if a file has stopped growing (copy is complete)."""
    try:
        size1 = filepath.stat().st_size
        time.sleep(wait)
        size2 = filepath.stat().st_size
        return size1 == size2 and size1 > 0
    except FileNotFoundError:
        return False


def get_pending_files():
    """Get ZIP files in the intake directory, sorted by modification time."""
    if not INTAKE_DIR.exists():
        return []
    files = sorted(INTAKE_DIR.glob("*.zip"), key=lambda f: f.stat().st_mtime)
    return files


def main():
    log.info("=== SLOTH Watcher ===")
    log.info("Chill 2 Kill.")
    log.info(f"Watching: {INTAKE_DIR}")
    log.info(f"Elasticsearch: {ES_HOST}:{ES_PORT}")
    log.info(f"Poll interval: {POLL_INTERVAL}s")

    INTAKE_DIR.mkdir(parents=True, exist_ok=True)

    while True:
        files = get_pending_files()

        if files:
            for zip_file in files:
                log.info(f"New file detected: {zip_file.name}")

                if not is_file_stable(zip_file):
                    log.info(f"File still being copied, will retry next cycle")
                    continue

                log.info(f"File is stable, starting pipeline")
                success = process_zip(
                    zip_path=str(zip_file),
                    es_host=ES_HOST,
                    es_port=ES_PORT,
                )

                if success:
                    log.info(f"Pipeline completed for {zip_file.name}")
                else:
                    log.error(f"Pipeline failed for {zip_file.name}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Watcher stopped")
        sys.exit(0)
