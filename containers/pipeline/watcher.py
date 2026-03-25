"""
Watcher — monitors the intake directory for new ZIP files and triggers processing.

Uses polling instead of inotify for Docker compatibility across platforms.
Waits for files to stop growing before processing (handles slow copies).
Supports parallel processing via ThreadPoolExecutor (configurable workers).
"""

import logging
import os
import re
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
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


def get_max_workers():
    """Determine the number of parallel workers.

    Reads PARALLEL_WORKERS from environment:
      - "auto" (default): 1 worker per GB of ES_HEAP
      - explicit number: use that value (minimum 1)
    """
    setting = os.environ.get("PARALLEL_WORKERS", "auto").strip().lower()

    if setting != "auto":
        try:
            return max(1, int(setting))
        except ValueError:
            log.warning(f"Invalid PARALLEL_WORKERS='{setting}', falling back to auto")

    # Auto: parse ES_HEAP (e.g. "2g", "4G", "512m")
    heap = os.environ.get("ES_HEAP", "2g").strip().lower()
    match = re.match(r"^(\d+)\s*([gm])?$", heap)
    if match:
        value = int(match.group(1))
        unit = match.group(2) or "g"
        gb = value if unit == "g" else max(1, value // 1024)
        workers = max(1, gb)
        return workers

    log.warning(f"Cannot parse ES_HEAP='{heap}', defaulting to 1 worker")
    return 1


def is_file_stable(filepath, wait=STABLE_WAIT):
    """Check if a file has stopped growing (copy is complete).
    Performs two rounds of size checks to handle slow network copies."""
    try:
        size1 = filepath.stat().st_size
        if size1 == 0:
            return False
        time.sleep(wait)
        size2 = filepath.stat().st_size
        if size1 != size2:
            return False
        # Second round to catch slow/bursty copies
        time.sleep(wait)
        size3 = filepath.stat().st_size
        return size2 == size3
    except FileNotFoundError:
        return False


def is_es_ready():
    """Check if Elasticsearch is reachable and healthy."""
    try:
        url = f"http://{ES_HOST}:{ES_PORT}/_cluster/health"
        req = urllib.request.urlopen(url, timeout=5)
        return req.status == 200
    except Exception:
        return False


def get_pending_files():
    """Get ZIP files in the intake directory, sorted by modification time."""
    if not INTAKE_DIR.exists():
        return []
    files = sorted(INTAKE_DIR.glob("*.zip"), key=lambda f: f.stat().st_mtime)
    return files


def _process_worker(zip_file, es_host, es_port):
    """Worker: check file stability, then run the full pipeline.

    Returns (zip_name, status) where status is "success", "failed", or "unstable".
    Runs inside a thread pool — must be self-contained.
    """
    name = zip_file.name
    try:
        if not is_file_stable(zip_file):
            log.info(f"[{name}] File still being copied, will retry next cycle")
            return (name, "unstable")

        log.info(f"[{name}] File is stable, starting pipeline")
        success = process_zip(
            zip_path=str(zip_file),
            es_host=es_host,
            es_port=es_port,
        )

        if success:
            log.info(f"[{name}] Pipeline completed")
            return (name, "success")
        else:
            log.error(f"[{name}] Pipeline failed")
            return (name, "failed")

    except Exception as e:
        log.exception(f"[{name}] Unexpected error: {e}")
        return (name, "failed")


def main():
    max_workers = get_max_workers()
    heap = os.environ.get("ES_HEAP", "2g")
    setting = os.environ.get("PARALLEL_WORKERS", "auto")

    log.info("=== SLOTH Watcher ===")
    log.info("Chill 2 Kill.")
    log.info(f"Watching: {INTAKE_DIR}")
    log.info(f"Elasticsearch: {ES_HOST}:{ES_PORT}")
    log.info(f"Poll interval: {POLL_INTERVAL}s")
    if setting.strip().lower() == "auto":
        log.info(f"Workers: {max_workers} (auto from ES_HEAP={heap})")
    else:
        log.info(f"Workers: {max_workers} (explicit)")

    INTAKE_DIR.mkdir(parents=True, exist_ok=True)

    # in_flight tracks files currently being processed: filename -> Future
    in_flight = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        while True:
            # --- Collect completed futures (non-blocking) ---
            done_keys = []
            for fname, future in in_flight.items():
                if future.done():
                    done_keys.append(fname)
                    try:
                        _, status = future.result()
                    except Exception as e:
                        log.exception(f"[{fname}] Worker raised: {e}")

            for key in done_keys:
                del in_flight[key]

            # --- Submit new work ---
            files = get_pending_files()
            if files:
                if not is_es_ready():
                    log.warning("Elasticsearch not ready, waiting...")
                    time.sleep(POLL_INTERVAL)
                    continue

                for zip_file in files:
                    # Skip if already in flight
                    if zip_file.name in in_flight:
                        continue

                    # Skip if we're at capacity
                    if len(in_flight) >= max_workers:
                        break

                    # Re-check file exists (may have been moved by clean-cases)
                    if not zip_file.exists():
                        continue

                    log.info(f"New file detected: {zip_file.name}")
                    future = executor.submit(
                        _process_worker, zip_file, ES_HOST, ES_PORT,
                    )
                    in_flight[zip_file.name] = future

            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Watcher stopped")
        sys.exit(0)
