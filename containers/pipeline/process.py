"""
Process a single evidence archive (ZIP) through the parsing pipeline.

Usage:
    python process.py /path/to/evidence.zip [--case-id CASE_ID] [--es-host HOST]
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

from elasticsearch import Elasticsearch

from ingest import load_index_template, ingest_jsonl
from parsers.hayabusa import transform as hayabusa_transform

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("sloth.process")

# Paths relative to this script
SCRIPT_DIR = Path(__file__).parent
MAPPINGS_DIR = SCRIPT_DIR / "mappings"

# Hayabusa binary — in container it will be at a fixed path
HAYABUSA_BIN = os.environ.get("HAYABUSA_BIN", shutil.which("hayabusa") or "")


def find_hayabusa():
    """Find the Hayabusa binary."""
    # Check environment variable first
    if HAYABUSA_BIN and Path(HAYABUSA_BIN).exists():
        return HAYABUSA_BIN

    # Check common locations
    candidates = [
        Path.home() / "sloth" / "tools" / "hayabusa" / "hayabusa-3.8.1-lin-x64-gnu",
        Path("/opt/hayabusa/hayabusa"),
    ]
    for c in candidates:
        if c.exists():
            return str(c)

    return None


def derive_case_id(zip_path):
    """Derive a case ID from the ZIP filename."""
    stem = Path(zip_path).stem  # e.g. "WORKSTATION01" or "WORKSTATION01_triage"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{stem}_{timestamp}"


def extract_zip(zip_path, extract_dir):
    """Extract a ZIP file to the target directory."""
    log.info(f"Extracting {zip_path} to {extract_dir}")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_dir)
    log.info(f"Extraction complete")


def find_evtx_dirs(extract_dir):
    """Find directories containing .evtx files."""
    evtx_files = list(Path(extract_dir).rglob("*.evtx"))
    if not evtx_files:
        return []
    # Return the extracted root — Hayabusa will scan recursively
    return [str(extract_dir)]


def run_hayabusa(hayabusa_bin, evtx_dir, output_path):
    """Run Hayabusa on a directory of EVTX files."""
    cmd = [
        hayabusa_bin,
        "json-timeline",
        "-d", evtx_dir,
        "-o", str(output_path),
        "-L",           # no color
        "-w",           # no wizard
        "-p", "verbose",  # verbose profile (includes MITRE tags)
    ]
    log.info(f"Running Hayabusa: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        log.error(f"Hayabusa failed:\n{result.stderr}")
        return False

    # Count output lines
    if output_path.exists():
        count = sum(1 for _ in open(output_path))
        log.info(f"Hayabusa produced {count} events")
        return True
    else:
        log.error("Hayabusa produced no output file")
        return False


def process_zip(zip_path, case_id=None, es_host="localhost", es_port=9200):
    """Process a single evidence ZIP through the full pipeline."""
    zip_path = Path(zip_path)
    if not zip_path.exists():
        log.error(f"File not found: {zip_path}")
        return False

    if case_id is None:
        case_id = derive_case_id(zip_path)

    log.info(f"=== Processing case: {case_id} ===")
    log.info(f"Source: {zip_path}")

    # Setup directories
    base_dir = Path(os.environ.get("DATA_PATH", "./data"))
    processing_dir = base_dir / "processing" / case_id
    processing_dir.mkdir(parents=True, exist_ok=True)

    raw_dir = processing_dir / "raw"
    parsed_dir = processing_dir / "parsed"
    parsed_dir.mkdir(exist_ok=True)

    # Status tracking
    status = {
        "case_id": case_id,
        "source": str(zip_path),
        "started": datetime.now().isoformat(),
        "steps": {},
    }

    try:
        # Step 1: Extract
        extract_zip(zip_path, raw_dir)
        status["steps"]["extract"] = "ok"

        # Step 2: Find EVTX files
        evtx_dirs = find_evtx_dirs(raw_dir)
        evtx_count = len(list(Path(raw_dir).rglob("*.evtx")))
        log.info(f"Found {evtx_count} EVTX files")

        if evtx_count == 0:
            log.warning("No EVTX files found — skipping Hayabusa")
            status["steps"]["hayabusa"] = "skipped"
        else:
            # Step 3: Run Hayabusa
            hayabusa_bin = find_hayabusa()
            if hayabusa_bin is None:
                log.error("Hayabusa binary not found")
                status["steps"]["hayabusa"] = "error: binary not found"
                return False

            hayabusa_output = parsed_dir / "hayabusa.jsonl"
            if run_hayabusa(hayabusa_bin, str(raw_dir), hayabusa_output):
                status["steps"]["hayabusa"] = "ok"
            else:
                status["steps"]["hayabusa"] = "error"
                return False

            # Step 4: Ingest into Elasticsearch
            es = Elasticsearch(f"http://{es_host}:{es_port}")
            load_index_template(
                es,
                MAPPINGS_DIR / "hayabusa.json",
                "sloth-hayabusa",
            )
            index_name = f"sloth-hayabusa-{case_id}".lower()
            total, errors = ingest_jsonl(
                es, hayabusa_output, index_name, hayabusa_transform
            )
            status["steps"]["ingest_hayabusa"] = {
                "index": index_name,
                "ingested": total,
                "errors": errors,
            }

        # Done — move ZIP to completed
        completed_dir = base_dir / "completed"
        completed_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(zip_path), str(completed_dir / zip_path.name))
        log.info(f"Moved {zip_path.name} to completed/")

        status["completed"] = datetime.now().isoformat()
        status["result"] = "success"

    except Exception as e:
        log.exception(f"Pipeline failed: {e}")
        status["result"] = "failed"
        status["error"] = str(e)

        # Move to failed
        failed_dir = base_dir / "failed"
        failed_dir.mkdir(parents=True, exist_ok=True)
        if zip_path.exists():
            shutil.move(str(zip_path), str(failed_dir / zip_path.name))

        return False

    finally:
        # Save status
        status_file = processing_dir / "status.json"
        with open(status_file, "w") as f:
            json.dump(status, f, indent=2)
        log.info(f"Status saved to {status_file}")

    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process a forensic evidence archive")
    parser.add_argument("zip_path", help="Path to the evidence ZIP file")
    parser.add_argument("--case-id", help="Case identifier (default: derived from filename)")
    parser.add_argument("--es-host", default="localhost", help="Elasticsearch host")
    parser.add_argument("--es-port", type=int, default=9200, help="Elasticsearch port")
    args = parser.parse_args()

    success = process_zip(args.zip_path, args.case_id, args.es_host, args.es_port)
    sys.exit(0 if success else 1)
