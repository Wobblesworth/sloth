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

from ingest import load_index_template, ingest_jsonl, ingest_docs
from parsers.hayabusa import transform as hayabusa_transform
from parsers.prefetch import transform_pf

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("sloth.process")

# Paths relative to this script
SCRIPT_DIR = Path(__file__).parent
MAPPINGS_DIR = SCRIPT_DIR / "mappings"

HAYABUSA_BIN = os.environ.get("HAYABUSA_BIN", shutil.which("hayabusa") or "")


def find_hayabusa():
    """Find the Hayabusa binary."""
    if HAYABUSA_BIN and Path(HAYABUSA_BIN).exists():
        return HAYABUSA_BIN
    candidates = [
        Path.home() / "sloth" / "tools" / "hayabusa" / "hayabusa-3.8.1-lin-x64-gnu",
        Path("/opt/hayabusa/hayabusa"),
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None


def parse_evidence_name(zip_path):
    """
    Parse the evidence filename to extract metadata.

    Naming convention: <organization>_<hostname>_<date>.zip
    Examples:
        acmecorp_DC01_20260319.zip    -> org=acmecorp, host=DC01, date=20260319
        clientB_LAPTOP01_20260319.zip -> org=clientB, host=LAPTOP01, date=20260319
        random-file.zip               -> org=None, host=None, date=None (fallback)

    Returns a dict with: case_id, organization, hostname, date (all may be None)
    """
    import re
    stem = Path(zip_path).stem
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Try to match convention: org_host_date (host may contain dashes)
    match = re.match(r"^([^_]+)_(.+)_(\d{8})$", stem)
    if match:
        org, host, date = match.groups()
        # Remove dashes from case_id (used in ES index names) but keep original in metadata
        safe_id = f"{org}_{host}_{date}".replace("-", "")
        return {
            "case_id": safe_id,
            "organization": org,
            "hostname": host,
            "date": date,
        }

    # Fallback: use filename as-is with timestamp to ensure uniqueness
    log.warning(
        f"Filename '{stem}' does not match convention <org>_<host>_<date>. "
        "Metadata will not be extracted."
    )
    return {
        "case_id": f"{stem}_{timestamp}",
        "organization": None,
        "hostname": None,
        "date": None,
    }


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


def find_prefetch_files(extract_dir):
    """Find all .pf files (Windows Prefetch) in the extracted triage."""
    return list(Path(extract_dir).rglob("*.pf"))


def parse_pf_with_libscca(pf_path):
    """Parse a single .pf file with libscca and return a PECmd-compatible dict.

    Returns None if the file can't be parsed OR is a SuperFetch pre-warming
    entry (not evidence of execution).
    """
    import pyscca
    try:
        scca = pyscca.file()
        scca.open(str(pf_path))
    except Exception as e:
        log.warning(f"Failed to open {pf_path.name}: {e}")
        return None

    try:
        exe_name = scca.executable_filename or ""
        # Skip SuperFetch pre-warming entries (Op-*, Ag*) — not execution evidence
        if exe_name.startswith("Op-") or pf_path.name.startswith("Ag"):
            return None

        # PF format v17/v23 (XP/Vista/7) has 1 last run time; v26+ (Win8+) has up to 8
        max_runs = 8 if (scca.format_version or 0) >= 26 else 1
        last_run_times = []
        for i in range(max_runs):
            try:
                t = scca.get_last_run_time(i)
                if t:
                    last_run_times.append(t.isoformat())
            except Exception:
                break

        volumes = []
        for i in range(scca.number_of_volumes):
            try:
                v = scca.get_volume_information(i)
                volumes.append({
                    "Name": v.device_path,
                    "SerialNumber": f"{v.serial_number:08X}" if v.serial_number else None,
                    "CreationTime": v.creation_time.isoformat() if v.creation_time else None,
                })
            except Exception:
                continue

        files_loaded = []
        for i in range(scca.number_of_filenames):
            try:
                files_loaded.append(scca.get_filename(i))
            except Exception:
                continue

        # Windows-style path (prefetch files are always in C:\Windows\Prefetch)
        windows_path = f"C:\\Windows\\Prefetch\\{pf_path.name}"

        return {
            "SourceFilename": windows_path,
            "ExecutableFilename": exe_name,
            "Hash": f"{scca.prefetch_hash:08X}" if scca.prefetch_hash else None,
            "Size": pf_path.stat().st_size,
            "Version": f"v{scca.format_version}" if scca.format_version else None,
            "RunCount": scca.run_count,
            "LastRunTimes": last_run_times,
            "Volumes": volumes,
            "FilesLoaded": files_loaded,
            "DirectoriesLoaded": [],
        }
    finally:
        scca.close()


def yield_prefetch_docs(pf_files):
    """Parse each .pf with libscca and yield ECS documents."""
    parsed = 0
    failed = 0
    for pf in pf_files:
        data = parse_pf_with_libscca(pf)
        if data is None:
            failed += 1
            continue
        parsed += 1
        pf_meta = {"path": str(pf), "filename": pf.name}
        for doc in transform_pf(data, pf_meta):
            yield doc
    log.info(f"Prefetch: {parsed} parsed, {failed} failed")


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

    # Parse filename for metadata
    meta = parse_evidence_name(zip_path)
    if case_id is None:
        case_id = meta["case_id"]

    log.info(f"=== Processing case: {case_id} ===")
    log.info(f"Source: {zip_path}")
    if meta["organization"]:
        log.info(f"Organization: {meta['organization']}, Host: {meta['hostname']}, Date: {meta['date']}")

    # Check if case already exists in Elasticsearch
    try:
        es = Elasticsearch(f"http://{es_host}:{es_port}")
        # Use _cat/indices to count actual matching indices (wildcards with HEAD are unreliable)
        response = es.cat.indices(index=f"sloth-*-{case_id}".lower(), h="index", format="json")
        if len(response) > 0:
            log.warning(
                f"Case '{case_id}' already exists in Elasticsearch. "
                f"Skipping. To reprocess, run: make clean-case CASE={case_id}"
            )
            # Move ZIP to completed so watcher doesn't retry every cycle
            base_dir = Path(os.environ.get("DATA_PATH", "./data"))
            completed_dir = base_dir / "completed"
            completed_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(zip_path), str(completed_dir / zip_path.name))
            zip_path.unlink()
            log.info(f"Moved {zip_path.name} to completed/ (skipped)")
            return True
    except Exception as e:
        log.debug(f"Duplicate check skipped: {e}")

    # Setup directories
    base_dir = Path(os.environ.get("DATA_PATH", "./data"))
    processing_dir = base_dir / "processing" / case_id
    processing_dir.mkdir(parents=True, exist_ok=True)

    # Lock file prevents concurrent processing of the same case
    lock_file = processing_dir / ".lock"
    if lock_file.exists():
        log.warning(f"Case '{case_id}' is already being processed (lock file exists). Skipping.")
        return True
    try:
        lock_file.touch(exist_ok=False)
    except FileExistsError:
        log.warning(f"Case '{case_id}' is already being processed. Skipping.")
        return True

    raw_dir = processing_dir / "raw"
    parsed_dir = processing_dir / "parsed"
    parsed_dir.mkdir(exist_ok=True)

    # Status tracking
    status = {
        "case_id": case_id,
        "source": str(zip_path),
        "organization": meta["organization"],
        "hostname": meta["hostname"],
        "date": meta["date"],
        "started": datetime.now().isoformat(),
        "steps": {},
    }

    try:
        # Step 1: Extract
        extract_zip(zip_path, raw_dir)
        status["steps"]["extract"] = "ok"

        # Build case metadata to inject into every document
        case_meta = {"case": {"id": case_id}}
        if meta["organization"]:
            case_meta["organization"] = {"name": meta["organization"]}
        if meta["hostname"]:
            case_meta["case"]["hostname"] = meta["hostname"]
        if meta["date"]:
            case_meta["case"]["date"] = meta["date"]

        es = Elasticsearch(f"http://{es_host}:{es_port}")

        # Step 2: Hayabusa (EVTX)
        evtx_count = len(list(Path(raw_dir).rglob("*.evtx")))
        log.info(f"Found {evtx_count} EVTX files")

        if evtx_count == 0:
            log.warning("No EVTX files found — skipping Hayabusa")
            status["steps"]["hayabusa"] = "skipped"
        else:
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

            load_index_template(es, MAPPINGS_DIR / "hayabusa.json", "sloth-hayabusa")
            index_name = f"sloth-hayabusa-{case_id}".lower()
            total, errors = ingest_jsonl(
                es, hayabusa_output, index_name, hayabusa_transform,
                extra_fields=case_meta,
            )
            status["steps"]["ingest_hayabusa"] = {
                "index": index_name, "ingested": total, "errors": errors,
            }

        # Step 3: Prefetch (libscca)
        pf_files = find_prefetch_files(raw_dir)
        log.info(f"Found {len(pf_files)} Prefetch (.pf) files")

        if not pf_files:
            log.info("No Prefetch files — skipping")
            status["steps"]["prefetch"] = "skipped"
        else:
            load_index_template(es, MAPPINGS_DIR / "prefetch.json", "sloth-libscca")
            index_name = f"sloth-libscca-{case_id}".lower()
            total, errors = ingest_docs(
                es, yield_prefetch_docs(pf_files), index_name,
                extra_fields=case_meta,
            )
            status["steps"]["prefetch"] = "ok"
            status["steps"]["ingest_prefetch"] = {
                "index": index_name, "ingested": total, "errors": errors,
            }

        # Done — move ZIP to completed
        completed_dir = base_dir / "completed"
        completed_dir.mkdir(parents=True, exist_ok=True)
        if zip_path.exists():
            shutil.copy2(str(zip_path), str(completed_dir / zip_path.name))
            zip_path.unlink()
            log.info(f"Moved {zip_path.name} to completed/")
        else:
            log.info(f"Source file already moved (likely by clean-cases)")

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
            shutil.copy2(str(zip_path), str(failed_dir / zip_path.name))
            zip_path.unlink()

        return False

    finally:
        # Save status atomically (write to temp file, then rename)
        status_file = processing_dir / "status.json"
        status_tmp = processing_dir / "status.json.tmp"
        try:
            with open(status_tmp, "w") as f:
                json.dump(status, f, indent=2)
            status_tmp.rename(status_file)
            log.info(f"Status saved to {status_file}")
        except Exception:
            log.warning("Could not save status file (directory may have been deleted)")

        # Remove lock file
        try:
            lock_file.unlink(missing_ok=True)
        except Exception:
            pass

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
