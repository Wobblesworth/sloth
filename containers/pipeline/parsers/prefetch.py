"""
Prefetch parser — transforms parsed Prefetch metadata to ECS documents.

Source data is produced by libscca (libyal) via process.py's
parse_pf_with_libscca(), which returns a PECmd-compatible dict per .pf.

We emit one document per execution (Option B): N docs for N LastRunTimes,
each with @timestamp set to the specific execution time.  This gives a
clean timeline view in Kibana and enables correlation with EVTX events.
"""

import json
import re


def _parse_timestamp(ts):
    """PECmd emits ISO timestamps with nanosecond precision — clip to ms for ES."""
    if not ts:
        return None
    # Handle Z suffix, preserve timezone
    ts = ts.strip()
    if ts.startswith("0001-01-01"):
        return None  # PECmd uses 0001-01-01 as null
    # Truncate to milliseconds: 2020-01-01T12:00:00.1234567 -> 2020-01-01T12:00:00.123
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{3}))?\d*(Z|[+-]\d{2}:?\d{2})?$", ts)
    if m:
        base, ms, tz = m.groups()
        result = base
        if ms:
            result += f".{ms}"
        if tz:
            result += tz if tz == "Z" or ":" in tz else f"{tz[:3]}:{tz[3:]}"
        else:
            result += "Z"
        return result
    return ts


_VOLUME_PREFIX_RE = re.compile(r"^\\VOLUME\{[^}]+\}", re.IGNORECASE)


def _normalize_volume_path(path):
    """Convert \\VOLUME{GUID}\\... to C:\\... (best-effort, assumes single-volume host).

    Prefetch stores paths with volume GUIDs; we normalize to C:\\ since most
    Windows endpoints have a single system volume. Non-VOLUME paths pass through.
    """
    if not isinstance(path, str):
        return path
    return _VOLUME_PREFIX_RE.sub("C:", path)


def _derive_executable_path(exe_name, files_loaded):
    """Find the full path of the executable from FilesLoaded, normalized to C:\\..."""
    if not exe_name or not files_loaded:
        return None
    exe_upper = exe_name.upper()
    for path in files_loaded:
        if isinstance(path, str) and path.upper().endswith(f"\\{exe_upper}"):
            return _normalize_volume_path(path)
    return None


def _derive_directories(files_loaded):
    """Extract unique parent directories from file paths, normalized and sorted."""
    dirs = set()
    for f in files_loaded:
        if not isinstance(f, str):
            continue
        parent = f.rsplit("\\", 1)[0] if "\\" in f else f
        dirs.add(_normalize_volume_path(parent))
    return sorted(dirs)


def transform_pf(raw_json, pf_meta):
    """Transform one PECmd JSON into a list of ECS documents (one per execution).

    Args:
        raw_json: dict parsed from PECmd JSON file
        pf_meta: dict with source info (path, filename)

    Returns:
        list of ECS-aligned docs
    """
    exe_name = raw_json.get("ExecutableFilename") or ""
    pf_hash = raw_json.get("Hash")
    run_count = raw_json.get("RunCount", 0)
    version = raw_json.get("Version") or raw_json.get("SourceFilename", "")

    last_run_times = raw_json.get("LastRunTimes", []) or []
    # Filter out null timestamps (PECmd pads with 0001-01-01 when unused)
    valid_times = [t for t in last_run_times if _parse_timestamp(t)]

    raw_files_loaded = raw_json.get("FilesLoaded", []) or []
    files_loaded = [_normalize_volume_path(f) for f in raw_files_loaded if isinstance(f, str)]
    # Derive directories from files (Prefetch doesn't store them separately)
    dirs_loaded = _derive_directories(raw_files_loaded)
    volumes = raw_json.get("Volumes", []) or []

    # Normalize volumes
    volume_docs = []
    for v in volumes:
        if not isinstance(v, dict):
            continue
        volume_docs.append({
            "name": v.get("Name"),
            "serial_number": v.get("SerialNumber"),
            "created": _parse_timestamp(v.get("CreationTime") or v.get("CreatedOn")),
        })

    executable_path = _derive_executable_path(exe_name, raw_files_loaded)

    def build_doc(execution_time, sequence):
        """Build a single ECS doc for one execution."""
        doc = {
            "@timestamp": execution_time,
            "event": {
                "module": "prefetch",
                "dataset": "libscca",
                "action": "program-executed",
                "category": ["process"],
                "type": ["start"],
                "outcome": "success",
                "original": json.dumps(raw_json, indent=2),
            },
            "process": {},
            "file": {},
            "prefetch": {},
        }

        if exe_name:
            doc["process"]["name"] = exe_name
        if executable_path:
            doc["process"]["executable"] = executable_path

        # The .pf file itself — Windows path only (source disk location)
        pf_path = raw_json.get("SourceFilename")
        if pf_path:
            doc["file"]["path"] = pf_path
            doc["file"]["name"] = pf_meta.get("filename")
        if raw_json.get("Size"):
            doc["file"]["size"] = raw_json["Size"]

        # Prefetch-specific fields
        if pf_hash:
            doc["prefetch"]["hash"] = pf_hash
        if run_count:
            doc["prefetch"]["run_count"] = run_count
        if version:
            doc["prefetch"]["version"] = version
        if sequence is not None:
            doc["prefetch"]["execution_sequence"] = sequence
        if files_loaded:
            doc["prefetch"]["files_loaded"] = files_loaded
        if dirs_loaded:
            doc["prefetch"]["directories_loaded"] = dirs_loaded
        if volume_docs:
            doc["prefetch"]["volumes"] = volume_docs

        # Clean up empty sub-docs
        for k in ("process", "file", "prefetch"):
            if not doc[k]:
                del doc[k]

        return doc

    # One doc per execution. Sequence: 1 = most recent (libscca sorts desc).
    docs = []
    for i, t in enumerate(valid_times, start=1):
        ts = _parse_timestamp(t)
        if ts:
            docs.append(build_doc(ts, i))
    return docs


def transform(raw_line, evt):
    """Compatibility entrypoint for the ingest pipeline.

    Prefetch ingestion uses transform_pf directly (one JSON per file, many
    docs per file). This function exists to match the hayabusa parser's
    signature but operates on already-parsed JSON.
    """
    pf_meta = evt.pop("_pf_meta", {})
    return transform_pf(evt, pf_meta)
