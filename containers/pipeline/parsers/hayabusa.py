"""
Hayabusa parser — transforms Hayabusa JSONL output to ECS-aligned documents.

Hayabusa profile: verbose (includes MitreTactics, MitreTags, RuleFile, EvtxFile)

ECS field mapping:
    Timestamp       -> @timestamp
    Computer        -> host.name
    EventID         -> event.code
    Channel         -> event.provider
    Level           -> event.severity + event.severity_label
    RuleTitle       -> rule.name
    RuleID          -> rule.id
    RuleFile        -> rule.ruleset
    MitreTactics    -> threat.tactic.name
    MitreTags       -> threat.technique.id
    OtherTags       -> tags
    Details.User    -> user.name
    Details.Proc    -> process.executable
    Details.Cmdline -> process.command_line
    Details.PID     -> process.pid
    Details.ParentCmdline -> process.parent.command_line
    Details.ParentPID     -> process.parent.pid
    EvtxFile        -> log.file.path
    (full original) -> event.original
    (remaining)     -> event.original_details / event.extra
"""

import json
import re


SEVERITY_MAP = {
    "info": (0, "informational"),
    "low":  (1, "low"),
    "med":  (2, "medium"),
    "high": (3, "high"),
    "crit": (4, "critical"),
}


def convert_timestamp(ts):
    """Convert Hayabusa timestamp to ISO 8601 format for Elasticsearch."""
    return re.sub(
        r"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}\.\d+) ([+-]\d{2}:\d{2})$",
        r"\1T\2\3",
        ts,
    )


def remove_empty_keys(obj):
    """Remove empty string keys from nested dicts (Hayabusa sometimes emits them)."""
    if isinstance(obj, dict):
        return {k: remove_empty_keys(v) for k, v in obj.items() if k}
    return obj


def to_int(val):
    """Convert a value to int, handling hex strings like 0x1688."""
    if val is None:
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        try:
            return int(val, 16) if val.startswith("0x") else int(val)
        except (ValueError, TypeError):
            return None
    return None


def transform(raw_line, evt):
    """Transform a single Hayabusa event to an ECS-aligned document."""
    details = evt.get("Details", {}) or {}
    if isinstance(details, str):
        details = {"_raw": details}
    details = remove_empty_keys(details)

    extra = evt.get("ExtraFieldInfo", {}) or {}
    if isinstance(extra, str):
        extra = {"_raw": extra}
    extra = remove_empty_keys(extra)

    sev_num, sev_label = SEVERITY_MAP.get(evt.get("Level", ""), (0, "informational"))

    doc = {
        "@timestamp": convert_timestamp(evt.get("Timestamp", "")),
        "event": {
            "module": "hayabusa",
            "original": json.dumps(json.loads(raw_line.strip()), indent=2),
            "code": str(evt.get("EventID", "")),
            "provider": evt.get("Channel"),
            "severity": sev_num,
            "severity_label": sev_label,
        },
        "host": {"name": evt.get("Computer")},
        "rule": {
            "name": evt.get("RuleTitle"),
            "id": evt.get("RuleID"),
            "ruleset": evt.get("RuleFile"),
        },
        "record_id": evt.get("RecordID"),
        "tags": evt.get("OtherTags", []),
    }

    # MITRE ATT&CK
    tactics = evt.get("MitreTactics", [])
    techniques = evt.get("MitreTags", [])
    if tactics:
        doc["threat"] = {"tactic": {"name": tactics}}
    if techniques:
        doc.setdefault("threat", {})["technique"] = {"id": techniques}

    # Extract common fields from Details into ECS
    if details.get("User"):
        doc["user"] = {"name": details.pop("User")}

    proc = {}
    if details.get("Proc"):
        proc["executable"] = details.pop("Proc")
    if details.get("Cmdline"):
        proc["command_line"] = details.pop("Cmdline")
    pid = to_int(details.pop("PID", None))
    if pid is not None:
        proc["pid"] = pid

    parent = {}
    if details.get("ParentCmdline"):
        parent["command_line"] = details.pop("ParentCmdline")
    ppid = to_int(details.pop("ParentPID", None))
    if ppid is not None:
        parent["pid"] = ppid
    if parent:
        proc["parent"] = parent
    if proc:
        doc["process"] = proc

    # Source EVTX file path
    if evt.get("EvtxFile"):
        doc["log"] = {"file": {"path": evt["EvtxFile"]}}

    # Remaining fields go to flattened catchall
    if details:
        doc["event"]["original_details"] = details
    if extra:
        doc["event"]["extra"] = extra

    return doc
