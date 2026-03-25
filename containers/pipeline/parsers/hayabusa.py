"""
Hayabusa parser — transforms Hayabusa JSONL output to ECS-aligned documents.

Event-type-aware dispatcher: each Channel/EventID combination gets a dedicated
handler that extracts fields into proper ECS namespaces.  Events without a
handler fall back to generic extraction.

Hayabusa profile: verbose (includes MitreTactics, MitreTags, RuleFile, EvtxFile)
"""

import json
import re


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "info": (0, "informational"),
    "low":  (1, "low"),
    "med":  (2, "medium"),
    "high": (3, "high"),
    "crit": (4, "critical"),
}

PROTO_MAP = {
    6:  "tcp",
    17: "udp",
    1:  "icmp",
    58: "ipv6-icmp",
}


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

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


def _deep_merge(base, override):
    """Merge override dict into base dict recursively."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def parse_hashes(hash_string):
    """Parse Hayabusa hash string into a dict of hash type -> value.

    Input:  "SHA1=abc,MD5=def,SHA256=ghi,IMPHASH=jkl"
    Output: {"sha1": "abc", "md5": "def", "sha256": "ghi", "imphash": "jkl"}
    """
    if not hash_string or not isinstance(hash_string, str):
        return {}
    result = {}
    for part in hash_string.split(","):
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key and value:
            result[key] = value
    return result


def parse_user(user_string):
    """Parse DOMAIN\\User into {"name": ..., "domain": ...}.

    Handles bare usernames, DOMAIN\\User, and skips n/a or empty values.
    Returns empty dict for invalid inputs.
    """
    if not user_string or not isinstance(user_string, str):
        return {}
    if user_string.lower() in ("n/a", "-", ""):
        return {}
    if "\\" in user_string:
        domain, _, name = user_string.partition("\\")
        result = {"name": name}
        if domain:
            result["domain"] = domain
        return result
    return {"name": user_string}


def parse_logon_type(type_string):
    """Parse Hayabusa logon type string like '3 - NETWORK' -> ('3', 'NETWORK')."""
    if not type_string or not isinstance(type_string, str):
        return None, None
    if " - " in type_string:
        code, _, label = type_string.partition(" - ")
        return code.strip(), label.strip()
    return type_string.strip(), None


def is_valid_ip(val):
    """Check if a value looks like a valid IP address (v4 or v6). Rejects '-', 'n/a', empty."""
    if not val or not isinstance(val, str):
        return False
    if val in ("-", "n/a", "", "::"):
        return False
    # Quick check: must contain at least one digit
    return any(c.isdigit() for c in val)


def _pop_internal(details, *keys):
    """Pop Hayabusa-internal fields that have no ECS mapping (PGUID, LGUID, etc.)."""
    for k in keys:
        details.pop(k, None)


def _build_process(details, exe_key="Proc", pid_key="PID"):
    """Extract common process fields from details, popping consumed keys."""
    proc = {}
    exe = details.pop(exe_key, None)
    if exe:
        proc["executable"] = exe
    pid = to_int(details.pop(pid_key, None))
    if pid is not None:
        proc["pid"] = pid
    return proc


# ---------------------------------------------------------------------------
# Event handlers — each receives (details, extra) and returns a partial doc.
# Handlers pop consumed fields from details; remaining go to catchall.
# ---------------------------------------------------------------------------

def _handle_sysmon_1(details, extra):
    """Sysmon EventID 1 — Process Creation."""
    doc = {"event": {"action": "process-created", "category": ["process"], "type": ["start"], "outcome": "success"}}

    # Process
    proc = _build_process(details)
    cmdline = details.pop("Cmdline", None)
    if cmdline:
        proc["command_line"] = cmdline

    # Hashes
    hashes = parse_hashes(details.pop("Hashes", None))
    if "sha1" in hashes or "md5" in hashes or "sha256" in hashes:
        proc["hash"] = {}
        for algo in ("sha1", "md5", "sha256"):
            if algo in hashes:
                proc["hash"][algo] = hashes[algo]

    # PE metadata
    pe = {}
    for field, ecs_key in (("Description", "description"), ("Product", "product"),
                           ("Company", "company")):
        val = details.pop(field, None)
        if val:
            pe[ecs_key] = val
    if "imphash" in hashes:
        pe["imphash"] = hashes["imphash"]
    if pe:
        proc["pe"] = pe

    # PE original filename from ExtraFieldInfo
    orig_fn = extra.pop("OriginalFileName", None)
    if orig_fn and orig_fn not in ("?", ""):
        pe = proc.get("pe", {})
        pe["original_file_name"] = orig_fn
        proc["pe"] = pe

    # Parent process
    parent = {}
    parent_cmd = details.pop("ParentCmdline", None)
    if parent_cmd:
        parent["command_line"] = parent_cmd
    ppid = to_int(details.pop("ParentPID", None))
    if ppid is not None:
        parent["pid"] = ppid
    # ParentImage from ExtraFieldInfo
    parent_img = extra.pop("ParentImage", None)
    if parent_img:
        parent["executable"] = parent_img
    if parent:
        proc["parent"] = parent

    # Working directory from ExtraFieldInfo
    cwd = extra.pop("CurrentDirectory", None)
    if cwd:
        proc["working_directory"] = cwd

    if proc:
        doc["process"] = proc

    # User
    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    # Winlog logon ID
    lid = details.pop("LID", None)
    if lid:
        doc["winlog"] = {"logon": {"id": lid}}

    _pop_internal(details, "LGUID", "PGUID", "ParentPGUID", "Rule")
    return doc


def _handle_sysmon_3(details, extra):
    """Sysmon EventID 3 — Network Connection."""
    doc = {"event": {"action": "network-connection", "category": ["network"], "type": ["connection"], "outcome": "success"}}

    # Source
    source = {}
    src_ip = details.pop("SrcIP", None)
    if is_valid_ip(src_ip):
        source["ip"] = src_ip
    src_port = to_int(details.pop("SrcPort", None))
    if src_port is not None:
        source["port"] = src_port
    src_host = details.pop("SrcHost", None)
    if src_host:
        source["address"] = src_host
    if source:
        doc["source"] = source

    # Destination
    dest = {}
    dst_ip = details.pop("TgtIP", None)
    if is_valid_ip(dst_ip):
        dest["ip"] = dst_ip
    dst_port = to_int(details.pop("TgtPort", None))
    if dst_port is not None:
        dest["port"] = dst_port
    dst_host = details.pop("TgtHost", None)
    if dst_host:
        dest["address"] = dst_host
    if dest:
        doc["destination"] = dest

    # Network
    network = {}
    proto = details.pop("Proto", None)
    if proto:
        network["transport"] = proto.lower() if isinstance(proto, str) else proto
    initiated = details.pop("Initiated", None)
    if initiated is not None:
        network["direction"] = "outbound" if initiated else "inbound"
    if network:
        doc["network"] = network

    # Process
    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    # User
    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    _pop_internal(details, "PGUID")
    return doc


def _handle_sysmon_5(details, extra):
    """Sysmon EventID 5 — Process Terminated."""
    doc = {"event": {"action": "process-terminated", "category": ["process"], "type": ["end"], "outcome": "success"}}
    proc = _build_process(details)
    if proc:
        doc["process"] = proc
    _pop_internal(details, "PGUID")
    return doc


def _handle_sysmon_6(details, extra):
    """Sysmon EventID 6 — Driver Loaded."""
    doc = {"event": {"action": "driver-loaded", "category": ["driver"], "type": ["start"], "outcome": "success"}}

    f = {}
    path = details.pop("Path", None)
    if path:
        f["path"] = path

    # Hashes
    hashes = parse_hashes(details.pop("Hashes", None))
    if "sha1" in hashes or "md5" in hashes or "sha256" in hashes:
        f["hash"] = {}
        for algo in ("sha1", "md5", "sha256"):
            if algo in hashes:
                f["hash"][algo] = hashes[algo]

    # Code signature
    sig = {}
    signed = details.pop("Signed", None)
    if signed is not None:
        sig["exists"] = bool(signed) if isinstance(signed, bool) else (signed == "true")
    sig_status = details.pop("SigStatus", None)
    if sig_status:
        sig["status"] = sig_status
    if sig:
        f["code_signature"] = sig

    if f:
        doc["file"] = f

    details.pop("Sig", None)  # signer name — no standard ECS field
    return doc


def _handle_sysmon_7(details, extra):
    """Sysmon EventID 7 — Image Loaded (DLL)."""
    doc = {"event": {"action": "dll-loaded", "category": ["process"], "type": ["start"], "outcome": "success"}}

    dll = {}
    image = details.pop("Image", None)
    if image:
        dll["path"] = image

    # PE metadata
    pe = {}
    for field, ecs_key in (("Description", "description"), ("Product", "product"),
                           ("Company", "company")):
        val = details.pop(field, None)
        if val:
            pe[ecs_key] = val
    orig = details.pop("OrigFilename", None)
    if orig and orig != "n/a":
        pe["original_file_name"] = orig

    # Hash
    hashes = parse_hashes(details.pop("Hash", None))
    if "sha1" in hashes or "md5" in hashes or "sha256" in hashes:
        dll["hash"] = {}
        for algo in ("sha1", "md5", "sha256"):
            if algo in hashes:
                dll["hash"][algo] = hashes[algo]
    if "imphash" in hashes:
        pe["imphash"] = hashes["imphash"]
    if pe:
        dll["pe"] = pe

    # Code signature
    sig = {}
    signed = details.pop("Signed", None)
    if signed is not None:
        sig["exists"] = bool(signed) if isinstance(signed, bool) else (signed == "true")
    sig_status = details.pop("Sig", None)
    if sig_status:
        sig["status"] = sig_status
    if sig:
        dll["code_signature"] = sig

    if dll:
        doc["dll"] = dll

    # Process that loaded the DLL
    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    _pop_internal(details, "PGUID", "Rule")
    return doc


def _handle_sysmon_8(details, extra):
    """Sysmon EventID 8 — CreateRemoteThread (injection)."""
    doc = {"event": {"action": "create-remote-thread", "category": ["process"], "type": ["access"], "outcome": "success"}}

    # Source process
    proc = {}
    src_proc = details.pop("SrcProc", None)
    if src_proc:
        proc["executable"] = src_proc
    src_pid = to_int(details.pop("SrcPID", None))
    if src_pid is not None:
        proc["pid"] = src_pid

    # Target process
    target = {}
    tgt_proc = details.pop("TgtProc", None)
    if tgt_proc:
        target["executable"] = tgt_proc
    tgt_pid = to_int(details.pop("TgtPID", None))
    if tgt_pid is not None:
        target["pid"] = tgt_pid

    if target:
        proc["target"] = target
    if proc:
        doc["process"] = proc

    _pop_internal(details, "SrcPGUID", "TgtPGUID")
    return doc


def _handle_sysmon_10(details, extra):
    """Sysmon EventID 10 — Process Access."""
    doc = {"event": {"action": "process-access", "category": ["process"], "type": ["access"], "outcome": "success"}}

    # Source process
    proc = {}
    src_proc = details.pop("SrcProc", None)
    if src_proc:
        proc["executable"] = src_proc
    src_pid = to_int(details.pop("SrcPID", None))
    if src_pid is not None:
        proc["pid"] = src_pid

    # Target process
    target = {}
    tgt_proc = details.pop("TgtProc", None)
    if tgt_proc:
        target["executable"] = tgt_proc
    tgt_pid = to_int(details.pop("TgtPID", None))
    if tgt_pid is not None:
        target["pid"] = tgt_pid
    if target:
        proc["target"] = target
    if proc:
        doc["process"] = proc

    # Access mask stays in Details (useful as-is, but we keep it)
    # details has "Access" which is a hex mask — keep in original_details

    # Users
    user = parse_user(details.pop("SrcUser", None))
    if user:
        doc["user"] = user
    tgt_user = parse_user(details.pop("TgtUser", None))
    if tgt_user:
        doc.setdefault("user", {})["target"] = tgt_user

    _pop_internal(details, "SrcPGUID", "TgtPGUID", "Rule")
    return doc


def _handle_sysmon_11(details, extra):
    """Sysmon EventID 11 — File Created."""
    doc = {"event": {"action": "file-created", "category": ["file"], "type": ["creation"], "outcome": "success"}}

    path = details.pop("Path", None)
    if path:
        doc["file"] = {"path": path}

    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    _pop_internal(details, "PGUID", "Rule")
    return doc


def _handle_sysmon_12(details, extra):
    """Sysmon EventID 12 — Registry Object Create/Delete."""
    doc = {"event": {"category": ["registry"], "type": ["change"], "outcome": "success"}}

    event_type = details.pop("EventType", None)
    if event_type:
        doc["event"]["action"] = event_type

    tgt_obj = details.pop("TgtObj", None)
    if tgt_obj:
        doc["registry"] = {"path": tgt_obj}

    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    _pop_internal(details, "PGUID", "Rule")
    return doc


def _handle_sysmon_13(details, extra):
    """Sysmon EventID 13 — Registry Value Set."""
    doc = {"event": {"category": ["registry"], "type": ["change"], "outcome": "success"}}

    event_type = details.pop("EventType", None)
    if event_type:
        doc["event"]["action"] = event_type

    reg = {}
    tgt_obj = details.pop("TgtObj", None)
    reg_key = details.pop("RegKey", None)
    if tgt_obj:
        reg["path"] = tgt_obj
    elif reg_key:
        reg["path"] = reg_key

    # The registry value data — may come from the renamed empty key or "Details"
    reg_value = details.pop("_value", None)
    reg_details = details.pop("Details", None)
    value = reg_value or reg_details
    if value:
        reg["data"] = {"strings": value}

    if reg:
        doc["registry"] = reg

    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    _pop_internal(details, "PGUID", "Rule")
    return doc


def _handle_sysmon_17(details, extra):
    """Sysmon EventID 17 — Pipe Created."""
    doc = {"event": {"action": "pipe-created", "category": ["file"], "type": ["creation"], "outcome": "success"}}

    pipe = details.pop("Pipe", None)
    if pipe:
        doc["file"] = {"name": pipe}

    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    _pop_internal(details, "PGUID", "Rule")
    return doc


def _handle_sysmon_18(details, extra):
    """Sysmon EventID 18 — Pipe Connected."""
    doc = {"event": {"action": "pipe-connected", "category": ["file"], "type": ["access"], "outcome": "success"}}

    pipe = details.pop("Pipe", None)
    if pipe:
        doc["file"] = {"name": pipe}

    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    _pop_internal(details, "PGUID", "Rule")
    return doc


def _handle_sec_4624(details, extra):
    """Security EventID 4624 — Logon Success."""
    doc = {"event": {"action": "logon-success", "category": ["authentication"], "type": ["start"], "outcome": "success"}}

    # Logon type
    winlog = {"logon": {}}
    type_str = details.pop("Type", None)
    logon_code = None
    if type_str:
        logon_code, label = parse_logon_type(str(type_str))
        if logon_code:
            winlog["logon"]["type"] = logon_code
    lid = details.pop("LID", None)
    if lid:
        winlog["logon"]["id"] = lid
    if winlog["logon"]:
        doc["winlog"] = winlog

    # Enrich category and network.protocol based on logon type
    if logon_code == "10":
        doc["event"]["category"].append("network")
        doc["network"] = {"protocol": "rdp"}
    elif logon_code == "3":
        doc["event"]["category"].append("network")

    # User who logged on — populate both user.* and user.target.*
    tgt_user = parse_user(details.pop("TgtUser", None))
    if tgt_user:
        tgt_domain = extra.pop("TargetDomainName", None)
        if tgt_domain and tgt_domain != "-":
            tgt_user["domain"] = tgt_domain
        tgt_sid = extra.pop("TargetUserSid", None)
        if tgt_sid and tgt_sid != "S-1-0-0":
            tgt_user["id"] = tgt_sid
        doc["user"] = dict(tgt_user)
        doc["user"]["target"] = tgt_user

    # Source
    source = {}
    src_ip = details.pop("SrcIP", None)
    if is_valid_ip(src_ip):
        source["ip"] = src_ip
    src_comp = details.pop("SrcComp", None)
    if src_comp:
        source["address"] = src_comp
    src_port = to_int(extra.pop("IpPort", None))
    if src_port is not None:
        source["port"] = src_port
    if source:
        doc["source"] = source

    return doc


def _handle_sec_4672(details, extra):
    """Security EventID 4672 — Special Privileges Assigned."""
    doc = {"event": {"action": "special-privileges-assigned", "category": ["iam"], "type": ["admin"], "outcome": "success"}}

    tgt_user = parse_user(details.pop("TgtUser", None))
    if tgt_user:
        subj_domain = extra.pop("SubjectDomainName", None)
        if subj_domain and subj_domain != "-":
            tgt_user["domain"] = subj_domain
        subj_sid = extra.pop("SubjectUserSid", None)
        if subj_sid and subj_sid != "S-1-0-0":
            tgt_user["id"] = subj_sid
        doc["user"] = dict(tgt_user)
        doc["user"]["target"] = tgt_user

    lid = details.pop("LID", None)
    if lid:
        doc["winlog"] = {"logon": {"id": lid}}

    return doc


def _handle_sec_4688(details, extra):
    """Security EventID 4688 — Process Creation."""
    doc = {"event": {"action": "process-created", "category": ["process"], "type": ["start"], "outcome": "success"}}

    proc = _build_process(details)
    cmdline = details.pop("Cmdline", None)
    if cmdline:
        proc["command_line"] = cmdline
    if proc:
        doc["process"] = proc

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    lid = details.pop("LID", None)
    if lid:
        doc["winlog"] = {"logon": {"id": lid}}

    return doc


def _handle_sec_4768(details, extra):
    """Security EventID 4768 — Kerberos TGT Request."""
    doc = {"event": {"action": "kerberos-tgt-request", "category": ["authentication"], "type": ["start"]}}

    tgt_user = parse_user(details.pop("TgtUser", None))
    if tgt_user:
        doc["user"] = dict(tgt_user)
        doc["user"]["target"] = tgt_user

    src_ip = details.pop("SrcIP", None)
    if is_valid_ip(src_ip):
        doc["source"] = {"ip": src_ip}

    status = details.pop("Status", None)
    if status:
        doc["event"]["outcome"] = "success" if status == "0x0" else "failure"

    details.pop("Svc", None)
    details.pop("PreAuthType", None)
    return doc


def _handle_sec_4776(details, extra):
    """Security EventID 4776 — Credential Validation."""
    doc = {"event": {"action": "credential-validation", "category": ["authentication"], "type": ["start"]}}

    tgt_user = parse_user(details.pop("TgtUser", None))
    if tgt_user:
        doc["user"] = dict(tgt_user)
        doc["user"]["target"] = tgt_user

    src_comp = details.pop("SrcComp", None)
    if src_comp:
        doc["source"] = {"address": src_comp}

    status = details.pop("Status", None)
    if status:
        doc["event"]["outcome"] = "success" if status == "0x0" else "failure"

    return doc


def _handle_sec_5136(details, extra):
    """Security EventID 5136 — Directory Service Object Modified."""
    doc = {"event": {"action": "directory-service-object-modified", "category": ["configuration"], "type": ["change"], "outcome": "success"}}

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    lid = details.pop("LID", None)
    if lid:
        doc["winlog"] = {"logon": {"id": lid}}

    # Keep SID, ObjDN, AttrLDAPName, OpType in original_details — domain-specific
    return doc


def _handle_sec_5145(details, extra):
    """Security EventID 5145 — Network Share Object Access."""
    doc = {"event": {"action": "network-share-access", "category": ["file", "network"], "type": ["access"], "outcome": "success"},
           "network": {"protocol": "smb"}}

    user = parse_user(details.pop("SrcUser", None))
    if user:
        doc["user"] = user

    src_ip = details.pop("SrcIP", None)
    if is_valid_ip(src_ip):
        doc["source"] = {"ip": src_ip}

    f = {}
    path = details.pop("Path", None)
    if path:
        f["path"] = path
    share_name = details.pop("ShareName", None)
    if share_name:
        f["share_name"] = share_name
    if f:
        doc["file"] = f

    lid = details.pop("LID", None)
    if lid:
        doc["winlog"] = {"logon": {"id": lid}}

    details.pop("SharePath", None)  # raw share path, redundant with share_name
    return doc


def _handle_sec_5156(details, extra):
    """Security EventID 5156 — WFP Connection Allowed."""
    doc = {"event": {"action": "network-connection-allowed", "category": ["network"], "type": ["connection"], "outcome": "success"}}

    # Source
    source = {}
    src_ip = details.pop("SrcIP", None)
    if is_valid_ip(src_ip):
        source["ip"] = src_ip
    src_port = to_int(details.pop("SrcPort", None))
    if src_port is not None:
        source["port"] = src_port
    if source:
        doc["source"] = source

    # Destination
    dest = {}
    dst_ip = details.pop("TgtIP", None)
    if is_valid_ip(dst_ip):
        dest["ip"] = dst_ip
    dst_port = to_int(details.pop("TgtPort", None))
    if dst_port is not None:
        dest["port"] = dst_port
    if dest:
        doc["destination"] = dest

    # Protocol (numeric in Sec/5156)
    protocol = details.pop("Protocol", None)
    if protocol is not None:
        transport = PROTO_MAP.get(protocol, str(protocol))
        doc["network"] = {"transport": transport}

    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    details.pop("TgtMachineID", None)
    details.pop("TgtSID", None)
    return doc


def _handle_bitscli_59(details, extra):
    """BITS Client EventID 59 — BITS Job Created."""
    doc = {"event": {"action": "bits-transfer", "category": ["network"], "type": ["protocol"], "outcome": "success"}}

    url = details.pop("URL", None)
    if url:
        doc["url"] = {"original": url}

    details.pop("JobTitle", None)  # no standard ECS field
    return doc


def _handle_pwsh_4104(details, extra):
    """PowerShell EventID 4104 — ScriptBlock Logging."""
    doc = {"event": {"action": "powershell-scriptblock", "category": ["process"], "type": ["info"], "outcome": "success"}}

    script = details.pop("ScriptBlock", None)
    if script:
        doc["powershell"] = {"file": {"script_block_text": script}}

    return doc


def _handle_defender_1116(details, extra):
    """Defender EventID 1116 — Malware Detection."""
    doc = {"event": {"action": "malware-detected", "category": ["malware"], "type": ["info"], "outcome": "success"}}

    threat = details.pop("Threat", None)
    if threat:
        doc["threat"] = {"indicator": {"description": threat}}

    path = details.pop("Path", None)
    if path:
        doc["file"] = {"path": path}

    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    details.pop("Severity", None)  # already in event.severity from Hayabusa Level
    details.pop("Type", None)
    return doc


def _handle_rds_rcm_1149(details, extra):
    """RDS-RCM EventID 1149 — RDP Logon."""
    doc = {"event": {"action": "rdp-connection", "category": ["authentication", "network"], "type": ["start"], "outcome": "success"},
           "network": {"protocol": "rdp"}}

    tgt_user = details.pop("TgtUser", None)
    domain = details.pop("Domain", None)
    if tgt_user:
        user_target = {"name": tgt_user}
        if domain:
            user_target["domain"] = domain
        doc["user"] = dict(user_target)
        doc["user"]["target"] = user_target

    src_ip = details.pop("SrcIP", None)
    if is_valid_ip(src_ip):
        doc["source"] = {"ip": src_ip}

    return doc


def _handle_sys_7045(details, extra):
    """System EventID 7045 — Service Installed."""
    doc = {"event": {"action": "service-installed", "category": ["configuration"], "type": ["creation"], "outcome": "success"}}

    svc = details.pop("Svc", None)
    if svc:
        doc["service"] = {"name": svc}

    path = details.pop("Path", None)
    if path:
        doc["file"] = {"path": path}

    acct = details.pop("Acct", None)
    if acct:
        doc["user"] = parse_user(acct) or {"name": acct}

    details.pop("StartType", None)
    return doc


def _handle_sec_4625(details, extra):
    """Security EventID 4625 — Logon Failure."""
    doc = {"event": {"action": "logon-failure", "category": ["authentication"], "type": ["start"], "outcome": "failure"}}

    winlog = {"logon": {}}
    type_str = details.pop("Type", None)
    logon_code = None
    if type_str:
        logon_code, label = parse_logon_type(str(type_str))
        if logon_code:
            winlog["logon"]["type"] = logon_code
    lid = details.pop("LID", None)
    if lid:
        winlog["logon"]["id"] = lid
    if winlog["logon"]:
        doc["winlog"] = winlog

    if logon_code == "10":
        doc["event"]["category"].append("network")
        doc["network"] = {"protocol": "rdp"}
    elif logon_code == "3":
        doc["event"]["category"].append("network")

    tgt_user = parse_user(details.pop("TgtUser", None))
    if tgt_user:
        tgt_domain = extra.pop("TargetDomainName", None)
        if tgt_domain and tgt_domain != "-":
            tgt_user["domain"] = tgt_domain
        tgt_sid = extra.pop("TargetUserSid", None)
        if tgt_sid and tgt_sid != "S-1-0-0":
            tgt_user["id"] = tgt_sid
        doc["user"] = dict(tgt_user)
        doc["user"]["target"] = tgt_user

    source = {}
    src_ip = details.pop("SrcIP", None)
    if is_valid_ip(src_ip):
        source["ip"] = src_ip
    src_comp = details.pop("SrcComp", None)
    if src_comp:
        source["address"] = src_comp
    src_port = to_int(extra.pop("IpPort", None))
    if src_port is not None:
        source["port"] = src_port
    if source:
        doc["source"] = source

    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    details.pop("AuthPkg", None)
    details.pop("SubStatus", None)
    return doc


def _handle_sec_4634(details, extra):
    """Security EventID 4634 — Logoff."""
    doc = {"event": {"action": "logoff", "category": ["authentication"], "type": ["end"], "outcome": "success"}}

    user = parse_user(details.pop("User", None))
    if user:
        tgt_domain = extra.pop("TargetDomainName", None)
        if tgt_domain and tgt_domain != "-":
            user["domain"] = tgt_domain
        tgt_sid = extra.pop("TargetUserSid", None)
        if tgt_sid and tgt_sid != "S-1-0-0":
            user["id"] = tgt_sid
        doc["user"] = user

    winlog = {"logon": {}}
    lid = details.pop("LID", None)
    if lid:
        winlog["logon"]["id"] = lid
    type_val = details.pop("Type", None)
    logon_code = None
    if type_val is not None:
        logon_code, label = parse_logon_type(str(type_val))
        if logon_code:
            winlog["logon"]["type"] = logon_code
    if winlog["logon"]:
        doc["winlog"] = winlog

    if logon_code == "10":
        doc["event"]["category"].append("network")
        doc["network"] = {"protocol": "rdp"}
    elif logon_code == "3":
        doc["event"]["category"].append("network")

    return doc


def _handle_sec_4648(details, extra):
    """Security EventID 4648 — Explicit Logon (runas, network auth)."""
    doc = {"event": {"action": "explicit-logon", "category": ["authentication"], "type": ["start"], "outcome": "success"}}

    tgt_user = parse_user(details.pop("TgtUser", None))
    if tgt_user:
        doc["user"] = {"target": tgt_user}

    src_user = parse_user(details.pop("SrcUser", None))
    if src_user:
        doc["user"] = doc.get("user", {})
        doc["user"].update(src_user)

    source = {}
    src_ip = details.pop("SrcIP", None)
    if is_valid_ip(src_ip):
        source["ip"] = src_ip
    if source:
        doc["source"] = source

    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    details.pop("TgtSvr", None)
    return doc


def _handle_sec_5379(details, extra):
    """Security EventID 5379 — Credential Manager Accessed."""
    doc = {"event": {"action": "credential-manager-access", "category": ["iam"], "type": ["access"], "outcome": "success"}}

    user = parse_user(details.pop("SrcUser", None))
    if user:
        subj_domain = extra.pop("SubjectDomainName", None)
        if subj_domain and subj_domain != "-":
            user["domain"] = subj_domain
        doc["user"] = user

    pid = to_int(details.pop("PID", None))
    if pid is not None:
        doc["process"] = {"pid": pid}

    lid = details.pop("LID", None)
    if lid:
        doc["winlog"] = {"logon": {"id": lid}}

    details.pop("SrcSID", None)
    details.pop("Tgt", None)
    details.pop("CredsReturned", None)
    details.pop("ReturnCode", None)
    return doc


def _handle_tasksch_106(details, extra):
    """Task Scheduler EventID 106 — Task Created."""
    doc = {"event": {"action": "scheduled-task-created", "category": ["configuration"], "type": ["creation"], "outcome": "success"}}

    name = details.pop("Name", None)
    if name:
        doc["task"] = {"name": name}

    user = parse_user(details.pop("UserContext", None))
    if user:
        doc["user"] = user

    return doc


def _handle_tasksch_140(details, extra):
    """Task Scheduler EventID 140 — Task Updated."""
    doc = {"event": {"action": "scheduled-task-updated", "category": ["configuration"], "type": ["change"], "outcome": "success"}}

    name = details.pop("Name", None)
    if name:
        doc["task"] = {"name": name}

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    return doc


def _handle_tasksch_141(details, extra):
    """Task Scheduler EventID 141 — Task Deleted."""
    doc = {"event": {"action": "scheduled-task-deleted", "category": ["configuration"], "type": ["deletion"], "outcome": "success"}}

    name = details.pop("Name", None)
    if name:
        doc["task"] = {"name": name}

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    return doc


def _handle_tasksch_200(details, extra):
    """Task Scheduler EventID 200 — Task Executed."""
    doc = {"event": {"action": "scheduled-task-executed", "category": ["process"], "type": ["start"], "outcome": "success"}}

    name = details.pop("Name", None)
    if name:
        doc["task"] = {"name": name}

    action = details.pop("Action", None)
    if action:
        doc["process"] = {"executable": action, "command_line": action}

    return doc


def _handle_pwsh_classic_400(details, extra):
    """PowerShell Classic EventID 400 — Engine Started."""
    doc = {"event": {"action": "powershell-engine-started", "category": ["process"], "type": ["start"], "outcome": "success"}}

    host_app = details.pop("HostApplication", None)
    if host_app:
        # Extract executable from first token of command line
        exe = host_app.split()[0] if host_app.split() else host_app
        doc["process"] = {"executable": exe, "command_line": host_app}

    details.pop("CommandLine", None)
    details.pop("CommandName", None)
    details.pop("CommandPath", None)
    details.pop("CommandType", None)
    details.pop("EngineVersion", None)
    details.pop("HostId", None)
    # Clean up Data[N] keys
    for k in list(details):
        if k.startswith("Data["):
            details.pop(k)
    return doc


def _handle_pwsh_classic_600(details, extra):
    """PowerShell Classic EventID 600 — Provider Started."""
    doc = {"event": {"action": "powershell-provider-started", "category": ["process"], "type": ["start"], "outcome": "success"}}

    host_app = details.pop("HostApplication", None)
    if host_app:
        exe = host_app.split()[0] if host_app.split() else host_app
        doc["process"] = {"executable": exe, "command_line": host_app}

    details.pop("CommandLine", None)
    details.pop("CommandName", None)
    details.pop("CommandPath", None)
    details.pop("CommandType", None)
    details.pop("EngineVersion", None)
    details.pop("HostId", None)
    for k in list(details):
        if k.startswith("Data["):
            details.pop(k)
    return doc


def _handle_sys_7023(details, extra):
    """System EventID 7023 — Service Terminated With Error."""
    doc = {"event": {"action": "service-error", "category": ["process"], "type": ["end"], "outcome": "failure"}}

    svc = details.pop("Svc", None)
    if svc:
        doc["service"] = {"name": svc}

    details.pop("Error", None)
    return doc


def _handle_sys_7034(details, extra):
    """System EventID 7034 — Service Crashed."""
    doc = {"event": {"action": "service-crashed", "category": ["process"], "type": ["end"], "outcome": "failure"}}

    svc = details.pop("Svc", None)
    if svc:
        doc["service"] = {"name": svc}

    details.pop("CrashCount", None)
    return doc


def _handle_rds_lsm_21(details, extra):
    """RDS-LSM EventID 21 — RDP Logon."""
    doc = {"event": {"action": "rdp-logon", "category": ["authentication", "network"], "type": ["start"], "outcome": "success"},
           "network": {"protocol": "rdp"}}

    tgt_user = parse_user(details.pop("TgtUser", None))
    if tgt_user:
        doc["user"] = dict(tgt_user)
        doc["user"]["target"] = tgt_user

    src_ip = details.pop("SrcIP", None)
    if is_valid_ip(src_ip) and src_ip != "LOCALE":
        doc["source"] = {"ip": src_ip}

    details.pop("SessID", None)
    return doc


def _handle_rds_lsm_23(details, extra):
    """RDS-LSM EventID 23 — RDP Logoff."""
    doc = {"event": {"action": "rdp-logoff", "category": ["authentication", "network"], "type": ["end"], "outcome": "success"},
           "network": {"protocol": "rdp"}}

    tgt_user = parse_user(details.pop("TgtUser", None))
    if tgt_user:
        doc["user"] = dict(tgt_user)
        doc["user"]["target"] = tgt_user

    details.pop("SessID", None)
    return doc


def _handle_rds_lsm_24(details, extra):
    """RDS-LSM EventID 24 — RDP Disconnect."""
    doc = {"event": {"action": "rdp-disconnect", "category": ["network"], "type": ["end"], "outcome": "success"},
           "network": {"protocol": "rdp"}}

    tgt_user = parse_user(details.pop("TgtUser", None))
    if tgt_user:
        doc["user"] = dict(tgt_user)
        doc["user"]["target"] = tgt_user

    src_ip = details.pop("SrcIP", None)
    if is_valid_ip(src_ip) and src_ip != "LOCALE":
        doc["source"] = {"ip": src_ip}

    details.pop("SessID", None)
    return doc


def _handle_rdp_cli_1024(details, extra):
    """RDP Client EventID 1024 — RDP Connection Attempt."""
    doc = {"event": {"action": "rdp-connection-attempt", "category": ["network"], "type": ["start"]},
           "network": {"protocol": "rdp"}}

    tgt_ip = details.pop("TgtIP", None)
    if tgt_ip:
        doc["destination"] = {"address": tgt_ip}

    return doc


def _handle_rdp_cli_1102(details, extra):
    """RDP Client EventID 1102 — RDP Connection Attempt."""
    doc = {"event": {"action": "rdp-connection-attempt", "category": ["network"], "type": ["start"]},
           "network": {"protocol": "rdp"}}

    tgt_ip = details.pop("TgtIP", None)
    if tgt_ip:
        doc["destination"] = {"address": tgt_ip}

    return doc


def _handle_wmi_5857(details, extra):
    """WMI EventID 5857 — WMI Provider Started."""
    doc = {"event": {"action": "wmi-provider-started", "category": ["process"], "type": ["start"], "outcome": "success"}}

    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    path = details.pop("Path", None)
    if path:
        doc["file"] = {"path": path}

    details.pop("Provider", None)
    details.pop("Result", None)
    return doc


def _handle_wmi_5860(details, extra):
    """WMI EventID 5860 — Temporary WMI Event Consumer."""
    doc = {"event": {"action": "wmi-temporary-consumer", "category": ["configuration"], "type": ["creation"], "outcome": "success"}}

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    pid = to_int(details.pop("PID", None))
    if pid is not None:
        doc["process"] = {"pid": pid}

    details.pop("Namespace", None)
    details.pop("Query", None)
    return doc


def _handle_smb_conn_30803(details, extra):
    """SMB Client Connectivity EventID 30803 — SMB Connection."""
    doc = {"event": {"action": "smb-connection", "category": ["network"], "type": ["connection"]},
           "network": {"protocol": "smb"}}

    server = details.pop("ServerName", None)
    if server:
        doc["destination"] = {"address": server}

    # Clean up all SMB-specific fields
    for k in list(details):
        details.pop(k)
    return doc


def _handle_sec_4720(details, extra):
    """Security EventID 4720 — User Account Created."""
    doc = {"event": {"action": "user-account-created", "category": ["iam"], "type": ["creation"], "outcome": "success"}}

    # Subject (who created the account) from ExtraFieldInfo
    subj_user = extra.pop("SubjectUserName", None)
    subj_domain = extra.pop("SubjectDomainName", None)
    if subj_user:
        user = {"name": subj_user}
        if subj_domain and subj_domain != "-":
            user["domain"] = subj_domain
        doc["user"] = user

    # Target (the account that was created)
    tgt_user = parse_user(details.pop("TgtUser", None))
    if tgt_user:
        tgt_domain = extra.pop("TargetDomainName", None)
        if tgt_domain and tgt_domain != "-":
            tgt_user["domain"] = tgt_domain
        doc.setdefault("user", {})["target"] = tgt_user

    details.pop("TgtSID", None)
    return doc


def _handle_sec_4724(details, extra):
    """Security EventID 4724 — Password Reset."""
    doc = {"event": {"action": "password-reset", "category": ["iam"], "type": ["change"], "outcome": "success"}}

    # Who reset the password
    subj_user = details.pop("SubjectUserName", None)
    subj_domain = details.pop("SubjectDomainName", None)
    if subj_user:
        user = {"name": subj_user}
        if subj_domain:
            user["domain"] = subj_domain
        doc["user"] = user

    # Whose password was reset
    tgt_user = details.pop("TargetUserName", None)
    tgt_domain = details.pop("TargetDomainName", None)
    if tgt_user:
        target = {"name": tgt_user}
        if tgt_domain:
            target["domain"] = tgt_domain
        doc.setdefault("user", {})["target"] = target

    details.pop("SubjectUserSid", None)
    details.pop("SubjectLogonId", None)
    details.pop("TargetSid", None)
    return doc


def _handle_sec_4732(details, extra):
    """Security EventID 4732 — User Added to Group."""
    doc = {"event": {"action": "user-added-to-group", "category": ["iam"], "type": ["change"], "outcome": "success"}}

    grp = details.pop("TgtGrp", None)
    if grp:
        doc["group"] = {"name": grp}

    lid = details.pop("LID", None)
    if lid:
        doc["winlog"] = {"logon": {"id": lid}}

    details.pop("SrcSID", None)
    return doc


def _handle_sec_4647(details, extra):
    """Security EventID 4647 — User Initiated Logoff."""
    doc = {"event": {"action": "logoff", "category": ["authentication"], "type": ["end"], "outcome": "success"}}

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    lid = details.pop("LID", None)
    if lid:
        doc["winlog"] = {"logon": {"id": lid}}

    return doc


def _handle_sec_4661(details, extra):
    """Security EventID 4661 — AD Object Accessed."""
    doc = {"event": {"action": "ad-object-access", "category": ["iam"], "type": ["access"], "outcome": "success"}}

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    lid = details.pop("LID", None)
    if lid:
        doc["winlog"] = {"logon": {"id": lid}}

    details.pop("ObjSvr", None)
    details.pop("ObjType", None)
    details.pop("ObjName", None)
    return doc


def _handle_sec_4697(details, extra):
    """Security EventID 4697 — Service Installed (Security log)."""
    doc = {"event": {"action": "service-installed", "category": ["configuration"], "type": ["creation"], "outcome": "success"}}

    svc = details.pop("Svc", None)
    if svc:
        doc["service"] = {"name": svc}

    path = details.pop("Path", None)
    if path:
        doc["file"] = {"path": path}

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    lid = details.pop("LID", None)
    if lid:
        doc["winlog"] = {"logon": {"id": lid}}

    details.pop("SvcAcct", None)
    details.pop("SvcType", None)
    details.pop("SvcStartType", None)
    return doc


def _handle_sec_4728(details, extra):
    """Security EventID 4728 — Member Added to Security-Enabled Global Group."""
    doc = {"event": {"action": "user-added-to-group", "category": ["iam"], "type": ["change"], "outcome": "success"}}

    grp = details.pop("TgtGrp", None)
    if grp:
        doc["group"] = {"name": grp}

    lid = details.pop("LID", None)
    if lid:
        doc["winlog"] = {"logon": {"id": lid}}

    details.pop("SrcSID", None)
    return doc


def _handle_sec_4769(details, extra):
    """Security EventID 4769 — Kerberos Service Ticket Requested."""
    doc = {"event": {"action": "kerberos-tgs-request", "category": ["authentication"], "type": ["start"]}}

    tgt_user = parse_user(details.pop("TgtUser", None))
    if tgt_user:
        doc["user"] = dict(tgt_user)
        doc["user"]["target"] = tgt_user

    src_ip = details.pop("SrcIP", None)
    if is_valid_ip(src_ip):
        doc["source"] = {"ip": src_ip}

    status = details.pop("Status", None)
    if status:
        doc["event"]["outcome"] = "success" if status == "0x0" else "failure"

    details.pop("Svc", None)
    return doc


def _handle_sec_5140(details, extra):
    """Security EventID 5140 — Network Share Accessed."""
    doc = {"event": {"action": "network-share-access", "category": ["file", "network"], "type": ["access"], "outcome": "success"},
           "network": {"protocol": "smb"}}

    user = parse_user(details.pop("SrcUser", None))
    if user:
        doc["user"] = user

    src_ip = details.pop("SrcIP", None)
    if is_valid_ip(src_ip):
        doc["source"] = {"ip": src_ip}

    share_name = details.pop("ShareName", None)
    if share_name:
        doc["file"] = {"share_name": share_name}

    lid = details.pop("LID", None)
    if lid:
        doc["winlog"] = {"logon": {"id": lid}}

    details.pop("SharePath", None)
    return doc


def _handle_sec_5157(details, extra):
    """Security EventID 5157 — WFP Connection Blocked."""
    doc = {"event": {"action": "network-connection-blocked", "category": ["network"], "type": ["denied"], "outcome": "failure"}}

    source = {}
    src_ip = details.pop("SrcIP", None)
    if is_valid_ip(src_ip):
        source["ip"] = src_ip
    src_port = to_int(details.pop("SrcPort", None))
    if src_port is not None:
        source["port"] = src_port
    if source:
        doc["source"] = source

    dest = {}
    dst_ip = details.pop("TgtIP", None)
    if is_valid_ip(dst_ip):
        dest["ip"] = dst_ip
    dst_port = to_int(details.pop("TgtPort", None))
    if dst_port is not None:
        dest["port"] = dst_port
    if dest:
        doc["destination"] = dest

    protocol = details.pop("Protocol", None)
    if protocol is not None:
        doc["network"] = {"transport": PROTO_MAP.get(protocol, str(protocol))}

    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    details.pop("TgtMachineID", None)
    details.pop("TgtSID", None)
    return doc


def _handle_sec_4616(details, extra):
    """Security EventID 4616 — System Time Changed."""
    doc = {"event": {"action": "system-time-changed", "category": ["configuration"], "type": ["change"], "outcome": "success"}}

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    lid = details.pop("LID", None)
    if lid:
        doc["winlog"] = {"logon": {"id": lid}}

    details.pop("PrevTime", None)
    details.pop("NewTime", None)
    return doc


def _handle_sec_1102(details, extra):
    """Security EventID 1102 — Security Log Cleared."""
    doc = {"event": {"action": "log-cleared", "category": ["configuration"], "type": ["deletion"], "outcome": "success"}}

    user_name = details.pop("SubjectUserName", None)
    user_domain = details.pop("SubjectDomainName", None)
    if user_name:
        user = {"name": user_name}
        if user_domain:
            user["domain"] = user_domain
        doc["user"] = user

    details.pop("SubjectUserSid", None)
    details.pop("SubjectLogonId", None)
    details.pop("xmlns", None)
    return doc


def _handle_sys_104(details, extra):
    """System EventID 104 — Event Log Cleared."""
    doc = {"event": {"action": "log-cleared", "category": ["configuration"], "type": ["deletion"], "outcome": "success"}}

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    details.pop("Log", None)
    return doc


def _handle_sys_7031(details, extra):
    """System EventID 7031 — Service Crashed (with recovery action)."""
    doc = {"event": {"action": "service-crashed", "category": ["process"], "type": ["end"], "outcome": "failure"}}

    svc = details.pop("Svc", None)
    if svc:
        doc["service"] = {"name": svc}

    details.pop("CrashCount", None)
    details.pop("Action", None)
    return doc


def _handle_pwsh_4103(details, extra):
    """PowerShell EventID 4103 — Pipeline Execution."""
    doc = {"event": {"action": "powershell-pipeline", "category": ["process"], "type": ["info"], "outcome": "success"}}

    payload = details.pop("Payload", None)
    if payload:
        doc["powershell"] = {"file": {"script_block_text": payload}}

    return doc


def _handle_firewall_2002(details, extra):
    """Windows Firewall EventID 2002 — Settings Changed."""
    doc = {"event": {"action": "firewall-settings-changed", "category": ["configuration"], "type": ["change"], "outcome": "success"}}

    for k in list(details):
        details.pop(k)
    return doc


def _handle_firewall_2005(details, extra):
    """Windows Firewall EventID 2005 — Rule Modified."""
    doc = {"event": {"action": "firewall-rule-modified", "category": ["configuration"], "type": ["change"], "outcome": "success"}}

    for k in list(details):
        details.pop(k)
    return doc


def _handle_firewall_2006(details, extra):
    """Windows Firewall EventID 2006 — Rule Deleted."""
    doc = {"event": {"action": "firewall-rule-deleted", "category": ["configuration"], "type": ["deletion"], "outcome": "success"}}

    details.pop("RuleName", None)
    details.pop("RuleId", None)
    details.pop("ModifyingApplication", None)
    details.pop("ModifyingUser", None)
    return doc


# --- Low-value but high-volume handlers (clean up Details, set category) ---

def _handle_partition_1006(details, extra):
    """MS-Win-Partition EventID 1006 — Device Connected."""
    doc = {"event": {"action": "device-connected", "category": ["host"], "type": ["info"], "outcome": "success"}}
    for k in list(details):
        details.pop(k)
    return doc


def _handle_ntfs_4(details, extra):
    """MS-Win-Ntfs EventID 4 — NTFS Volume Mounted."""
    doc = {"event": {"action": "volume-mounted", "category": ["host"], "type": ["info"], "outcome": "success"}}
    for k in list(details):
        details.pop(k)
    return doc


def _handle_oalerts_300(details, extra):
    """OAlerts EventID 300 — Office App Popup."""
    doc = {"event": {"action": "office-popup", "category": ["process"], "type": ["info"], "outcome": "success"}}

    app = details.pop("App", None)
    if app:
        app = app.strip().rstrip("\n")
        doc["process"] = {"name": app}

    msg = details.pop("Msg", None)
    if msg:
        doc["message"] = msg.strip().rstrip("\n")

    details.pop("Ver", None)
    return doc


def _handle_app_install(details, extra):
    """Application EventID 1022/1033 — Application Installed."""
    doc = {"event": {"action": "application-installed", "category": ["package"], "type": ["installation"], "outcome": "success"}}
    for k in list(details):
        details.pop(k)
    return doc


def _handle_app_uninstall(details, extra):
    """Application EventID 1034/11724 — Application Uninstalled."""
    doc = {"event": {"action": "application-removed", "category": ["package"], "type": ["deletion"], "outcome": "success"}}
    for k in list(details):
        details.pop(k)
    return doc


def _handle_codeintegrity_3033(details, extra):
    """CodeIntegrity EventID 3033 — Unsigned Code Loaded."""
    doc = {"event": {"action": "code-integrity-violation", "category": ["process"], "type": ["info"], "outcome": "failure"}}
    for k in list(details):
        details.pop(k)
    return doc


def _handle_sys_20001(details, extra):
    """System EventID 20001 — New PnP Device."""
    doc = {"event": {"action": "device-connected", "category": ["host"], "type": ["info"], "outcome": "success"}}
    for k in list(details):
        details.pop(k)
    return doc


def _handle_defender_1013(details, extra):
    """Defender EventID 1013 — Malware History Deleted."""
    doc = {"event": {"action": "malware-history-deleted", "category": ["malware"], "type": ["deletion"], "outcome": "success"}}

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    for k in list(details):
        details.pop(k)
    return doc


def _handle_sys_boot(details, extra):
    """System EventID 6005/6009/12 — System Startup."""
    doc = {"event": {"action": "system-startup", "category": ["host"], "type": ["start"], "outcome": "success"}}
    for k in list(details):
        details.pop(k)
    return doc


def _handle_sys_shutdown(details, extra):
    """System EventID 6006 — System Shutdown."""
    doc = {"event": {"action": "system-shutdown", "category": ["host"], "type": ["end"], "outcome": "success"}}
    for k in list(details):
        details.pop(k)
    return doc


def _handle_sys_6013(details, extra):
    """System EventID 6013 — System Uptime."""
    doc = {"event": {"action": "system-uptime", "category": ["host"], "type": ["info"], "outcome": "success"}}
    for k in list(details):
        details.pop(k)
    return doc


def _handle_sys_98(details, extra):
    """System EventID 98 — Volume Shadow Copy Mount."""
    doc = {"event": {"action": "vss-mount", "category": ["host"], "type": ["info"], "outcome": "success"}}
    for k in list(details):
        details.pop(k)
    return doc


def _handle_sysmon_2(details, extra):
    """Sysmon EventID 2 — File Creation Time Changed (Timestomping)."""
    doc = {"event": {"action": "file-time-changed", "category": ["file"], "type": ["change"], "outcome": "success"}}

    path = details.pop("Path", None)
    if path:
        doc["file"] = {"path": path}

    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    details.pop("CreateTime", None)
    details.pop("PrevTime", None)
    _pop_internal(details, "PGUID")
    return doc


def _handle_sysmon_wmi(details, extra):
    """Sysmon EventID 19/20/21 — WMI Event Filter/Consumer/Binding."""
    doc = {"event": {"action": "wmi-persistence", "category": ["configuration"], "type": ["creation"], "outcome": "success"}}

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    for k in list(details):
        details.pop(k)
    return doc


def _handle_sysmon_23(details, extra):
    """Sysmon EventID 23 — File Deleted."""
    doc = {"event": {"action": "file-deleted", "category": ["file"], "type": ["deletion"], "outcome": "success"}}

    path = details.pop("Path", None)
    if path:
        doc["file"] = {"path": path}

    proc = _build_process(details)
    if proc:
        doc["process"] = proc

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    _pop_internal(details, "PGUID")
    return doc


def _handle_sec_4698(details, extra):
    """Security EventID 4698 — Scheduled Task Created."""
    doc = {"event": {"action": "scheduled-task-created", "category": ["configuration"], "type": ["creation"], "outcome": "success"}}

    name = details.pop("Name", None)
    if name:
        doc["task"] = {"name": name}

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    details.pop("Content", None)
    details.pop("LID", None)
    return doc


def _handle_sec_4699(details, extra):
    """Security EventID 4699 — Scheduled Task Deleted."""
    doc = {"event": {"action": "scheduled-task-deleted", "category": ["configuration"], "type": ["deletion"], "outcome": "success"}}

    name = details.pop("Name", None)
    if name:
        doc["task"] = {"name": name}

    user = parse_user(details.pop("User", None))
    if user:
        doc["user"] = user

    details.pop("LID", None)
    return doc


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

DISPATCH = {
    # Sysmon
    ("Sysmon", 1):      _handle_sysmon_1,
    ("Sysmon", 3):      _handle_sysmon_3,
    ("Sysmon", 5):      _handle_sysmon_5,
    ("Sysmon", 6):      _handle_sysmon_6,
    ("Sysmon", 7):      _handle_sysmon_7,
    ("Sysmon", 8):      _handle_sysmon_8,
    ("Sysmon", 10):     _handle_sysmon_10,
    ("Sysmon", 11):     _handle_sysmon_11,
    ("Sysmon", 12):     _handle_sysmon_12,
    ("Sysmon", 13):     _handle_sysmon_13,
    ("Sysmon", 17):     _handle_sysmon_17,
    ("Sysmon", 18):     _handle_sysmon_18,
    # Security
    ("Sec", 4624):      _handle_sec_4624,
    ("Sec", 4625):      _handle_sec_4625,
    ("Sec", 4634):      _handle_sec_4634,
    ("Sec", 4648):      _handle_sec_4648,
    ("Sec", 4672):      _handle_sec_4672,
    ("Sec", 4688):      _handle_sec_4688,
    ("Sec", 4768):      _handle_sec_4768,
    ("Sec", 4776):      _handle_sec_4776,
    ("Sec", 4616):      _handle_sec_4616,
    ("Sec", 4647):      _handle_sec_4647,
    ("Sec", 4661):      _handle_sec_4661,
    ("Sec", 4697):      _handle_sec_4697,
    ("Sec", 4720):      _handle_sec_4720,
    ("Sec", 4724):      _handle_sec_4724,
    ("Sec", 4728):      _handle_sec_4728,
    ("Sec", 4732):      _handle_sec_4732,
    ("Sec", 4769):      _handle_sec_4769,
    ("Sec", 5136):      _handle_sec_5136,
    ("Sec", 5140):      _handle_sec_5140,
    ("Sec", 5145):      _handle_sec_5145,
    ("Sec", 5156):      _handle_sec_5156,
    ("Sec", 5157):      _handle_sec_5157,
    ("Sec", 5379):      _handle_sec_5379,
    ("Sec", 1102):      _handle_sec_1102,
    # Task Scheduler
    ("TaskSch", 106):   _handle_tasksch_106,
    ("TaskSch", 140):   _handle_tasksch_140,
    ("TaskSch", 141):   _handle_tasksch_141,
    ("TaskSch", 200):   _handle_tasksch_200,
    # PowerShell
    ("PwSh", 4103):     _handle_pwsh_4103,
    ("PwSh", 4104):     _handle_pwsh_4104,
    ("PwShClassic", 400): _handle_pwsh_classic_400,
    ("PwShClassic", 600): _handle_pwsh_classic_600,
    # System
    ("Sys", 12):        _handle_sys_boot,
    ("Sys", 98):        _handle_sys_98,
    ("Sys", 104):       _handle_sys_104,
    ("Sys", 6005):      _handle_sys_boot,
    ("Sys", 6006):      _handle_sys_shutdown,
    ("Sys", 6009):      _handle_sys_boot,
    ("Sys", 6013):      _handle_sys_6013,
    ("Sys", 7023):      _handle_sys_7023,
    ("Sys", 7031):      _handle_sys_7031,
    ("Sys", 7034):      _handle_sys_7034,
    ("Sys", 7045):      _handle_sys_7045,
    ("Sys", 20001):     _handle_sys_20001,
    # RDP
    ("RDS-RCM", 1149):  _handle_rds_rcm_1149,
    ("RDS-LSM", 21):    _handle_rds_lsm_21,
    ("RDS-LSM", 23):    _handle_rds_lsm_23,
    ("RDS-LSM", 24):    _handle_rds_lsm_24,
    ("RDP-Cli", 1024):  _handle_rdp_cli_1024,
    ("RDP-Cli", 1102):  _handle_rdp_cli_1102,
    # BITS
    ("BitsCli", 59):    _handle_bitscli_59,
    # Defender
    ("Defender", 1116): _handle_defender_1116,
    # WMI
    ("WMI", 5857):      _handle_wmi_5857,
    ("WMI", 5860):      _handle_wmi_5860,
    # SMB
    ("MS-Win-SmbCli/Conn", 30803): _handle_smb_conn_30803,
    # Firewall
    ("Firewall", 2002): _handle_firewall_2002,
    ("Firewall", 2005): _handle_firewall_2005,
    ("Firewall", 2006): _handle_firewall_2006,
    # Defender
    ("Defender", 1013): _handle_defender_1013,
    # Application install/uninstall
    ("App", 1022):      _handle_app_install,
    ("App", 1033):      _handle_app_install,
    ("App", 1034):      _handle_app_uninstall,
    ("App", 11724):     _handle_app_uninstall,
    # Office
    ("OAlerts", 300):   _handle_oalerts_300,
    # Code Integrity
    ("CodeInteg", 3033): _handle_codeintegrity_3033,
    # Partition / Storage
    ("MS-Win-Partition/Diagnostic", 1006): _handle_partition_1006,
    ("MS-Win-Ntfs/Op", 4): _handle_ntfs_4,
    # Sysmon — additional
    ("Sysmon", 2):      _handle_sysmon_2,
    ("Sysmon", 19):     _handle_sysmon_wmi,
    ("Sysmon", 20):     _handle_sysmon_wmi,
    ("Sysmon", 21):     _handle_sysmon_wmi,
    ("Sysmon", 23):     _handle_sysmon_23,
    # Security — additional
    ("Sec", 4698):      _handle_sec_4698,
    ("Sec", 4699):      _handle_sec_4699,
}


# ---------------------------------------------------------------------------
# Generic fallback (for unhandled event types)
# ---------------------------------------------------------------------------

def _generic_extract(details):
    """Extract common fields from Details for events without a specific handler."""
    doc = {"event": {"category": ["event"], "type": ["info"], "outcome": "success"}}

    # Try multiple user field names for maximum coverage
    user_raw = details.pop("User", None) or details.pop("SrcUser", None) or details.pop("TgtUser", None)
    user = parse_user(user_raw)
    if user:
        doc["user"] = user

    proc = _build_process(details)
    cmdline = details.pop("Cmdline", None)
    if cmdline:
        proc["command_line"] = cmdline

    parent = {}
    parent_cmd = details.pop("ParentCmdline", None)
    if parent_cmd:
        parent["command_line"] = parent_cmd
    ppid = to_int(details.pop("ParentPID", None))
    if ppid is not None:
        parent["pid"] = ppid
    if parent:
        proc["parent"] = parent
    if proc:
        doc["process"] = proc

    _pop_internal(details, "PGUID", "LGUID", "ParentPGUID", "LID", "Rule")
    return doc


# ---------------------------------------------------------------------------
# Main transform
# ---------------------------------------------------------------------------

def transform(raw_line, evt):
    """Transform a single Hayabusa event to an ECS-aligned document."""
    details = evt.get("Details", {}) or {}
    if isinstance(details, str):
        details = {"_raw": details}

    # Rescue the empty-string key before remove_empty_keys strips it
    # (Sysmon/13 stores registry value data under "" key)
    if "" in details:
        details["_value"] = details.pop("")

    details = remove_empty_keys(details)

    extra = evt.get("ExtraFieldInfo", {}) or {}
    if isinstance(extra, str):
        extra = {"_raw": extra}
    extra = remove_empty_keys(extra)

    sev_num, sev_label = SEVERITY_MAP.get(evt.get("Level", ""), (0, "informational"))
    event_id = evt.get("EventID", "")
    channel = evt.get("Channel", "")
    computer = evt.get("Computer", "")
    record_id = evt.get("RecordID")

    # Base document — common fields for all events
    doc = {
        "@timestamp": convert_timestamp(evt.get("Timestamp", "")),
        "event": {
            "module": "hayabusa",
            "original": json.dumps(json.loads(raw_line.strip()), indent=2),
            "code": str(event_id),
            "provider": channel,
            "severity": sev_num,
            "severity_label": sev_label,
        },
        "host": {"name": computer},
        "rule": {
            "name": evt.get("RuleTitle"),
            "id": evt.get("RuleID"),
            "ruleset": evt.get("RuleFile"),
        },
        "record_id": record_id,
        "tags": evt.get("OtherTags", []),
        # winlog.* duplicates
        "winlog": {
            "event_id": str(event_id),
            "channel": channel,
            "computer_name": computer,
            "record_id": record_id,
        },
    }

    # MITRE ATT&CK
    tactics = evt.get("MitreTactics", [])
    techniques = evt.get("MitreTags", [])
    if tactics:
        doc["threat"] = {"tactic": {"name": tactics}}
    if techniques:
        doc.setdefault("threat", {})["technique"] = {"id": techniques}

    # Source EVTX file path
    if evt.get("EvtxFile"):
        doc["log"] = {"file": {"path": evt["EvtxFile"]}}

    # Dispatch to event-type handler or fall back to generic extraction
    handler = DISPATCH.get((channel, event_id))
    if handler:
        partial = handler(details, extra)
    else:
        partial = _generic_extract(details)

    # Deep-merge handler output into base doc
    if partial:
        _deep_merge(doc, partial)

    # Remaining unmapped fields go to catchall
    if details:
        doc["event"]["original_details"] = details
    if extra:
        doc["event"]["extra"] = extra

    return doc
