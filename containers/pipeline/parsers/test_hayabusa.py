"""Tests for the Hayabusa event-type-aware ECS parser."""

import json
import sys
from pathlib import Path

import pytest

# Allow imports from pipeline directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from parsers.hayabusa import (
    transform,
    parse_hashes,
    parse_user,
    parse_logon_type,
    convert_timestamp,
    to_int,
)


# ---------------------------------------------------------------------------
# Utility function tests
# ---------------------------------------------------------------------------

class TestParseHashes:
    def test_full_hash_string(self):
        h = parse_hashes("SHA1=aaa,MD5=bbb,SHA256=ccc,IMPHASH=ddd")
        assert h == {"sha1": "aaa", "md5": "bbb", "sha256": "ccc", "imphash": "ddd"}

    def test_partial_hashes(self):
        h = parse_hashes("MD5=abc,SHA256=def")
        assert h == {"md5": "abc", "sha256": "def"}

    def test_malformed_entry_skipped(self):
        h = parse_hashes("SHA1=abc,?,MD5=def")
        assert h == {"sha1": "abc", "md5": "def"}

    def test_none_input(self):
        assert parse_hashes(None) == {}

    def test_empty_string(self):
        assert parse_hashes("") == {}


class TestParseUser:
    def test_domain_user(self):
        assert parse_user("DOMAIN\\Admin") == {"name": "Admin", "domain": "DOMAIN"}

    def test_bare_username(self):
        assert parse_user("bob") == {"name": "bob"}

    def test_nt_authority(self):
        u = parse_user("NT AUTHORITY\\SYSTEM")
        assert u == {"name": "SYSTEM", "domain": "NT AUTHORITY"}

    def test_na_skipped(self):
        assert parse_user("n/a") == {}

    def test_dash_skipped(self):
        assert parse_user("-") == {}

    def test_none_input(self):
        assert parse_user(None) == {}


class TestParseLogonType:
    def test_standard(self):
        code, label = parse_logon_type("3 - NETWORK")
        assert code == "3"
        assert label == "NETWORK"

    def test_bare_value(self):
        code, label = parse_logon_type("10")
        assert code == "10"
        assert label is None

    def test_none(self):
        assert parse_logon_type(None) == (None, None)


class TestConvertTimestamp:
    def test_standard(self):
        assert convert_timestamp("2020-09-28 14:47:36.197 +02:00") == \
            "2020-09-28T14:47:36.197+02:00"

    def test_utc(self):
        assert convert_timestamp("2019-04-30 22:48:59.260 +00:00") == \
            "2019-04-30T22:48:59.260+00:00"


class TestToInt:
    def test_int(self):
        assert to_int(123) == 123

    def test_hex_string(self):
        assert to_int("0x1688") == 5768

    def test_decimal_string(self):
        assert to_int("1234") == 1234

    def test_none(self):
        assert to_int(None) is None

    def test_invalid(self):
        assert to_int("abc") is None


# ---------------------------------------------------------------------------
# Helper to run transform on a raw JSON string
# ---------------------------------------------------------------------------

def run(raw_json):
    """Parse a raw JSON line through transform and return the doc."""
    evt = json.loads(raw_json)
    return transform(raw_json, evt)


# ---------------------------------------------------------------------------
# Base / common field tests
# ---------------------------------------------------------------------------

class TestBaseFields:
    SAMPLE = json.dumps({
        "Timestamp": "2020-09-28 14:47:36.197 +02:00",
        "RuleTitle": "Test Rule",
        "Level": "high",
        "Computer": "WORKSTATION1",
        "Channel": "Sysmon",
        "EventID": 1,
        "RuleID": "abc-123",
        "RuleFile": "test.yml",
        "RecordID": 42,
        "OtherTags": ["sysmon"],
        "MitreTactics": ["Execution"],
        "MitreTags": ["T1059"],
        "EvtxFile": "/path/to/file.evtx",
        "Details": {"Cmdline": "cmd.exe", "Proc": "C:\\cmd.exe", "PID": 100,
                    "ParentCmdline": "explorer.exe", "ParentPID": 1,
                    "User": "TEST\\admin", "Hashes": "MD5=aaa,SHA256=bbb",
                    "Description": "d", "Product": "p", "Company": "c",
                    "LID": "0x123", "LGUID": "g", "PGUID": "g", "ParentPGUID": "g"},
        "ExtraFieldInfo": {"CurrentDirectory": "C:\\"}
    })

    def test_timestamp(self):
        doc = run(self.SAMPLE)
        assert doc["@timestamp"] == "2020-09-28T14:47:36.197+02:00"

    def test_event_fields(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["code"] == "1"
        assert doc["event"]["provider"] == "Sysmon"
        assert doc["event"]["severity"] == 3
        assert doc["event"]["severity_label"] == "high"
        assert doc["event"]["module"] == "evtx"
        assert doc["event"]["dataset"] == "hayabusa"

    def test_host(self):
        doc = run(self.SAMPLE)
        assert doc["host"]["name"] == "WORKSTATION1"

    def test_rule(self):
        doc = run(self.SAMPLE)
        assert doc["rule"]["name"] == "Test Rule"
        assert doc["rule"]["id"] == "abc-123"

    def test_winlog_duplicates(self):
        doc = run(self.SAMPLE)
        assert doc["winlog"]["event_id"] == "1"
        assert doc["winlog"]["channel"] == "Sysmon"
        assert doc["winlog"]["computer_name"] == "WORKSTATION1"
        assert doc["winlog"]["record_id"] == 42

    def test_mitre(self):
        doc = run(self.SAMPLE)
        assert doc["threat"]["tactic"]["name"] == ["Execution"]
        assert doc["threat"]["technique"]["id"] == ["T1059"]

    def test_log_file(self):
        doc = run(self.SAMPLE)
        assert doc["log"]["file"]["path"] == "/path/to/file.evtx"

    def test_tags(self):
        doc = run(self.SAMPLE)
        assert doc["tags"] == ["sysmon"]

    def test_event_original_is_json(self):
        doc = run(self.SAMPLE)
        reparsed = json.loads(doc["event"]["original"])
        assert reparsed["RuleTitle"] == "Test Rule"


# ---------------------------------------------------------------------------
# Sysmon/1 — Process Creation
# ---------------------------------------------------------------------------

class TestSysmon1:
    SAMPLE = '{"Timestamp":"2020-09-28 14:47:36.197 +02:00","RuleTitle":"Proc Exec","Level":"info","Computer":"DESKTOP-PIU87N6","Channel":"Sysmon","EventID":1,"OtherTags":["sysmon"],"RecordID":5226,"Details":{"Cmdline":"rdrleakdiag.exe /p 668","Proc":"C:\\\\Windows\\\\System32\\\\rdrleakdiag.exe","User":"DESKTOP-PIU87N6\\\\wanwan","ParentCmdline":"\\"C:\\\\WINDOWS\\\\system32\\\\cmd.exe\\"","LID":"0x30b90","LGUID":"BC47D85C-6E10-5F68-0000-0020900B0300","PID":3352,"PGUID":"BC47D85C-DB68-5F71-0000-0010B237AB01","ParentPID":1456,"ParentPGUID":"BC47D85C-9569-5F71-0000-0010D9FD8300","Description":"Microsoft Windows Resource Leak Diagnostic","Product":"Microsoft\\u00ae Windows\\u00ae Operating System","Company":"Microsoft Corporation","Hashes":"MD5=C04F4FB2C7B44E19E85908459D3F0085,SHA256=D66E1EE7970598A5F34FD4B468B5B7705219E80A8A2784E7B18564831FCA797C,IMPHASH=5D87ACDE58B6E042FB38FE42B86E9C25"},"ExtraFieldInfo":{"CurrentDirectory":"C:\\\\Users\\\\wanwan\\\\Desktop\\\\"},"RuleFile":"Sysmon_1_Info_ProcExec.yml","RuleID":"85790e3e-e270-499f-a6ad-f8afe85c35f1","EvtxFile":"/path/to/file.evtx"}'

    def test_process_fields(self):
        doc = run(self.SAMPLE)
        assert doc["process"]["executable"] == "C:\\Windows\\System32\\rdrleakdiag.exe"
        assert doc["process"]["command_line"] == "rdrleakdiag.exe /p 668"
        assert doc["process"]["pid"] == 3352

    def test_process_hashes(self):
        doc = run(self.SAMPLE)
        assert doc["process"]["hash"]["md5"] == "C04F4FB2C7B44E19E85908459D3F0085"
        assert doc["process"]["hash"]["sha256"] == "D66E1EE7970598A5F34FD4B468B5B7705219E80A8A2784E7B18564831FCA797C"

    def test_pe_metadata(self):
        doc = run(self.SAMPLE)
        assert doc["process"]["pe"]["description"] == "Microsoft Windows Resource Leak Diagnostic"
        assert doc["process"]["pe"]["imphash"] == "5D87ACDE58B6E042FB38FE42B86E9C25"

    def test_parent_process(self):
        doc = run(self.SAMPLE)
        assert doc["process"]["parent"]["command_line"] == '"C:\\WINDOWS\\system32\\cmd.exe"'
        assert doc["process"]["parent"]["pid"] == 1456

    def test_user_parsed(self):
        doc = run(self.SAMPLE)
        assert doc["user"]["name"] == "wanwan"
        assert doc["user"]["domain"] == "DESKTOP-PIU87N6"

    def test_winlog_logon_id(self):
        doc = run(self.SAMPLE)
        assert doc["winlog"]["logon"]["id"] == "0x30b90"

    def test_internal_fields_cleaned(self):
        doc = run(self.SAMPLE)
        # PGUID, LGUID should not appear in original_details
        od = doc["event"].get("original_details", {})
        assert "PGUID" not in od
        assert "LGUID" not in od


# ---------------------------------------------------------------------------
# Sysmon/3 — Network Connection
# ---------------------------------------------------------------------------

class TestSysmon3:
    SAMPLE = '{"Timestamp":"2019-05-02 16:48:53.950 +02:00","RuleTitle":"Net Conn","Level":"info","Computer":"IEWIN7","Channel":"Sysmon","EventID":3,"OtherTags":["sysmon"],"RecordID":10272,"Details":{"Initiated":true,"Proto":"tcp","SrcIP":"10.0.2.15","SrcPort":49178,"SrcHost":"IEWIN7.home","TgtIP":"151.101.36.133","TgtPort":443,"TgtHost":"","User":"IEWIN7\\\\IEUser","Proc":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","PID":1508,"PGUID":"x"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_source(self):
        doc = run(self.SAMPLE)
        assert doc["source"]["ip"] == "10.0.2.15"
        assert doc["source"]["port"] == 49178
        assert doc["source"]["address"] == "IEWIN7.home"

    def test_destination(self):
        doc = run(self.SAMPLE)
        assert doc["destination"]["ip"] == "151.101.36.133"
        assert doc["destination"]["port"] == 443

    def test_network(self):
        doc = run(self.SAMPLE)
        assert doc["network"]["transport"] == "tcp"
        assert doc["network"]["direction"] == "outbound"

    def test_process(self):
        doc = run(self.SAMPLE)
        assert "powershell.exe" in doc["process"]["executable"]
        assert doc["process"]["pid"] == 1508

    def test_user(self):
        doc = run(self.SAMPLE)
        assert doc["user"]["name"] == "IEUser"


# ---------------------------------------------------------------------------
# Sysmon/7 — DLL Loaded
# ---------------------------------------------------------------------------

class TestSysmon7:
    SAMPLE = '{"Timestamp":"2019-08-30 14:54:08.257 +02:00","RuleTitle":"DLL Loaded","Level":"low","Computer":"MSEDGEWIN10","Channel":"Sysmon","EventID":7,"OtherTags":["sysmon"],"RecordID":32153,"Details":{"Rule":"Suspicious WMI","Image":"C:\\\\Windows\\\\System32\\\\wbem\\\\wmiutils.dll","Proc":"C:\\\\Windows\\\\System32\\\\cscript.exe","Description":"WMI","Product":"Microsoft","Company":"Microsoft Corporation","Signed":true,"Sig":"Valid","PID":2576,"PGUID":"x","Hash":"SHA1=2E6A,MD5=A081,SHA256=3D77,IMPHASH=0D31","OrigFilename":"n/a"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_dll_path(self):
        doc = run(self.SAMPLE)
        assert doc["dll"]["path"] == "C:\\Windows\\System32\\wbem\\wmiutils.dll"

    def test_dll_hashes(self):
        doc = run(self.SAMPLE)
        assert doc["dll"]["hash"]["sha1"] == "2E6A"
        assert doc["dll"]["hash"]["md5"] == "A081"

    def test_dll_pe(self):
        doc = run(self.SAMPLE)
        assert doc["dll"]["pe"]["description"] == "WMI"
        assert doc["dll"]["pe"]["imphash"] == "0D31"

    def test_dll_code_signature(self):
        doc = run(self.SAMPLE)
        assert doc["dll"]["code_signature"]["exists"] is True
        assert doc["dll"]["code_signature"]["status"] == "Valid"

    def test_orig_filename_na_skipped(self):
        doc = run(self.SAMPLE)
        assert "original_file_name" not in doc["dll"].get("pe", {})

    def test_process(self):
        doc = run(self.SAMPLE)
        assert doc["process"]["executable"] == "C:\\Windows\\System32\\cscript.exe"


# ---------------------------------------------------------------------------
# Sysmon/8 — CreateRemoteThread
# ---------------------------------------------------------------------------

class TestSysmon8:
    SAMPLE = '{"Timestamp":"2020-09-28 14:47:36.206 +02:00","RuleTitle":"Proc Injection","Level":"med","Computer":"DESKTOP","Channel":"Sysmon","EventID":8,"RecordID":5227,"Details":{"SrcProc":"C:\\\\rdrleakdiag.exe","TgtProc":"C:\\\\lsass.exe","SrcPID":3352,"SrcPGUID":"x","TgtPID":668,"TgtPGUID":"y"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_source_process(self):
        doc = run(self.SAMPLE)
        assert doc["process"]["executable"] == "C:\\rdrleakdiag.exe"
        assert doc["process"]["pid"] == 3352

    def test_target_process(self):
        doc = run(self.SAMPLE)
        assert doc["process"]["target"]["executable"] == "C:\\lsass.exe"
        assert doc["process"]["target"]["pid"] == 668

    def test_event_action(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["action"] == "create-remote-thread"


# ---------------------------------------------------------------------------
# Sysmon/10 — Process Access
# ---------------------------------------------------------------------------

class TestSysmon10:
    SAMPLE = '{"Timestamp":"2019-05-02 16:50:17.955 +02:00","RuleTitle":"Proc Access","Level":"low","Computer":"IEWIN7","Channel":"Sysmon","EventID":10,"RecordID":10273,"Details":{"SrcProc":"C:\\\\powershell.exe","TgtProc":"C:\\\\lsass.exe","SrcUser":"n/a","TgtUser":"n/a","Access":"0x143a","SrcPID":1508,"SrcPGUID":"x","TgtPID":484,"TgtPGUID":"y"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_source_process(self):
        doc = run(self.SAMPLE)
        assert doc["process"]["executable"] == "C:\\powershell.exe"

    def test_target_process(self):
        doc = run(self.SAMPLE)
        assert doc["process"]["target"]["executable"] == "C:\\lsass.exe"

    def test_na_users_skipped(self):
        doc = run(self.SAMPLE)
        # n/a should not produce user fields
        assert "user" not in doc or doc.get("user") == {}

    def test_access_mask_in_details(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["original_details"]["Access"] == "0x143a"


# ---------------------------------------------------------------------------
# Sysmon/11 — File Created
# ---------------------------------------------------------------------------

class TestSysmon11:
    SAMPLE = '{"Timestamp":"2020-09-28 14:47:36.630 +02:00","RuleTitle":"File Created","Level":"info","Computer":"DESKTOP","Channel":"Sysmon","EventID":11,"RecordID":5229,"Details":{"Path":"C:\\\\Users\\\\test\\\\dump.dmp","Proc":"C:\\\\rdrleakdiag.exe","PID":3352,"PGUID":"x"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_file_path(self):
        doc = run(self.SAMPLE)
        assert doc["file"]["path"] == "C:\\Users\\test\\dump.dmp"

    def test_process(self):
        doc = run(self.SAMPLE)
        assert doc["process"]["executable"] == "C:\\rdrleakdiag.exe"

    def test_action(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["action"] == "file-created"


# ---------------------------------------------------------------------------
# Sysmon/13 — Registry Value Set
# ---------------------------------------------------------------------------

class TestSysmon13:
    SAMPLE = '{"Timestamp":"2020-09-20 23:22:24.799 +02:00","RuleTitle":"Reg Set","Level":"med","Computer":"MSEDGEWIN10","Channel":"Sysmon","EventID":13,"RecordID":401997,"Details":{"Rule":"Test","EventType":"SetValue","TgtObj":"HKLM\\\\SAM\\\\Test","":"Binary Data","Proc":"C:\\\\lsass.exe","PID":648,"PGUID":"x"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_registry_path(self):
        doc = run(self.SAMPLE)
        assert doc["registry"]["path"] == "HKLM\\SAM\\Test"

    def test_registry_data(self):
        doc = run(self.SAMPLE)
        assert doc["registry"]["data"]["strings"] == "Binary Data"

    def test_event_action(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["action"] == "SetValue"


# ---------------------------------------------------------------------------
# Sec/4624 — Logon
# ---------------------------------------------------------------------------

class TestSec4624:
    SAMPLE = '{"Timestamp":"2020-09-17 12:57:44.270 +02:00","RuleTitle":"Logon","Level":"info","Computer":"DC01","Channel":"Sec","EventID":4624,"RecordID":769794,"Details":{"Type":"3 - NETWORK","TgtUser":"Administrator","SrcComp":"CLIENT01","SrcIP":"172.16.66.37","LID":"0x853237"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_logon_type(self):
        doc = run(self.SAMPLE)
        assert doc["winlog"]["logon"]["type"] == "3"

    def test_logon_id(self):
        doc = run(self.SAMPLE)
        assert doc["winlog"]["logon"]["id"] == "0x853237"

    def test_target_user(self):
        doc = run(self.SAMPLE)
        assert doc["user"]["target"]["name"] == "Administrator"

    def test_source(self):
        doc = run(self.SAMPLE)
        assert doc["source"]["ip"] == "172.16.66.37"
        assert doc["source"]["address"] == "CLIENT01"  # hostname overrides ip copy

    def test_user_is_target_when_no_subject(self):
        doc = run(self.SAMPLE)
        # No subject in ExtraFieldInfo -> user.name mirrors target
        assert doc["user"]["name"] == "Administrator"
        assert doc["user"]["target"]["name"] == "Administrator"

    def test_event_action(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["action"] == "logon-success"


# ---------------------------------------------------------------------------
# Sec/4768 — Kerberos TGT
# ---------------------------------------------------------------------------

class TestSec4768:
    SAMPLE = '{"Timestamp":"2020-07-22 22:29:36.414 +02:00","RuleTitle":"Kerberos TGT","Level":"info","Computer":"DC01","Channel":"Sec","EventID":4768,"RecordID":887107,"Details":{"TgtUser":"HD01","Svc":"krbtgt/DOMAIN","SrcIP":"172.16.66.1","Status":"0x6","PreAuthType":"-"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_target_user(self):
        doc = run(self.SAMPLE)
        assert doc["user"]["target"]["name"] == "HD01"

    def test_source_ip(self):
        doc = run(self.SAMPLE)
        assert doc["source"]["ip"] == "172.16.66.1"

    def test_outcome_failure(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["outcome"] == "failure"

    def test_outcome_success(self):
        raw = self.SAMPLE.replace('"0x6"', '"0x0"')
        doc = run(raw)
        assert doc["event"]["outcome"] == "success"


# ---------------------------------------------------------------------------
# Sec/5145 — Network Share
# ---------------------------------------------------------------------------

class TestSec5145:
    SAMPLE = '{"Timestamp":"2022-02-16 11:37:20.534 +02:00","RuleTitle":"NetShare","Level":"info","Computer":"DC01","Channel":"Sec","EventID":5145,"RecordID":2988537,"Details":{"SrcUser":"samir","ShareName":"\\\\\\\\*\\\\C$","SharePath":"\\\\??\\\\C:\\\\","Path":"Users\\\\test","SrcIP":"172.16.66.36","LID":"0x567758"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_user(self):
        doc = run(self.SAMPLE)
        assert doc["user"]["name"] == "samir"

    def test_source_ip(self):
        doc = run(self.SAMPLE)
        assert doc["source"]["ip"] == "172.16.66.36"

    def test_file_path(self):
        doc = run(self.SAMPLE)
        assert doc["file"]["path"] == "Users\\test"

    def test_file_share_name(self):
        doc = run(self.SAMPLE)
        assert "share_name" in doc["file"]


# ---------------------------------------------------------------------------
# Sec/5156 — WFP Connection
# ---------------------------------------------------------------------------

class TestSec5156:
    SAMPLE = '{"Timestamp":"2019-03-20 00:35:08.786 +01:00","RuleTitle":"Net Conn","Level":"info","Computer":"PC01","Channel":"Sec","EventID":5156,"RecordID":452812,"Details":{"Proc":"\\\\device\\\\harddiskvolume1\\\\svchost.exe","SrcIP":"10.0.0.1","SrcPort":546,"TgtIP":"10.0.0.2","TgtPort":547,"Protocol":17,"TgtMachineID":"S-1-0-0","TgtSID":"S-1-0-0","PID":812},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_source(self):
        doc = run(self.SAMPLE)
        assert doc["source"]["ip"] == "10.0.0.1"
        assert doc["source"]["port"] == 546

    def test_destination(self):
        doc = run(self.SAMPLE)
        assert doc["destination"]["ip"] == "10.0.0.2"
        assert doc["destination"]["port"] == 547

    def test_network_transport_from_protocol_number(self):
        doc = run(self.SAMPLE)
        assert doc["network"]["transport"] == "udp"

    def test_process(self):
        doc = run(self.SAMPLE)
        assert "svchost.exe" in doc["process"]["executable"]


# ---------------------------------------------------------------------------
# PwSh/4104 — PowerShell ScriptBlock
# ---------------------------------------------------------------------------

class TestPwSh4104:
    SAMPLE = '{"Timestamp":"2019-09-09 15:35:08.655 +02:00","RuleTitle":"PwSh","Level":"med","Computer":"PC01","Channel":"PwSh","EventID":4104,"RecordID":1122,"Details":{"ScriptBlock":"Get-Process"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_script_block(self):
        doc = run(self.SAMPLE)
        assert doc["powershell"]["file"]["script_block_text"] == "Get-Process"


# ---------------------------------------------------------------------------
# BitsCli/59 — BITS Transfer
# ---------------------------------------------------------------------------

class TestBitsCli59:
    SAMPLE = '{"Timestamp":"2020-07-03 10:55:49.123 +02:00","RuleTitle":"Bits Job","Level":"info","Computer":"PC01","Channel":"BitsCli","EventID":59,"RecordID":2776,"Details":{"JobTitle":"Download","URL":"https://example.com/file.7z"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_url(self):
        doc = run(self.SAMPLE)
        assert doc["url"]["original"] == "https://example.com/file.7z"

    def test_action(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["action"] == "bits-transfer"


# ---------------------------------------------------------------------------
# Defender/1116 — Malware Detection
# ---------------------------------------------------------------------------

class TestDefender1116:
    SAMPLE = '{"Timestamp":"2019-07-18 22:41:16.418 +02:00","RuleTitle":"Defender","Level":"high","Computer":"PC01","Channel":"Defender","EventID":1116,"RecordID":75,"Details":{"Threat":"HackTool:JS/Jsprat","Severity":"High","Type":"Tool","User":"PC01\\\\IEUser","Path":"C:\\\\malware.exe","Proc":"C:\\\\powershell.exe"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_threat(self):
        doc = run(self.SAMPLE)
        assert doc["threat"]["indicator"]["description"] == "HackTool:JS/Jsprat"

    def test_file_path(self):
        doc = run(self.SAMPLE)
        assert doc["file"]["path"] == "C:\\malware.exe"

    def test_user(self):
        doc = run(self.SAMPLE)
        assert doc["user"]["name"] == "IEUser"


# ---------------------------------------------------------------------------
# RDS-RCM/1149 — RDP
# ---------------------------------------------------------------------------

class TestRdsRcm1149:
    SAMPLE = '{"Timestamp":"2018-11-06 22:45:50.411 +01:00","RuleTitle":"RDP Logon","Level":"info","Computer":"PC01","Channel":"RDS-RCM","EventID":1149,"RecordID":6,"Details":{"TgtUser":"administrator","Domain":"ie11win7","SrcIP":"10.0.2.16"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_target_user(self):
        doc = run(self.SAMPLE)
        assert doc["user"]["target"]["name"] == "administrator"
        assert doc["user"]["target"]["domain"] == "ie11win7"

    def test_source_ip(self):
        doc = run(self.SAMPLE)
        assert doc["source"]["ip"] == "10.0.2.16"

    def test_action(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["action"] == "rdp-connection"


# ---------------------------------------------------------------------------
# Sys/7045 — Service Installed
# ---------------------------------------------------------------------------

class TestSys7045:
    SAMPLE = '{"Timestamp":"2019-05-12 14:52:43.702 +02:00","RuleTitle":"Svc Installed","Level":"info","Computer":"PC01","Channel":"Sys","EventID":7045,"RecordID":10446,"Details":{"Svc":"WinPwnage","Path":"%COMSPEC% /c ping","Acct":"LocalSystem","StartType":"demand start"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_service_name(self):
        doc = run(self.SAMPLE)
        assert doc["service"]["name"] == "WinPwnage"

    def test_file_path(self):
        doc = run(self.SAMPLE)
        assert doc["file"]["path"] == "%COMSPEC% /c ping"

    def test_user(self):
        doc = run(self.SAMPLE)
        assert doc["user"]["name"] == "LocalSystem"


# ---------------------------------------------------------------------------
# Sysmon/6 — Driver Loaded
# ---------------------------------------------------------------------------

class TestSysmon6:
    SAMPLE = '{"Timestamp":"2020-02-10 09:28:12.981 +01:00","RuleTitle":"Driver","Level":"med","Computer":"PC01","Channel":"Sysmon","EventID":6,"RecordID":18766,"Details":{"Path":"C:\\\\drivers\\\\VBoxDrv.sys","Sig":"innotek GmbH","Signed":true,"SigStatus":"Valid","Hashes":"SHA1=7C1B,MD5=EAEA,SHA256=CF3A,IMPHASH=B262"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_file_path(self):
        doc = run(self.SAMPLE)
        assert doc["file"]["path"] == "C:\\drivers\\VBoxDrv.sys"

    def test_file_hashes(self):
        doc = run(self.SAMPLE)
        assert doc["file"]["hash"]["sha1"] == "7C1B"
        assert doc["file"]["hash"]["md5"] == "EAEA"

    def test_code_signature(self):
        doc = run(self.SAMPLE)
        assert doc["file"]["code_signature"]["exists"] is True
        assert doc["file"]["code_signature"]["status"] == "Valid"


# ---------------------------------------------------------------------------
# Sysmon/5 — Process Terminated
# ---------------------------------------------------------------------------

class TestSysmon5:
    SAMPLE = '{"Timestamp":"2021-04-23 00:09:26.307 +02:00","RuleTitle":"Proc Terminated","Level":"info","Computer":"PC01","Channel":"Sysmon","EventID":5,"RecordID":564599,"Details":{"Proc":"C:\\\\PPLdump.exe","PID":6316,"PGUID":"x"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_process(self):
        doc = run(self.SAMPLE)
        assert doc["process"]["executable"] == "C:\\PPLdump.exe"
        assert doc["process"]["pid"] == 6316

    def test_action(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["action"] == "process-terminated"


# ---------------------------------------------------------------------------
# Sysmon/12 — Registry Object Create/Delete
# ---------------------------------------------------------------------------

class TestSysmon12:
    SAMPLE = '{"Timestamp":"2021-04-23 00:09:35.165 +02:00","RuleTitle":"Reg","Level":"high","Computer":"PC01","Channel":"Sysmon","EventID":12,"RecordID":564603,"Details":{"EventType":"CreateKey","TgtObj":"HKU\\\\S-1-5\\\\RunMRU","Proc":"C:\\\\mmc.exe","PID":800,"PGUID":"x"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_registry_path(self):
        doc = run(self.SAMPLE)
        assert doc["registry"]["path"] == "HKU\\S-1-5\\RunMRU"

    def test_action(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["action"] == "CreateKey"


# ---------------------------------------------------------------------------
# Sysmon/17,18 — Pipe Created/Connected
# ---------------------------------------------------------------------------

class TestSysmon17:
    SAMPLE = '{"Timestamp":"2019-09-06 15:49:35.433 +02:00","RuleTitle":"Pipe Created","Level":"med","Computer":"PC01","Channel":"Sysmon","EventID":17,"RecordID":37109,"Details":{"Rule":"CredAccess","Pipe":"\\\\kekeo_tsssp_endpoint","Proc":"C:\\\\kekeo.exe","PID":6908,"PGUID":"x"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_pipe_name(self):
        doc = run(self.SAMPLE)
        assert doc["file"]["name"] == "\\kekeo_tsssp_endpoint"

    def test_action(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["action"] == "pipe-created"


class TestSysmon18:
    SAMPLE = '{"Timestamp":"2019-09-06 15:49:39.823 +02:00","RuleTitle":"Pipe Connected","Level":"med","Computer":"PC01","Channel":"Sysmon","EventID":18,"RecordID":37110,"Details":{"Rule":"CredAccess","Pipe":"\\\\kekeo","Proc":"C:\\\\kekeo.exe","PID":7808,"PGUID":"x"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_action(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["action"] == "pipe-connected"


# ---------------------------------------------------------------------------
# Sec/4672 — Special Privileges
# ---------------------------------------------------------------------------

class TestSec4672:
    SAMPLE = '{"Timestamp":"2022-02-16 11:37:20.450 +01:00","RuleTitle":"Admin Logon","Level":"info","Computer":"DC01","Channel":"Sec","EventID":4672,"RecordID":2988528,"Details":{"TgtUser":"samir","LID":"0x567515"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_target_user(self):
        doc = run(self.SAMPLE)
        assert doc["user"]["target"]["name"] == "samir"

    def test_logon_id(self):
        doc = run(self.SAMPLE)
        assert doc["winlog"]["logon"]["id"] == "0x567515"


# ---------------------------------------------------------------------------
# Sec/4688 — Process Creation (Security)
# ---------------------------------------------------------------------------

class TestSec4688:
    SAMPLE = '{"Timestamp":"2021-12-07 18:33:01.397 +01:00","RuleTitle":"Proc Exec","Level":"info","Computer":"PC01","Channel":"Sec","EventID":4688,"RecordID":329914,"Details":{"Cmdline":"test.exe /flag","Proc":"C:\\\\test.exe","PID":8612,"User":"IEUser","LID":"0x53ca2"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_process(self):
        doc = run(self.SAMPLE)
        assert doc["process"]["executable"] == "C:\\test.exe"
        assert doc["process"]["command_line"] == "test.exe /flag"

    def test_user(self):
        doc = run(self.SAMPLE)
        assert doc["user"]["name"] == "IEUser"


# ---------------------------------------------------------------------------
# Sec/4776 — Credential Validation
# ---------------------------------------------------------------------------

class TestSec4776:
    SAMPLE = '{"Timestamp":"2020-09-17 12:57:44.254 +02:00","RuleTitle":"NTLM Auth","Level":"info","Computer":"DC01","Channel":"Sec","EventID":4776,"RecordID":769793,"Details":{"TgtUser":"Administrator","SrcComp":"CLIENT01","Status":"0x0"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_target_user(self):
        doc = run(self.SAMPLE)
        assert doc["user"]["target"]["name"] == "Administrator"

    def test_source_address(self):
        doc = run(self.SAMPLE)
        assert doc["source"]["address"] == "CLIENT01"

    def test_outcome_success(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["outcome"] == "success"


# ---------------------------------------------------------------------------
# Sec/5136 — Directory Service Object Modified
# ---------------------------------------------------------------------------

class TestSec5136:
    SAMPLE = '{"Timestamp":"2019-03-25 11:33:56.457 +01:00","RuleTitle":"DS Modified","Level":"info","Computer":"DC01","Channel":"Sec","EventID":5136,"RecordID":198238043,"Details":{"User":"bob","SID":"S-1-5-21","ObjDN":"CN=test","AttrLDAPName":"versionNumber","OpType":"%%14675","LID":"0x8d7099"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_user(self):
        doc = run(self.SAMPLE)
        assert doc["user"]["name"] == "bob"

    def test_logon_id(self):
        doc = run(self.SAMPLE)
        assert doc["winlog"]["logon"]["id"] == "0x8d7099"

    def test_action(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["action"] == "directory-service-object-modified"


# ---------------------------------------------------------------------------
# Fallback — unhandled event types
# ---------------------------------------------------------------------------

class TestFallback:
    SAMPLE = '{"Timestamp":"2019-11-04 14:46:01.171 +01:00","RuleTitle":"Test","Level":"low","Computer":"PC01","Channel":"App","EventID":99999,"RecordID":13026,"Details":{"Data[1]":"sa","Data[2]":"Reason: bad password"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_unhandled_preserves_details(self):
        doc = run(self.SAMPLE)
        assert "Data[1]" in doc["event"]["original_details"]

    def test_base_fields_present(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["code"] == "99999"
        assert doc["winlog"]["event_id"] == "99999"


class TestApp18456:
    SAMPLE = '{"Timestamp":"2019-11-04 14:46:01.171 +01:00","RuleTitle":"MSSQL Failed Logon","Level":"low","Computer":"DB01","Channel":"App","EventID":18456,"RecordID":13026,"Details":{"Data[1]":"sa","Data[2]":"Reason: Password did not match.","Data[3]":"[CLIENT: 172.16.0.89]","Binary":"abc"},"ExtraFieldInfo":{},"RuleFile":"test.yml","RuleID":"a","EvtxFile":"/path.evtx"}'

    def test_action(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["action"] == "mssql-logon-failure"

    def test_outcome(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["outcome"] == "failure"

    def test_user(self):
        doc = run(self.SAMPLE)
        assert doc["user"]["name"] == "sa"

    def test_source_ip(self):
        doc = run(self.SAMPLE)
        assert doc["source"]["ip"] == "172.16.0.89"
        assert doc["source"]["address"] == "172.16.0.89"

    def test_reason(self):
        doc = run(self.SAMPLE)
        assert doc["event"]["reason"] == "Password did not match."

    def test_local_machine(self):
        raw = self.SAMPLE.replace("[CLIENT: 172.16.0.89]", "[CLIENT: <local machine>]")
        doc = run(raw)
        assert "source" not in doc
