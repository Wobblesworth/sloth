"""Tests for the Prefetch/PECmd parser."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from parsers.prefetch import (
    transform_pf,
    _parse_timestamp,
    _derive_executable_path,
    _normalize_volume_path,
    _derive_directories,
)


class TestNormalizeVolumePath:
    def test_strips_volume_prefix(self):
        path = "\\VOLUME{01da9a1e0adb2ea0-2e0ae4f7}\\WINDOWS\\SYSTEM32\\NTDLL.DLL"
        assert _normalize_volume_path(path) == "C:\\WINDOWS\\SYSTEM32\\NTDLL.DLL"

    def test_passthrough_non_volume(self):
        assert _normalize_volume_path("C:\\Windows\\System32") == "C:\\Windows\\System32"

    def test_non_string_passthrough(self):
        assert _normalize_volume_path(None) is None


class TestDeriveDirectories:
    def test_unique_sorted(self):
        files = [
            "\\VOLUME{abc}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
            "\\VOLUME{abc}\\WINDOWS\\SYSTEM32\\KERNEL32.DLL",
            "\\VOLUME{abc}\\USERS\\BOB\\DESKTOP\\x.txt",
        ]
        dirs = _derive_directories(files)
        assert dirs == [
            "C:\\USERS\\BOB\\DESKTOP",
            "C:\\WINDOWS\\SYSTEM32",
        ]


class TestParseTimestamp:
    def test_nanoseconds_clipped_to_ms(self):
        assert _parse_timestamp("2020-01-01T12:00:00.1234567") == "2020-01-01T12:00:00.123Z"

    def test_already_ms(self):
        assert _parse_timestamp("2020-01-01T12:00:00.123") == "2020-01-01T12:00:00.123Z"

    def test_no_fraction(self):
        assert _parse_timestamp("2020-01-01T12:00:00") == "2020-01-01T12:00:00Z"

    def test_null_pecmd_value(self):
        assert _parse_timestamp("0001-01-01T00:00:00") is None

    def test_empty(self):
        assert _parse_timestamp("") is None
        assert _parse_timestamp(None) is None


class TestDeriveExecutablePath:
    def test_matches_exe_in_files_loaded(self):
        files = [
            "\\VOLUME{01d5a12b3e4f5678-aabbccdd}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
            "\\VOLUME{01d5a12b3e4f5678-aabbccdd}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE",
        ]
        assert _derive_executable_path("NOTEPAD.EXE", files) == "C:\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE"

    def test_no_match(self):
        files = ["\\VOLUME{abc}\\WINDOWS\\SYSTEM32\\NTDLL.DLL"]
        assert _derive_executable_path("NOTEPAD.EXE", files) is None

    def test_empty_inputs(self):
        assert _derive_executable_path("", []) is None
        assert _derive_executable_path("NOTEPAD.EXE", []) is None


class TestTransformPf:
    SAMPLE = {
        "SourceFilename": "C:\\Windows\\Prefetch\\NOTEPAD.EXE-D8414F97.pf",
        "SourceCreated": "2020-01-15T10:00:00.0000000",
        "SourceModified": "2020-02-01T14:00:00.0000000",
        "SourceAccessed": "2020-02-01T14:00:00.0000000",
        "ExecutableFilename": "NOTEPAD.EXE",
        "Hash": "D8414F97",
        "Size": 12345,
        "Version": "Windows10",
        "RunCount": 3,
        "LastRunTimes": [
            "2020-02-01T14:00:00.1234567",
            "2020-01-20T10:00:00.0000000",
            "2020-01-15T09:00:00.0000000",
            "0001-01-01T00:00:00",
            "0001-01-01T00:00:00",
        ],
        "Volumes": [
            {"Name": "\\VOLUME{abc}", "SerialNumber": "DEAD-BEEF", "CreationTime": "2019-12-01T00:00:00.0000000"}
        ],
        "FilesLoaded": ["\\VOLUME{abc}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE"],
        "DirectoriesLoaded": ["\\VOLUME{abc}\\WINDOWS\\SYSTEM32"],
    }

    def test_one_doc_per_execution(self):
        docs = transform_pf(self.SAMPLE, {"filename": "NOTEPAD.EXE-D8414F97.pf"})
        # 3 valid times (null ones filtered)
        assert len(docs) == 3

    def test_timestamps_set(self):
        docs = transform_pf(self.SAMPLE, {})
        assert docs[0]["@timestamp"] == "2020-02-01T14:00:00.123Z"
        assert docs[1]["@timestamp"] == "2020-01-20T10:00:00.000Z"

    def test_execution_sequence(self):
        docs = transform_pf(self.SAMPLE, {})
        assert docs[0]["prefetch"]["execution_sequence"] == 1
        assert docs[2]["prefetch"]["execution_sequence"] == 3

    def test_process_fields(self):
        docs = transform_pf(self.SAMPLE, {})
        assert docs[0]["process"]["name"] == "NOTEPAD.EXE"
        assert docs[0]["process"]["executable"] == "C:\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE"

    def test_event_fields(self):
        docs = transform_pf(self.SAMPLE, {})
        assert docs[0]["event"]["module"] == "prefetch"
        assert docs[0]["event"]["dataset"] == "libscca"
        assert docs[0]["event"]["action"] == "program-executed"
        assert docs[0]["event"]["category"] == ["process"]
        assert docs[0]["event"]["outcome"] == "success"

    def test_prefetch_fields(self):
        docs = transform_pf(self.SAMPLE, {})
        assert docs[0]["prefetch"]["hash"] == "D8414F97"
        assert docs[0]["prefetch"]["run_count"] == 3
        assert docs[0]["prefetch"]["version"] == "Windows10"

    def test_volumes(self):
        docs = transform_pf(self.SAMPLE, {})
        vols = docs[0]["prefetch"]["volumes"]
        assert len(vols) == 1
        assert vols[0]["serial_number"] == "DEAD-BEEF"

    def test_no_executions_no_docs(self):
        sample = dict(self.SAMPLE)
        sample["LastRunTimes"] = []
        docs = transform_pf(sample, {})
        # No timestamps -> no docs (can't place on timeline)
        assert docs == []
