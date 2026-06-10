import os
import json
import pytest
from src.utils.audit_log import sha256_file, log_action
from src.wrappers.base_wrapper import BaseWrapper
from src.wrappers.volatility_wrapper import VolatilityWrapper


# ─────────────────────────────────────────────────────────────
# Volatility parser regression tests (issues 3.1 / 3.3)
# ─────────────────────────────────────────────────────────────

def test_parse_malfind():
    wrapper = VolatilityWrapper()

    mock_output = """
Volatility 3 Framework 2.4.0
PID    Process    Start VPN    End VPN    Tag    Protection    CommitCharge    PrivateMemory    FileOutput    Disasm
4    System    0x10000    0x11000    VadS    PAGE_EXECUTE_READWRITE    1    1    -
0x10000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
0x10010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
    """

    items = wrapper._parse("windows.malfind", mock_output)

    assert len(items) == 1
    assert items[0]["severity"] == "critical"
    assert "RWX region and embedded PE/shellcode detected" in items[0]["value"]
    assert items[0]["evidence_type"] == "injected_code"


def test_parse_filescan():
    wrapper = VolatilityWrapper()

    mock_output = """
Volatility 3 Framework 2.4.0
0x000000001000    \\Device\\HarddiskVolume2\\Intel\\ivecuqmanpnirkt615\\tasksche.exe
0x000000002000    \\Device\\HarddiskVolume2\\Windows\\System32\\kernel32.dll
0x000000003000    \\Device\\HarddiskVolume2\\Users\\Public\\malware.exe
    """

    items = wrapper._parse("windows.filescan", mock_output)

    assert len(items) == 2
    assert "tasksche.exe" in items[0]["value"]
    assert "malware.exe" in items[1]["value"]


def test_extract_strings():
    wrapper = VolatilityWrapper()

    corpus = """
    http://www.suspicious-domain-123.com/payload
    random_hex_string_that_looks_like_btc_but_invalid: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    real_onion: exp1234567890abcdef.onion
    HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware
    ignore_this_file.dll
    1234567890abcdef1234567890abcdef1234.exe
    """

    items = wrapper._extract_strings(corpus)

    types = [item["evidence_type"] for item in items]
    values = [item["value"] for item in items]

    assert "suspicious_domain" in types
    assert "www.suspicious-domain-123.com" in values
    assert "exp1234567890abcdef.onion" in values
    assert "registry_key" in types
    assert "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware" in values
    assert "suspicious_crypto" in types
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in values
    assert "ignore_this_file.dll" not in values


# ─────────────────────────────────────────────────────────────
# Audit log
# ─────────────────────────────────────────────────────────────

def test_audit_log_creates_entry(tmp_path):
    import src.utils.audit_log as al
    al.AUDIT_LOG_PATH = str(tmp_path / "audit_log.json")
    log_action("test_tool", ["echo", "hi"], [], [], "success")
    with open(al.AUDIT_LOG_PATH) as f:
        entries = json.load(f)
    assert len(entries) == 1
    assert entries[0]["tool"] == "test_tool"
    assert entries[0]["status"] == "success"


def test_sha256_missing_file():
    result = sha256_file("/nonexistent/path/file.dmp")
    assert result == "file_not_found"


# ─────────────────────────────────────────────────────────────
# Base wrapper
# ─────────────────────────────────────────────────────────────

def test_base_wrapper_makes_evidence_item():
    w = BaseWrapper("test_tool")
    item = w.make_evidence_item(
        artifact_id="test_001",
        evidence_type="process",
        value="svchost.exe (PID:1234)",
        severity="high",
        confidence=0.9
    )
    required = ["artifact_id","source_tool","evidence_type",
                "timestamp","value","severity","confidence","linked_artifacts"]
    for field in required:
        assert field in item, f"Missing field: {field}"
    assert item["artifact_id"] == "test_001"
    assert item["source_tool"] == "test_tool"
    assert item["severity"] == "high"


def test_base_wrapper_run_command_success():
    w = BaseWrapper("echo_test")
    stdout, stderr, code = w.run_command(["echo", "hello"])
    assert code == 0
    assert "hello" in stdout


def test_base_wrapper_run_command_timeout():
    w = BaseWrapper("sleep_test")
    stdout, stderr, code = w.run_command(["sleep", "10"], timeout=1)
    assert code == -1


def test_evidence_item_schema_matches():
    import json
    with open("src/schemas/evidence_item.json") as f:
        schema = json.load(f)
    w = BaseWrapper("schema_test")
    item = w.make_evidence_item("id_001","process","test value")
    for key in schema["required"]:
        assert key in item, f"Schema field '{key}' missing from evidence_item output"


# ─────────────────────────────────────────────────────────────
# Evidence-file mapping (multiple artifacts per type)
# ─────────────────────────────────────────────────────────────

def test_map_evidence_files_keeps_multiple_memory_images():
    import autoforensiq
    mapping = autoforensiq._map_evidence_files([
        "/case/memory_dump/wannacry.raw",
        "/case/memory_dump/0zapftis.vmem",
    ])
    # Both images survive instead of the second clobbering the first.
    assert mapping["memory_dump"] == [
        "/case/memory_dump/wannacry.raw",
        "/case/memory_dump/0zapftis.vmem",
    ]


def test_map_evidence_files_recognizes_vmem_by_extension():
    import autoforensiq
    mapping = autoforensiq._map_evidence_files(["/elsewhere/snapshot.vmem"])
    assert mapping.get("memory_dump") == ["/elsewhere/snapshot.vmem"]


def test_map_evidence_files_separates_types():
    import autoforensiq
    mapping = autoforensiq._map_evidence_files([
        "/c/mem.raw", "/c/cap.pcap", "/c/disk.e01",
    ])
    assert mapping["memory_dump"] == ["/c/mem.raw"]
    assert mapping["pcap"] == ["/c/cap.pcap"]
    assert mapping["disk_image"] == ["/c/disk.e01"]
