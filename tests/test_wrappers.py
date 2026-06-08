import os
import json
import pytest
import sys
import types
from src.utils.audit_log import sha256_file, log_action
from src.wrappers.base_wrapper import BaseWrapper
from src.wrappers.volatility_wrapper import VolatilityWrapper
from src.wrappers.memprocfs_wrapper import MemProcFSWrapper

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


def test_volatility_malfind_detects_pe_on_continuation_lines():
    wrapper = VolatilityWrapper()
    lines = [
        "Volatility 3 Framework 2.26.2",
        "PID Process Start End Tag Prot",
        "1234 svchost.exe 0x1000 0x2000 VadS PAGE_EXECUTE_READWRITE",
        "    00000000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00  MZ..............",
        "5678 svchost.exe 0x3000 0x4000 VadS PAGE_READWRITE",
    ]

    items = wrapper._parse_malfind(lines)

    assert len(items) == 2
    assert any(item["severity"] == "critical" for item in items)
    assert any(item["severity"] == "medium" for item in items)
    assert any("Corroborated" in item["value"] or "PE/shellcode" in item["value"] for item in items)


def test_volatility_filescan_keeps_intel_payload_path():
    wrapper = VolatilityWrapper()
    lines = [
        "0x00000000  0x00000001  C:\\Intel\\ivecuqmanpnirkt615\\payload.dll",
        "0x00000000  0x00000002  C:\\Windows\\System32\\kernel32.dll",
    ]

    items = wrapper._parse_filescan(lines)

    assert len(items) == 1
    assert items[0]["value"].lower().endswith("payload.dll")


def test_volatility_extract_strings_filters_noise_and_recovers_registry():
    wrapper = VolatilityWrapper()
    corpus = "\n".join([
        "MALWARE.EXAMPLE.COM",
        "report.docx",
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyX",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        "C2.server.example.co.uk",
        "user@example.com",
    ])

    items = wrapper._extract_strings(corpus)
    values = {item["value"] for item in items}

    assert "malware.example.com" in values
    assert "c2.server.example.co.uk" in values
    assert "report.docx" not in values
    assert "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" in values
    assert "1BoatSLRHtKNngkdXEeobR76b53LETtpyX" not in values
    assert any(item["evidence_type"] == "registry_key" for item in items)


def test_memprocfs_api_branch_returns_process_items(monkeypatch):
    wrapper = MemProcFSWrapper()

    monkeypatch.setattr("src.wrappers.memprocfs_wrapper.log_action", lambda *args, **kwargs: None)

    fake_module = types.SimpleNamespace()

    class FakeProc:
        def __init__(self, pid, name, ppid):
            self.pid = pid
            self.name = name
            self.ppid = ppid

    class FakeVmm:
        def __init__(self, args):
            self.args = args

        def process_list(self):
            return [FakeProc(1234, "svchost.exe", 4)]

        def close(self):
            return None

    fake_module.Vmm = FakeVmm
    monkeypatch.setitem(sys.modules, "memprocfs", fake_module)

    items = wrapper.run("/tmp/sample.dmp")

    assert len(items) == 1
    assert items[0]["evidence_type"] == "memprocfs_process"
    assert "svchost.exe" in items[0]["value"]


def test_memprocfs_binary_branch_lists_mount_artifacts(tmp_path, monkeypatch):
    wrapper = MemProcFSWrapper()
    mount_dir = tmp_path / "memprocfs_mount"
    process_dir = mount_dir / "forensic" / "processes"
    process_dir.mkdir(parents=True)
    (process_dir / "System.exe").write_text("", encoding="utf-8")
    (process_dir / "payload.dll").write_text("", encoding="utf-8")

    monkeypatch.setattr("src.wrappers.memprocfs_wrapper.shutil.which", lambda _: "/usr/bin/memprocfs")
    monkeypatch.setattr("src.wrappers.memprocfs_wrapper.tempfile.mkdtemp", lambda prefix: str(mount_dir))
    monkeypatch.setattr(
        wrapper,
        "run_command",
        lambda command, input_files=None, output_files=None, timeout=300: ("", "", 0),
    )

    items = wrapper._run_binary("/tmp/sample.dmp")

    assert len(items) == 2
    assert all(item["evidence_type"] == "memprocfs_process" for item in items)
