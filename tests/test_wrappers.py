import os
import json
import pytest
from src.utils.audit_log import sha256_file, log_action
from src.wrappers.base_wrapper import BaseWrapper
from src.wrappers.volatility_wrapper import VolatilityWrapper
from src.agents.tool_selector import select_tools, load_json

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


def test_volatility_strings_plugin_uses_generated_strings_file(tmp_path, monkeypatch):
    image_path = tmp_path / "memory.dmp"
    image_path.write_bytes(b"\x00" * 16 + b"hello.onion\x00" + b"A" * 16)

    captured = {}

    def fake_run_command(self, command, input_files=None, output_files=None, timeout=300):
        if command[-1] == "-h":
            return "Volatility 3 Framework", "", 0

        if "windows.strings" in command:
            captured["command"] = command
            strings_index = command.index("--strings-file") + 1
            assert os.path.exists(command[strings_index])
            return "0 hello.onion\n", "", 0

        return "", "", 0

    monkeypatch.setattr(VolatilityWrapper, "run_command", fake_run_command)

    wrapper = VolatilityWrapper()
    items = wrapper.run(str(image_path))

    assert "--strings-file" in captured["command"]
    assert any(item["evidence_type"] == "suspicious_domain" for item in items)


def test_volatility_filescan_requires_staging_marker(tmp_path):
    wrapper = VolatilityWrapper()

    lines = [
        r"0x1 0x2 C:\Windows\System32\kernel32.dll",
        r"0x3 0x4 C:\Users\Public\Temp\payload.exe",
        r"0x5 0x6 C:\ProgramData\Startup\helper.dll",
    ]

    items = wrapper._parse_filescan(lines)

    assert len(items) == 2
    assert all("Users\\Public" in item["value"] or "ProgramData" in item["value"] for item in items)


def test_registry_hive_routes_to_regripper():
    ontology = load_json("src/data/tool_ontology.json")
    context = {
        "case_type": "ransomware",
        "artifact_types": ["registry_hive"],
    }

    selected = select_tools(context, ontology)

    assert [tool["name"] for tool in selected] == ["regripper"]
