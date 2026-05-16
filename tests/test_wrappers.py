import os
import json
import pytest
from src.utils.audit_log import sha256_file, log_action
from src.wrappers.base_wrapper import BaseWrapper

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
