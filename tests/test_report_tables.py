"""Tests for report table rendering robustness under multi-tool input.

Covers the Process Tree builder (structured PID/PPID, no cross-type leakage)
and the markdown cell sanitizer used by the IOC / MITRE / Critical Findings
tables.
"""

import json

from src.report_generator.report_generator import (
    _build_process_tree,
    _md_cell,
    _parse_flat_pids,
)


def test_md_cell_escapes_pipes_and_collapses_newlines():
    assert _md_cell("a | b") == "a \\| b"
    assert _md_cell("line1\nline2\r\nline3") == "line1 line2 line3"
    assert _md_cell("   spaced   out  ") == "spaced out"
    assert _md_cell("") == "-"
    assert _md_cell(None) == "-"


def test_parse_flat_pids_does_not_confuse_pid_with_ppid():
    # PPID appearing before PID must not bleed into the PID match.
    assert _parse_flat_pids("svchost.exe (PPID 1636, PID 1940)") == ("1940", "1636")
    assert _parse_flat_pids("tasksche.exe (PID:1940 PPID:1636)") == ("1940", "1636")
    # Only a PPID present -> PID stays None (no false match inside "ppid").
    assert _parse_flat_pids("orphan (PPID:1636)") == (None, "1636")


def test_process_tree_ignores_non_process_artifacts():
    items = [
        {"evidence_type": "file_artifact", "source_tool": "tsk_fls",
         "value": "Suspicious file: /tmp/pulse-ubuntu/pid", "severity": "high",
         "artifact_id": "file_1"},
        {"evidence_type": "network_connection", "source_tool": "volatility3",
         "value": "1.2.3.4:4444 [ESTABLISHED] PID:1940", "severity": "high",
         "artifact_id": "net_1"},
        {"evidence_type": "process", "source_tool": "volatility3",
         "value": "tasksche.exe (PID:1940 PPID:1636)", "severity": "critical",
         "artifact_id": "proc_1940_tasksche_exe"},
    ]
    tree = _build_process_tree(items, anomaly_ids=set())
    assert "tasksche.exe" in tree
    # The file and network artifacts must not appear as process rows.
    assert "pulse-ubuntu" not in tree
    assert "1.2.3.4" not in tree


def test_process_tree_renders_hierarchy_from_structured_json():
    tree_json = json.dumps({
        "pid": 1636, "ppid": 1608, "name": "explorer.exe", "cmdline": "",
        "suspicious": False, "reasons": [],
        "children": [
            {"pid": 1940, "ppid": 1636, "name": "tasksche.exe", "cmdline": "",
             "suspicious": True, "reasons": ["dropper"], "children": []},
        ],
    })
    items = [{
        "evidence_type": "process_tree", "source_tool": "volatility3",
        "value": tree_json, "severity": "medium",
        "artifact_id": "process_tree_1636",
    }]
    tree = _build_process_tree(items, anomaly_ids=set())
    lines = tree.splitlines()
    parent = next(l for l in lines if "explorer.exe" in l)
    child = next(l for l in lines if "tasksche.exe" in l)
    # Child is indented deeper than its parent and carries the correct PID/PPID.
    assert child.index("tasksche.exe") > parent.index("explorer.exe")
    assert "PID 1940" in child and "PPID 1636" in child
    # Suspicious child is flagged; benign parent is not.
    assert "[!]" in child
    assert parent.strip().startswith("[ ]")


def test_process_tree_empty_when_no_processes():
    items = [{"evidence_type": "dns_query", "value": "evil.com",
              "artifact_id": "dns_1", "source_tool": "tshark"}]
    assert _build_process_tree(items, anomaly_ids=set()) == \
        "_No process artifacts in evidence._"
