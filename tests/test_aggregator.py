"""Test suite for the Evidence Aggregator (P4)."""

import json
import os
import pytest
import tempfile
from src.aggregator.evidence_aggregator import (
    deduplicate_items,
    sort_evidence_items,
    build_indices,
    aggregate_evidence,
    load_raw_outputs
)
from autoforensiq import run_bulk_aggregation


def test_deduplicate_removes_duplicates():
    """Test that duplicate artifact IDs are removed."""
    items = [
        {"artifact_id": "item_1", "source_tool": "tool_a", "value": "test1"},
        {"artifact_id": "item_2", "source_tool": "tool_b", "value": "test2"},
        {"artifact_id": "item_1", "source_tool": "tool_c", "value": "test1_dup"},  # dup
    ]
    deduplicated, removed = deduplicate_items(items)
    assert len(deduplicated) == 2
    assert removed == 1
    assert deduplicated[0]["artifact_id"] == "item_1"
    assert deduplicated[0]["source_tool"] == "tool_a"  # keeps first


def test_sort_by_severity_and_confidence():
    """Test that items are sorted by severity then confidence."""
    items = [
        {"artifact_id": "a", "severity": "low", "confidence": 0.9, "source_tool": "tool"},
        {"artifact_id": "b", "severity": "critical", "confidence": 0.5, "source_tool": "tool"},
        {"artifact_id": "c", "severity": "high", "confidence": 0.95, "source_tool": "tool"},
    ]
    sorted_items = sort_evidence_items(items)
    # Should be: critical (b), high (c), low (a)
    assert sorted_items[0]["artifact_id"] == "b"
    assert sorted_items[1]["artifact_id"] == "c"
    assert sorted_items[2]["artifact_id"] == "a"


def test_build_indices():
    """Test that indices group items correctly."""
    items = [
        {"artifact_id": "a", "evidence_type": "process", "source_tool": "vol"},
        {"artifact_id": "b", "evidence_type": "network", "source_tool": "tshark"},
        {"artifact_id": "c", "evidence_type": "process", "source_tool": "vol"},
    ]
    indices = build_indices(items)
    
    assert len(indices["by_type"]["process"]) == 2
    assert len(indices["by_type"]["network"]) == 1
    assert len(indices["by_tool"]["vol"]) == 2
    assert len(indices["by_tool"]["tshark"]) == 1


def test_aggregate_evidence_with_empty_tools():
    """Test aggregation with no raw outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        case_context = {"case_id": "test_case_123"}
        result = aggregate_evidence(
            case_context=case_context,
            raw_outputs_dir=tmpdir,
            output_path=os.path.join(tmpdir, "unified.json")
        )
        
        assert result["case_id"] == "test_case_123"
        assert result["total_items"] == 0
        assert result["tools_aggregated"] == []
        assert result["evidence_items"] == []


def test_aggregate_evidence_preserves_provenance():
    """Test that tool provenance is maintained in output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create sample raw outputs
        raw_dir = os.path.join(tmpdir, "raw")
        os.makedirs(raw_dir)
        
        vol_output = {
            "tool": "volatility3",
            "items": [
                {"artifact_id": "proc_1", "source_tool": "volatility3",
                 "evidence_type": "process", "value": "test.exe", 
                 "severity": "high", "confidence": 0.9, 
                 "timestamp": "", "linked_artifacts": []}
            ]
        }
        tshark_output = {
            "tool": "tshark",
            "items": [
                {"artifact_id": "conn_1", "source_tool": "tshark",
                 "evidence_type": "network", "value": "1.2.3.4:80",
                 "severity": "low", "confidence": 0.8,
                 "timestamp": "", "linked_artifacts": ["proc_1"]}
            ]
        }
        
        with open(os.path.join(raw_dir, "volatility_output.json"), "w") as f:
            json.dump(vol_output, f)
        with open(os.path.join(raw_dir, "tshark_output.json"), "w") as f:
            json.dump(tshark_output, f)
        
        case_context = {"case_id": "test_case_456"}
        result = aggregate_evidence(
            case_context=case_context,
            raw_outputs_dir=raw_dir,
            output_path=os.path.join(tmpdir, "unified.json")
        )
        
        assert result["total_items"] == 2
        assert "volatility3" in result["tools_aggregated"]
        assert "tshark" in result["tools_aggregated"]
        assert len(result["evidence_by_tool"]["volatility3"]) == 1
        assert len(result["evidence_by_tool"]["tshark"]) == 1
        
        # Check that provenance is maintained
        for item in result["evidence_items"]:
            assert item["source_tool"] in ["volatility3", "tshark"]


def test_aggregate_evidence_builds_correlations_and_exfiltration():
    """Test that cross-tool correlations and the exfiltration rule are emitted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        raw_dir = os.path.join(tmpdir, "raw")
        os.makedirs(raw_dir)

        vol_output = {
            "tool": "volatility3",
            "items": [
                {
                    "artifact_id": "proc_4321_powershell_exe",
                    "source_tool": "volatility3",
                    "evidence_type": "process",
                    "value": "powershell.exe (PID:4321 PPID:100)",
                    "severity": "high",
                    "confidence": 0.9,
                    "timestamp": "2026-05-08T12:00:00Z",
                    "linked_artifacts": [],
                },
                {
                    "artifact_id": "proc_tree_4321",
                    "source_tool": "volatility3",
                    "evidence_type": "process_tree",
                    "value": "Suspicious parent-child: powershell.exe (PID:4321) under PPID:100",
                    "severity": "high",
                    "confidence": 0.85,
                    "timestamp": "2026-05-08T12:00:00Z",
                    "linked_artifacts": [],
                },
            ],
        }
        tshark_output = {
            "tool": "tshark",
            "items": [
                {
                    "artifact_id": "net_4321_4444",
                    "source_tool": "tshark",
                    "evidence_type": "network_connection",
                    "value": "TCP 10.0.0.5 → 185.220.101.47:4444 (1500000 bytes, 12 packets)",
                    "severity": "high",
                    "confidence": 0.8,
                    "timestamp": "2026-05-08T12:05:00Z",
                    "linked_artifacts": ["proc_4321_powershell_exe"],
                },
            ],
        }
        tsk_output = {
            "tool": "tsk_fls",
            "items": [
                {
                    "artifact_id": "timeline_payload",
                    "source_tool": "tsk_fls",
                    "evidence_type": "timeline_event",
                    "value": "[2026-05-08T12:01:00Z] modified → C:/Users/admin/AppData/Temp/payload.exe",
                    "severity": "medium",
                    "confidence": 0.7,
                    "timestamp": "2026-05-08T12:01:00Z",
                    "linked_artifacts": [],
                },
                {
                    "artifact_id": "file_payload",
                    "source_tool": "tsk_fls",
                    "evidence_type": "file_artifact",
                    "value": "Suspicious file: C:/Users/admin/AppData/Temp/payload.exe",
                    "severity": "medium",
                    "confidence": 0.75,
                    "timestamp": "2026-05-08T12:01:00Z",
                    "linked_artifacts": [],
                },
            ],
        }

        with open(os.path.join(raw_dir, "volatility_output.json"), "w") as f:
            json.dump(vol_output, f)
        with open(os.path.join(raw_dir, "tshark_output.json"), "w") as f:
            json.dump(tshark_output, f)
        with open(os.path.join(raw_dir, "tsk_output.json"), "w") as f:
            json.dump(tsk_output, f)

        case_context = {
            "case_id": "test_case_789",
            "affected_systems": ["WIN-ACCT-033"],
        }
        result = aggregate_evidence(
            case_context=case_context,
            raw_outputs_dir=raw_dir,
            output_path=os.path.join(tmpdir, "unified.json")
        )

        assert result["total_items"] == 5
        assert result["evidence_by_machine"]["WIN-ACCT-033"]
        assert any(f["correlation_type"] == "same_pid" for f in result["findings"])
        assert any(f["correlation_type"] == "exfiltration" for f in result["exfiltration_findings"])
        assert any(item.get("correlations") for item in result["evidence_items"])
        exfil = next(f for f in result["exfiltration_findings"] if f["correlation_type"] == "exfiltration")
        assert exfil["file"].endswith("payload.exe")
        assert exfil["destination"] == "185.220.101.47:4444"
        assert exfil["bytes_transferred"] == 1500000


def test_run_bulk_aggregation_writes_summary():
    """Test that the CLI bulk helper aggregates multiple machine bundles."""
    with tempfile.TemporaryDirectory() as tmpdir:
        machine_a_raw = os.path.join(tmpdir, "machine_a", "raw")
        machine_b_raw = os.path.join(tmpdir, "machine_b", "raw")
        output_root = os.path.join(tmpdir, "bulk_output")
        summary_path = os.path.join(tmpdir, "bulk_summary.json")
        os.makedirs(machine_a_raw)
        os.makedirs(machine_b_raw)

        shared_item = {
            "artifact_id": "proc_shared",
            "source_tool": "volatility3",
            "evidence_type": "process",
            "value": "powershell.exe (PID:9001 PPID:100)",
            "severity": "high",
            "confidence": 0.9,
            "timestamp": "2026-05-08T12:00:00Z",
            "linked_artifacts": [],
        }

        with open(os.path.join(machine_a_raw, "volatility_output.json"), "w") as f:
            json.dump({"tool": "volatility3", "items": [shared_item]}, f)

        with open(os.path.join(machine_b_raw, "volatility_output.json"), "w") as f:
            json.dump({"tool": "volatility3", "items": [shared_item]}, f)

        manifest = {
            "output_root": output_root,
            "summary_path": summary_path,
            "machines": [
                {
                    "machine_name": "machine_a",
                    "raw_outputs_dir": machine_a_raw,
                    "case_context": {"case_id": "case-a", "affected_systems": ["machine-a"]},
                },
                {
                    "machine_name": "machine_b",
                    "raw_outputs_dir": machine_b_raw,
                    "case_context": {"case_id": "case-b", "affected_systems": ["machine-b"]},
                },
            ],
        }

        manifest_path = os.path.join(tmpdir, "bulk_manifest.json")
        with open(manifest_path, "w") as f:
            json.dump(manifest, f)

        result = run_bulk_aggregation(manifest_path)

        assert os.path.exists(summary_path)
        assert result["bulk_summary"]["total_items"] == 2
        assert len(result["bulk_summary"]["machines"]) == 2
        assert result["bulk_summary"]["machines"][0]["findings"] >= 0


    def test_aggregate_evidence_builds_correlations_and_exfiltration():
        """Test that correlations and exfiltration findings are generated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            raw_dir = os.path.join(tmpdir, "raw")
            os.makedirs(raw_dir)

            vol_output = {
                "tool": "volatility3",
                "items": [
                    {"artifact_id": "proc_10", "source_tool": "volatility3",
                     "evidence_type": "process", "value": "svchost.exe (pid:10)",
                     "severity": "medium", "confidence": 0.7, "timestamp": "2023-01-01T10:00:00Z", "linked_artifacts": []},
                    {"artifact_id": "file_a", "source_tool": "volatility3",
                     "evidence_type": "file", "value": "C:\\Users\\user\\secrets.txt", 
                     "severity": "low", "confidence": 0.6, "timestamp": "2023-01-01T09:59:00Z", "linked_artifacts": []}
                ]
            }

            tshark_output = {
                "tool": "tshark",
                "items": [
                    {"artifact_id": "conn_1", "source_tool": "tshark",
                     "evidence_type": "network_connection", "value": "1.2.3.4:4444", 
                     "severity": "high", "confidence": 0.9, "timestamp": "1672560000", "linked_artifacts": []}
                ]
            }

            with open(os.path.join(raw_dir, "volatility_output.json"), "w") as f:
                json.dump(vol_output, f)
            with open(os.path.join(raw_dir, "tshark_output.json"), "w") as f:
                json.dump(tshark_output, f)

            case_context = {"case_id": "case_exf", "affected_systems": ["host-1"]}
            result = aggregate_evidence(
                case_context=case_context,
                raw_outputs_dir=raw_dir,
                output_path=os.path.join(tmpdir, "unified.json")
            )

            # Should have at least one finding and possibly exfiltration finding
            assert isinstance(result.get("findings"), list)
            assert isinstance(result.get("exfiltration_findings"), list)


    def test_run_bulk_aggregation_writes_summary():
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create two machine raw dirs
            machines = {
                "hostA": {"raw_outputs_dir": os.path.join(tmpdir, "hostA_raw"), "case_context": {"case_id": "hostA"}},
                "hostB": {"raw_outputs_dir": os.path.join(tmpdir, "hostB_raw"), "case_context": {"case_id": "hostB"}}
            }
            os.makedirs(machines["hostA"]["raw_outputs_dir"])
            os.makedirs(machines["hostB"]["raw_outputs_dir"])

            # Add a small tshark output for hostA
            tshark_output = {"tool": "tshark", "items": []}
            with open(os.path.join(machines["hostA"]["raw_outputs_dir"], "tshark_output.json"), "w") as f:
                json.dump(tshark_output, f)

            sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
            from src.aggregator.evidence_aggregator import aggregate_bulk_evidence

            summary = aggregate_bulk_evidence(machines, output_root=os.path.join(tmpdir, "bulk_out"))
            assert summary["machines"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
