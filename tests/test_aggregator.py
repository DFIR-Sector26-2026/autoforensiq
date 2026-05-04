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
            "tool": "volatility",
            "items": [
                {"artifact_id": "proc_1", "source_tool": "volatility", 
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
        assert "volatility" in result["tools_aggregated"]
        assert "tshark" in result["tools_aggregated"]
        assert len(result["evidence_by_tool"]["volatility"]) == 1
        assert len(result["evidence_by_tool"]["tshark"]) == 1
        
        # Check that provenance is maintained
        for item in result["evidence_items"]:
            assert item["source_tool"] in ["volatility", "tshark"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
