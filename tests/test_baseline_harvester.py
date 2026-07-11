import json

from src.ml.baseline_harvester import harvest_baseline


def _unified(items):
    return {"evidence_items": items}


def _item(**over):
    base = {"artifact_id": "a1", "source_tool": "tshark",
            "evidence_type": "network_connection", "timestamp": "",
            "value": "TCP 10.0.0.5 -> 93.184.216.34:443", "severity": "low",
            "confidence": 0.75, "linked_artifacts": ["x"], "ioc_match": []}
    base.update(over)
    return base


def test_only_unflagged_low_severity_items_are_harvested(tmp_path):
    # A planted IOC inside a "benign" sample must never be labeled normal: anything
    # flagged, non-low, or a status item stays out of the baseline.
    unified = tmp_path / "unified.json"
    baseline = tmp_path / "baseline.json"
    unified.write_text(json.dumps(_unified([
        _item(artifact_id="ok"),
        _item(artifact_id="flagged", ioc_match=["tor_hidden_service"]),
        _item(artifact_id="high", severity="high"),
        _item(artifact_id="status", evidence_type="memory_analysis_status"),
        _item(artifact_id="empty", value="   "),
    ])))
    added = harvest_baseline(str(unified), str(baseline))
    assert added == {"network": 1}
    records = json.loads(baseline.read_text())
    assert [r["artifact_id"] for r in records] == ["ok"]
    # case-specific links are stripped; the schema fields survive
    assert records[0]["linked_artifacts"] == []
    assert records[0]["confidence"] == 0.75


def test_harvest_dedupes_against_existing_baseline_across_runs(tmp_path):
    unified = tmp_path / "unified.json"
    baseline = tmp_path / "baseline.json"
    unified.write_text(json.dumps(_unified([_item()])))
    assert harvest_baseline(str(unified), str(baseline)) == {"network": 1}
    # same content again (e.g. re-running the same pcap) adds nothing
    assert harvest_baseline(str(unified), str(baseline)) == {}
    assert len(json.loads(baseline.read_text())) == 1


def test_per_scope_cap_limits_chatty_tools(tmp_path):
    unified = tmp_path / "unified.json"
    baseline = tmp_path / "baseline.json"
    items = [_item(artifact_id=f"n{i}", value=f"TCP conn {i}") for i in range(5)]
    unified.write_text(json.dumps(_unified(items)))
    added = harvest_baseline(str(unified), str(baseline), cap_per_scope=3)
    assert added == {"network": 3}
