from src.ioc.ioc_engine import extract_iocs


def _ids(iocs):
    return [i["artifact_id"] for i in iocs]


def test_emitted_ioc_ids_are_unique_for_multi_match_item():
    # A single process_relation item matches BOTH process names in the
    # SUSPICIOUS_PROCESSES loop. Previously every match reused
    # `ioc_proc_<source_id>`, colliding; the matched token must make them unique.
    rel = {
        "artifact_id": "rel_1940_740",
        "evidence_type": "process_relation",
        "value": "tasksche.exe -> @WanaDecryptor@",
    }
    iocs = extract_iocs([rel])
    ids = _ids(iocs)
    assert len(ids) == len(set(ids)), f"colliding ids: {ids}"
    # both process matches present, distinguished by token suffix
    assert "ioc_proc_rel_1940_740_tasksche_exe" in ids
    assert "ioc_proc_rel_1940_740_wanadecryptor" in ids
    # the lineage IOC is still emitted
    assert "ioc_relation_rel_1940_740_tasksche_exe_wanadecryptor" in ids


def test_process_tree_aggregate_is_skipped():
    # The process_tree blob is a summary of processes scored individually
    # elsewhere; scanning it re-derives duplicate IOCs (issue 4.4). It must be
    # skipped so it contributes no ioc_* items at all.
    tree = {
        "artifact_id": "process_tree_1636",
        "evidence_type": "process_tree",
        "value": "explorer.exe (1636) -> tasksche.exe (1940) -> @WanaDecryptor@ (740)",
    }
    iocs = extract_iocs([tree])
    assert iocs == []


def test_genuine_process_iocs_survive_without_the_tree():
    # Skipping the tree must not lose real detections: the same processes exist
    # as their own per-PID `process` items, which are still scanned.
    items = [
        {"artifact_id": "process_tree_1636", "evidence_type": "process_tree",
         "value": "explorer.exe (1636) -> tasksche.exe (1940)"},
        {"artifact_id": "process_1940", "evidence_type": "process",
         "value": "tasksche.exe (PID 1940)"},
        {"artifact_id": "process_740", "evidence_type": "process",
         "value": "@WanaDecryptor@ (PID 740)"},
    ]
    iocs = extract_iocs(items)
    ids = _ids(iocs)
    assert "ioc_proc_process_1940_tasksche_exe" in ids
    assert "ioc_proc_process_740_wanadecryptor" in ids
    # nothing derived from the skipped tree
    assert not any("process_tree_1636" in i for i in ids)


def test_duplicate_indicator_across_items_is_deduped_with_merged_links():
    # IOC-redundancy: the same indicator seen across N source items used to emit
    # N near-identical ioc items differing only by linked_artifacts. They must
    # collapse to ONE item per (value, severity), carrying all source links.
    items = [
        {"artifact_id": "file_a", "evidence_type": "file_artifact",
         "value": "C:\\Users\\Public\\tasksche.exe"},
        {"artifact_id": "file_b", "evidence_type": "file_artifact",
         "value": "C:\\Windows\\tasksche.exe"},
        {"artifact_id": "proc_1940", "evidence_type": "process",
         "value": "tasksche.exe (PID 1940)"},
    ]
    iocs = extract_iocs(items)
    tasksche = [i for i in iocs
                if i["value"] == "Suspicious process detected: tasksche.exe"]
    assert len(tasksche) == 1
    # every source that saw the indicator is preserved as a link
    assert set(tasksche[0]["linked_artifacts"]) == {"file_a", "file_b", "proc_1940"}


def test_distinct_indicators_are_not_collapsed():
    # Dedup keys on (value, severity), so genuinely different indicators (even at
    # the same severity) must survive as separate items.
    items = [
        {"artifact_id": "proc_1", "evidence_type": "process",
         "value": "tasksche.exe seen"},
        {"artifact_id": "proc_2", "evidence_type": "process",
         "value": "@WanaDecryptor@ seen"},
    ]
    iocs = extract_iocs(items)
    values = {i["value"] for i in iocs}
    assert "Suspicious process detected: tasksche.exe" in values
    assert "Suspicious process detected: @WanaDecryptor@" in values
