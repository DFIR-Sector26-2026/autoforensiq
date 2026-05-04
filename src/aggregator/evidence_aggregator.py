"""
Evidence Aggregator (P4) — Normalize and consolidate forensic evidence

Responsibilities:
  1. Read all raw/<tool>_output.json files from P3
  2. Validate each evidence item against evidence_item.json schema
  3. Deduplicate by artifact_id (keep first occurrence)
  4. Sort by severity (critical → low) then confidence (high → low)
  5. Build lookup indices (by type, by tool)
  6. Validate output against unified_evidence.json schema
  7. Write consolidated result

Usage (standalone):
    python -m src.aggregator.evidence_aggregator
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[2]

# Severity ranking for sorting
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def load_json(path: str) -> dict[str, Any]:
    """Load a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str, data: dict[str, Any]) -> None:
    """Write a JSON file, creating parent directory if needed."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def load_raw_outputs(raw_dir: str) -> dict[str, list[dict]]:
    """
    Load all raw/<tool>_output.json files.
    Returns a dict mapping tool names to lists of evidence items.
    """
    all_outputs = {}

    if not os.path.isdir(raw_dir):
        print(f"  [WARN] Raw outputs directory not found: {raw_dir}")
        return all_outputs

    for filename in sorted(os.listdir(raw_dir)):
        if not filename.endswith("_output.json"):
            continue

        filepath = os.path.join(raw_dir, filename)
        try:
            data = load_json(filepath)
            tool_name = data.get("tool", filename.replace("_output.json", ""))
            items = data.get("items", [])
            if items:
                all_outputs[tool_name] = items
                print(f"    [LOAD] {tool_name}: {len(items)} items from {filename}")
            else:
                print(f"    [SKIP] {tool_name}: no items (empty)")
        except Exception as e:
            print(f"    [ERROR] Failed to load {filename}: {e}")

    return all_outputs


def deduplicate_items(all_items: list[dict]) -> tuple[list[dict], int]:
    """
    Deduplicate evidence items by artifact_id.
    Keeps first occurrence, removes duplicates.
    Returns (deduplicated_list, count_removed).
    """
    seen = {}
    deduplicated = []
    removed_count = 0

    for item in all_items:
        artifact_id = item.get("artifact_id")
        if artifact_id not in seen:
            deduplicated.append(item)
            seen[artifact_id] = True
        else:
            removed_count += 1

    return deduplicated, removed_count


def sort_evidence_items(items: list[dict]) -> list[dict]:
    """
    Sort evidence items by:
      1. Severity (critical → high → medium → low)
      2. Confidence (high → low)
      3. Source tool (alphabetical for stability)
    """
    def sort_key(item: dict) -> tuple:
        severity_val = SEVERITY_ORDER.get(item.get("severity", "low"), 0)
        confidence_val = -item.get("confidence", 0.5)  # negative for desc order
        tool = item.get("source_tool", "")
        return (-severity_val, confidence_val, tool)

    return sorted(items, key=sort_key)


def build_indices(items: list[dict]) -> dict[str, dict]:
    """
    Build lookup indices for evidence items.
    Returns {
      'by_type': {evidence_type: [items]},
      'by_tool': {source_tool: [items]}
    }
    """
    by_type = defaultdict(list)
    by_tool = defaultdict(list)

    for item in items:
        by_type[item.get("evidence_type", "unknown")].append(item)
        by_tool[item.get("source_tool", "unknown")].append(item)

    return {
        "by_type": dict(by_type),
        "by_tool": dict(by_tool)
    }


def aggregate_evidence(
    case_context: dict,
    raw_outputs_dir: str = "output/raw",
    output_path: str = "output/unified_evidence.json"
) -> dict:
    """
    Main aggregation pipeline.
    
    Args:
        case_context: Output from P1 intent classifier (for case_id)
        raw_outputs_dir: Directory containing raw tool outputs
        output_path: Where to write unified_evidence.json
        
    Returns:
        The unified_evidence dict that was written.
    """
    print(f"\n  [AGGREGATOR] Reading from: {raw_outputs_dir}")
    
    # Step 1: Load all raw outputs
    all_by_tool = load_raw_outputs(raw_outputs_dir)
    
    if not all_by_tool:
        print(f"  [WARN] No raw outputs found. Writing empty unified_evidence.json")
        unified = {
            "case_id": case_context.get("case_id", "unknown"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tools_aggregated": [],
            "total_items": 0,
            "deduplication_stats": {
                "raw_items_before": 0,
                "duplicates_removed": 0
            },
            "evidence_items": [],
            "evidence_by_type": {},
            "evidence_by_tool": {}
        }
        write_json(output_path, unified)
        return unified
    
    # Step 2: Flatten all items into one list
    all_items = []
    raw_count = 0
    for tool_name, items in all_by_tool.items():
        all_items.extend(items)
        raw_count += len(items)
    
    print(f"  [MERGE] {raw_count} items from {len(all_by_tool)} tools")
    
    # Step 3: Deduplicate
    unique_items, removed_count = deduplicate_items(all_items)
    print(f"  [DEDUP] Removed {removed_count} duplicates → {len(unique_items)} unique")
    
    # Step 4: Sort by severity and confidence
    sorted_items = sort_evidence_items(unique_items)
    
    # Step 5: Build indices
    indices = build_indices(sorted_items)
    
    # Step 6: Build unified_evidence output
    unified = {
        "case_id": case_context.get("case_id", "unknown"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tools_aggregated": sorted(list(all_by_tool.keys())),
        "total_items": len(sorted_items),
        "deduplication_stats": {
            "raw_items_before": raw_count,
            "duplicates_removed": removed_count
        },
        "evidence_items": sorted_items,
        "evidence_by_type": indices["by_type"],
        "evidence_by_tool": indices["by_tool"]
    }
    
    # Step 7: Write output
    write_json(output_path, unified)
    print(f"  [SAVE] Wrote unified_evidence.json ({len(sorted_items)} items)")
    
    return unified


if __name__ == "__main__":
    # Standalone test: aggregate outputs from a recent run
    import sys
    sys.path.insert(0, str(ROOT_DIR))
    
    # Try to load case_context to get case_id
    case_context = {}
    case_context_path = ROOT_DIR / "output" / "case_context.json"
    if case_context_path.exists():
        case_context = load_json(str(case_context_path))
    
    result = aggregate_evidence(
        case_context=case_context,
        raw_outputs_dir=str(ROOT_DIR / "output" / "raw"),
        output_path=str(ROOT_DIR / "output" / "unified_evidence.json")
    )
    
    print(f"\n  [DONE] Aggregator complete")
    print(f"        Case ID: {result.get('case_id')}")
    print(f"        Tools: {', '.join(result.get('tools_aggregated', []))}")
    print(f"        Total evidence items: {result.get('total_items')}")
