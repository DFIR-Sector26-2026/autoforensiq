"""
Evidence Aggregator (P4) — Normalize and consolidate forensic evidence

Responsibilities:
  1. Read all raw/<tool>_output.json files from P3
  2. Validate each evidence item against evidence_item.json schema (warns on violation)
  3. Deduplicate by artifact_id (keep first occurrence)
  4. Sort by severity (critical → low) then confidence (high → low)
  5. Build lookup indices (by type, by tool)
  6. Validate output against unified_evidence.json schema (warns on violation)
  7. Write consolidated result

Usage (standalone):
    python -m src.aggregator.evidence_aggregator
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from typing import Any
import jsonschema

from src.aggregator.ioc_rescorer import load_ioc_catalog, rescore_items

ROOT_DIR = Path(__file__).resolve().parents[2]

# Severity ranking for sorting
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# IOC catalog for post-aggregation severity re-scoring (loaded once).
_IOC_CATALOG = load_ioc_catalog()


def load_json(path: str) -> dict[str, Any]:
    """Load a JSON file."""
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


_SCHEMAS_DIR = ROOT_DIR / "src" / "schemas"
_EVIDENCE_ITEM_SCHEMA = load_json(str(_SCHEMAS_DIR / "evidence_item.json")) if (_SCHEMAS_DIR / "evidence_item.json").exists() else None
_UNIFIED_EVIDENCE_SCHEMA = load_json(str(_SCHEMAS_DIR / "unified_evidence.json")) if (_SCHEMAS_DIR / "unified_evidence.json").exists() else None


def write_json(path: str, data: dict[str, Any]) -> None:
    """Write a JSON file, creating parent directory if needed."""
    p = Path(path)
    if p.parent:
        p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
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

    raw_path = Path(raw_dir)
    if not raw_path.exists():
        return all_outputs

    for filename in sorted([p.name for p in raw_path.iterdir() if p.is_file()]):
        if not filename.endswith("_output.json"):
            continue

        filepath = raw_path / filename
        try:
            data = load_json(filepath)
            tool_name = data.get("tool", filename.replace("_output.json", ""))
            items = data.get("items", [])
            if items:
                if _EVIDENCE_ITEM_SCHEMA:
                    for item in items:
                        try:
                            jsonschema.validate(instance=item, schema=_EVIDENCE_ITEM_SCHEMA)
                        except jsonschema.ValidationError as ve:
                            print(f"    [WARN] Schema violation in {filename}: {ve.message}")
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
        if not artifact_id:
            print(f"  [WARN] Skipping item missing artifact_id: {item.get('value', '<no value>')}")
            deduplicated.append(item)
            continue
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
        # Within a tier, rule-based catalog matches (ioc_match populated by the
        # re-scorer) outrank pure-heuristic items so real IOCs survive the
        # downstream findings cap
        has_ioc = 1 if item.get("ioc_match") else 0
        confidence_val = -item.get("confidence", 0.5)  # negative for desc order
        tool = item.get("source_tool", "")
        return (-severity_val, -has_ioc, confidence_val, tool)

    return sorted(items, key=sort_key)


def build_indices(items: list[dict]) -> dict[str, dict]:
    """
    Build lookup indices for evidence items.
    Returns {
      'by_type': {evidence_type: [items]},
      'by_tool': {source_tool: [items]},
      'by_machine': {machine_id: [items]}
    }
    """
    by_type = defaultdict(list)
    by_tool = defaultdict(list)
    by_machine = defaultdict(list)

    for item in items:
        by_type[item.get("evidence_type", "unknown")].append(item)
        by_tool[item.get("source_tool", "unknown")].append(item)
        by_machine[item.get("machine_id", "unknown")].append(item)

    return {
        "by_type": dict(by_type),
        "by_tool": dict(by_tool),
        "by_machine": dict(by_machine)
    }


# --- Normalisation / signal extraction helpers --------------------------------
PID_RE = re.compile(r"\bpid[:\s#]*(\d+)\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
WINDOWS_PATH_RE = re.compile(r"(?:[A-Za-z]:\\[^|<>\"\r\n\t]+|\\\\[^|<>\"\r\n\t]+)")
UNIX_PATH_RE = re.compile(r"(?:/(?:[^\s\"'<>|]+))")
BYTES_RE = re.compile(r"(\d[\d,]*)\s+bytes", re.IGNORECASE)
DESTINATION_RE = re.compile(
    r"(?P<dst>(?:\d{1,3}\.){3}\d{1,3})(?::(?P<port>\d+))?\s*(?:\(|$)"
)
EXFIL_BYTES_THRESHOLD = 1_000_000
EXFIL_TIME_WINDOW_SECONDS = 24 * 60 * 60


def _normalize_whitespace(value: Any) -> str:
    return " ".join(str(value or "").split())


def _normalize_path(path: str) -> str:
    normalized = path.strip().rstrip(".,;)]")
    normalized = normalized.replace("/", "\\")
    normalized = re.sub(r"\\{2,}", r"\\", normalized)
    return normalized


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        try:
            return datetime.fromtimestamp(float(text), tz=timezone.utc)
        except Exception:
            return None

    candidates = [text, text.replace("Z", "+00:00")]
    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%a %b %d %H:%M:%S %Y",
    ):
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.replace(tzinfo=timezone.utc)
        except Exception:
            continue

    return None


def _timestamp_bucket(value: Any) -> str:
    parsed = _parse_timestamp(value)
    if parsed:
        return parsed.replace(second=0, microsecond=0).isoformat()
    return _normalize_whitespace(value)


def _extract_pids(text: str) -> list[str]:
    pids = set(PID_RE.findall(text))
    pids.update(re.findall(r"\b(?:proc|cmdline|net|malfind|timeline)_(\d+)\b", text, re.IGNORECASE))
    return sorted(pids)


def _extract_ips(text: str) -> list[str]:
    return sorted(set(IP_RE.findall(text)))


def _extract_paths(text: str) -> list[str]:
    candidates = []
    for match in WINDOWS_PATH_RE.findall(text):
        candidates.append(_normalize_path(match))
    for match in UNIX_PATH_RE.findall(text):
        candidates.append(_normalize_path(match))
    deduplicated = []
    seen = set()
    for candidate in candidates:
        key = candidate.lower()
        if key not in seen:
            seen.add(key)
            deduplicated.append(candidate)
    return deduplicated


def _extract_bytes(text: str) -> int:
    match = BYTES_RE.search(text)
    if not match:
        return 0
    try:
        return int(match.group(1).replace(",", ""))
    except Exception:
        return 0


def _extract_destination(text: str) -> tuple[str, int]:
    match = DESTINATION_RE.search(text)
    if not match:
        ips = _extract_ips(text)
        return (ips[-1] if ips else "", 0)
    destination_ip = match.group("dst")
    destination_port = int(match.group("port") or 0)
    return destination_ip, destination_port


def _default_machine_id(case_context: dict) -> str:
    affected_systems = case_context.get("affected_systems") or []
    if affected_systems:
        return str(affected_systems[0])
    return str(case_context.get("case_id", "unknown"))


def _extract_item_signals(item: dict, default_machine: str) -> dict[str, Any]:
    artifact_id = str(item.get("artifact_id", ""))
    source_tool = str(item.get("source_tool", ""))
    evidence_type = str(item.get("evidence_type", ""))
    raw_value = str(item.get("value", ""))
    normalized_value = _normalize_whitespace(raw_value)
    combined = " ".join([artifact_id, source_tool, evidence_type, raw_value, normalized_value])

    timestamp_value = item.get("timestamp", "")
    timestamp_dt = _parse_timestamp(timestamp_value)

    # The process_tree aggregate summarises an entire subtree, so its value
    # names every PID/path it contains. Extracting correlation signals from it
    # would make it spuriously join — and, being high-confidence, anchor —
    # every PID group, duplicating correlations the per-PID process/cmdline
    # items already carry. Treat it as a non-participant: keep the item but give
    # it no correlation signals.
    if evidence_type == "process_tree":
        pids, ips, paths = [], [], []
    else:
        pids = _extract_pids(combined)
        ips = _extract_ips(combined)
        paths = _extract_paths(combined)
    destination_ip, destination_port = _extract_destination(combined)

    file_keys = []
    for path in paths:
        normalized_path = _normalize_path(path)
        file_keys.append(normalized_path.lower())
        file_name = os.path.basename(normalized_path)
        if file_name:
            file_keys.append(file_name.lower())
    file_keys = sorted(set(file_keys))

    return {
        "artifact_id": artifact_id,
        "source_tool": source_tool,
        "evidence_type": evidence_type,
        "raw_value": raw_value,
        "normalized_value": normalized_value,
        "timestamp": timestamp_value,
        "timestamp_dt": timestamp_dt,
        "timestamp_bucket": _timestamp_bucket(timestamp_value),
        "machine_id": str(item.get("machine_id") or default_machine),
        "pids": pids,
        "ips": ips,
        "paths": paths,
        "file_keys": file_keys,
        "bytes_transferred": _extract_bytes(combined),
        "destination_ip": destination_ip,
        "destination_port": destination_port,
    }


def enrich_evidence_items(items: list[dict], case_context: dict) -> tuple[list[dict], dict[str, dict[str, Any]]]:
    default_machine = _default_machine_id(case_context)
    enriched_items = []
    signals_by_artifact = {}

    for item in items:
        enriched_item = dict(item)
        artifact_id = str(enriched_item.get("artifact_id", ""))
        enriched_item["raw_value"] = str(enriched_item.get("value", ""))
        enriched_item["normalized_value"] = _normalize_whitespace(enriched_item.get("value", ""))
        enriched_item["machine_id"] = str(enriched_item.get("machine_id") or default_machine)
        if not isinstance(enriched_item.get("correlations"), list):
            enriched_item["correlations"] = []
        signals_by_artifact[artifact_id] = _extract_item_signals(enriched_item, default_machine)
        enriched_items.append(enriched_item)

    return enriched_items, signals_by_artifact


def _select_anchor(items: list[dict]) -> dict:
    return sort_evidence_items(items)[0]


def _correlation_confidence(items: list[dict], base: float = 0.75) -> float:
    unique_tools = len({item.get("source_tool", "") for item in items if item.get("source_tool")})
    support_count = max(len(items) - 1, 0)
    confidence = base + (0.06 * min(unique_tools, 4)) + (0.03 * min(support_count, 5))
    return round(min(confidence, 0.99), 2)


def _finding_matches(anchor: dict, related_items: list[dict]) -> list[dict]:
    matches = []
    for item in related_items:
        if item.get("artifact_id") == anchor.get("artifact_id"):
            continue
        matches.append({
            "artifact_id": item.get("artifact_id", ""),
            "source_tool": item.get("source_tool", ""),
            "evidence_type": item.get("evidence_type", ""),
            "value": item.get("normalized_value", item.get("value", "")),
            "timestamp": item.get("timestamp", ""),
        })
    return matches


def _make_finding(
    anchor: dict,
    related_items: list[dict],
    correlation_type: str,
    finding: str,
    what_confirmed_it: list[str],
    confidence: float,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    related_artifacts = [item.get("artifact_id", "") for item in related_items]
    related_tools = sorted({item.get("source_tool", "") for item in related_items if item.get("source_tool")})
    output = {
        "item": anchor.get("artifact_id", ""),
        "matches": _finding_matches(anchor, related_items),
        "confidence": round(confidence, 2),
        "correlation_type": correlation_type,
        "finding": finding,
        "what_confirmed_it": what_confirmed_it,
        # Deduped: the anchor is selected from related_items, so its id is also
        # in related_artifacts; without dedup it would appear twice and each
        # consumer (annotate_item_correlations) would record the finding twice.
        "artifacts": list(dict.fromkeys(
            [anchor.get("artifact_id", "")] + [artifact for artifact in related_artifacts if artifact]
        )),
        "source_tools": sorted(set([anchor.get("source_tool", "")] + related_tools)),
    }
    if extra:
        output.update(extra)
    return output


def _group_items_by_signal(items: list[dict], signals: dict[str, dict[str, Any]], key_name: str) -> list[dict[str, Any]]:
    grouped = defaultdict(list)
    for item in items:
        signal = signals.get(item.get("artifact_id", ""), {})
        keys = signal.get(key_name) or []
        if isinstance(keys, str):
            keys = [keys]
        for key in keys:
            if key:
                grouped[key].append(item)

    findings = []
    for key, related_items in grouped.items():
        if len(related_items) < 2:
            continue
        anchor = _select_anchor(related_items)
        if key_name == "pids":
            finding = f"PID {key} observed across multiple artifacts"
            reasons = [f"Same PID {key} appeared in multiple artifacts"]
        elif key_name == "ips":
            finding = f"IP {key} observed across multiple artifacts"
            reasons = [f"Same IP {key} appeared in multiple artifacts"]
        elif key_name == "file_keys":
            finding = f"File {key} observed across multiple artifacts"
            reasons = [f"Same file/path {key} appeared in multiple artifacts"]
        else:
            finding = f"Shared {key_name[:-1] if key_name.endswith('s') else key_name} bucket {key} observed across multiple artifacts"
            reasons = [f"Same timestamp bucket {key} appeared in multiple artifacts"]

        findings.append(_make_finding(
            anchor=anchor,
            related_items=related_items,
            correlation_type={
                "pids": "same_pid",
                "ips": "same_ip",
                "file_keys": "same_file",
                "timestamp_bucket": "same_timestamp",
            }.get(key_name, key_name),
            finding=finding,
            what_confirmed_it=reasons,
            confidence=_correlation_confidence(related_items),
            extra={"signal": key},
        ))

    return findings


def _build_exfiltration_findings(items: list[dict], signals: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    file_events = []
    network_events = []

    for item in items:
        signal = signals.get(item.get("artifact_id", ""), {})
        timestamp_dt = signal.get("timestamp_dt")
        if not signal.get("file_keys") or timestamp_dt is None:
            continue

        file_events.append({
            "item": item,
            "signal": signal,
            "paths": signal.get("paths", []),
        })

    for item in items:
        signal = signals.get(item.get("artifact_id", ""), {})
        if item.get("evidence_type") != "network_connection":
            continue
        if signal.get("bytes_transferred", 0) < EXFIL_BYTES_THRESHOLD:
            continue
        if signal.get("timestamp_dt") is None:
            continue
        network_events.append({"item": item, "signal": signal})

    findings = []
    for network_event in network_events:
        network_signal = network_event["signal"]
        network_dt = network_signal["timestamp_dt"]
        destination = network_signal.get("destination_ip", "")
        if network_signal.get("destination_port"):
            destination = f"{destination}:{network_signal['destination_port']}"

        matching_file_events = []
        for file_event in file_events:
            file_signal = file_event["signal"]
            file_dt = file_signal.get("timestamp_dt")
            if file_dt is None or network_dt is None:
                continue
            if file_dt > network_dt:
                continue
            delta = (network_dt - file_dt).total_seconds()
            if delta > EXFIL_TIME_WINDOW_SECONDS:
                continue

            shared_keys = set(file_signal.get("file_keys", [])) & set(network_signal.get("file_keys", []))
            path_overlap = shared_keys or file_signal.get("paths")
            if not path_overlap:
                continue

            matching_file_events.append(file_event)

        if not matching_file_events:
            continue

        anchor = network_event["item"]
        supporting_items = [event["item"] for event in matching_file_events]
        primary_file = matching_file_events[0]["signal"].get("paths", [])
        primary_file_path = primary_file[0] if primary_file else matching_file_events[0]["item"].get("normalized_value", matching_file_events[0]["item"].get("value", ""))
        findings.append(_make_finding(
            anchor=anchor,
            related_items=supporting_items,
            correlation_type="exfiltration",
            finding=f"Large outbound transfer of {primary_file_path} to {destination}",
            what_confirmed_it=[
                "Large outbound traffic exceeded the exfiltration threshold",
                "File activity was observed before the outbound transfer",
                "The file path matched disk/timeline evidence from TSK",
            ],
            confidence=_correlation_confidence([anchor] + supporting_items, base=0.82),
            extra={
                "file": primary_file_path,
                "destination": destination,
                "timestamp": network_signal.get("timestamp", ""),
                "bytes_transferred": network_signal.get("bytes_transferred", 0),
            },
        ))

    return findings


def annotate_item_correlations(items: list[dict], findings: list[dict[str, Any]]) -> list[dict]:
    by_artifact = defaultdict(list)
    for finding in findings:
        anchor_id = finding.get("item", "")
        correlation_entry = {
            "artifact_id": anchor_id,
            "correlation_type": finding.get("correlation_type", ""),
            "matches": [match.get("artifact_id", "") for match in finding.get("matches", []) if match.get("artifact_id")],
            "confidence": finding.get("confidence", 0.0),
            "reason": finding.get("what_confirmed_it", [""])[0],
            "finding": finding.get("finding", ""),
        }
        for artifact_id in dict.fromkeys(finding.get("artifacts", [])):
            if artifact_id:
                by_artifact[artifact_id].append(correlation_entry)

    enriched = []
    for item in items:
        artifact_id = item.get("artifact_id", "")
        enriched_item = dict(item)
        enriched_item["correlations"] = sorted(
            by_artifact.get(artifact_id, []),
            key=lambda entry: entry.get("confidence", 0.0),
            reverse=True,
        )
        enriched.append(enriched_item)

    return enriched


def build_correlations(items: list[dict], signals: dict[str, dict[str, Any]]) -> tuple[list[dict], list[dict]]:
    findings = []
    findings.extend(_group_items_by_signal(items, signals, "pids"))
    findings.extend(_group_items_by_signal(items, signals, "ips"))
    findings.extend(_group_items_by_signal(items, signals, "file_keys"))
    findings.extend(_group_items_by_signal(items, signals, "timestamp_bucket"))
    findings.extend(_build_exfiltration_findings(items, signals))

    findings = sorted(
        findings,
        key=lambda finding: (
            -finding.get("confidence", 0.0),
            finding.get("correlation_type", ""),
            finding.get("item", ""),
        ),
    )

    annotated_items = annotate_item_correlations(items, findings)
    return annotated_items, findings


def build_bulk_summary(unified: dict) -> dict[str, Any]:
    evidence_items = unified.get("evidence_items", [])
    machine_ids = sorted({item.get("machine_id", "unknown") for item in evidence_items})
    return {
        "machines_analyzed": len(machine_ids),
        "machine_ids": machine_ids,
        "findings_detected": len(unified.get("findings", [])),
        "exfiltration_findings": len(unified.get("exfiltration_findings", [])),
    }


def aggregate_bulk_evidence(
    machine_runs: dict[str, dict[str, Any]],
    output_root: str = "output/bulk"
) -> dict[str, Any]:
    """
    Aggregate evidence for multiple machines.

    machine_runs should map a machine label to a dictionary containing:
      - case_context: dict
      - raw_outputs_dir: str
      - output_path: optional str
    """
    summary = {
        "machines": [],
        "total_items": 0,
        "total_findings": 0,
        "output_root": output_root,
    }

    Path(output_root).mkdir(parents=True, exist_ok=True)

    for machine_name, machine_spec in machine_runs.items():
        machine_case_context = machine_spec.get("case_context") or {"case_id": machine_name}
        machine_raw_dir = machine_spec.get("raw_outputs_dir")
        machine_output_path = machine_spec.get("output_path") or str(
            Path(output_root) / f"{machine_name}_unified_evidence.json"
        )
        if not machine_raw_dir:
            continue

        unified = aggregate_evidence(
            case_context=machine_case_context,
            raw_outputs_dir=machine_raw_dir,
            output_path=machine_output_path,
        )
        summary["machines"].append({
            "machine_name": machine_name,
            "case_id": unified.get("case_id", "unknown"),
            "total_items": unified.get("total_items", 0),
            "findings": len(unified.get("findings", [])),
            "output_path": machine_output_path,
        })
        summary["total_items"] += unified.get("total_items", 0)
        summary["total_findings"] += len(unified.get("findings", []))

    return summary


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
            "evidence_by_tool": {},
            "evidence_by_machine": {},
            "findings": [],
            "exfiltration_findings": [],
            "bulk_summary": {
                "machines_analyzed": 0,
                "machine_ids": [],
                "findings_detected": 0,
                "exfiltration_findings": 0,
            }
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

    # Step 3b: IOC re-scoring (boost severity on known indicators).
    # Must run BEFORE sort, which keys on severity.
    unique_items, boosted_count = rescore_items(unique_items, _IOC_CATALOG, case_context)
    print(f"  [IOC] Re-scored severity on {boosted_count} item(s)")

    # Step 4: Enrich items with normalized values and machine grouping
    enriched_items, signals_by_artifact = enrich_evidence_items(unique_items, case_context)

    # Step 5: Sort by severity and confidence
    sorted_items = sort_evidence_items(enriched_items)

    # Step 6: Build correlations and indices
    annotated_items, findings = build_correlations(sorted_items, signals_by_artifact)
    exfiltration_findings = [finding for finding in findings if finding.get("correlation_type") == "exfiltration"]
    indices = build_indices(annotated_items)


    # Step 7: Build unified_evidence output
    unified = {
        "case_id": case_context.get("case_id", "unknown"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tools_aggregated": sorted(list(all_by_tool.keys())),
        "total_items": len(annotated_items),
        "deduplication_stats": {
            "raw_items_before": raw_count,
            "duplicates_removed": removed_count
        },
        "evidence_items": annotated_items,
        "evidence_by_type": indices["by_type"],
        "evidence_by_tool": indices["by_tool"],
        "evidence_by_machine": indices["by_machine"],
        "findings": findings,
        "exfiltration_findings": exfiltration_findings,
        "bulk_summary": build_bulk_summary({"evidence_items": annotated_items, "findings": findings, "exfiltration_findings": exfiltration_findings}),
    }

    # Step 8: Validate output schema
    if _UNIFIED_EVIDENCE_SCHEMA:
        try:
            resolver = jsonschema.RefResolver(
                base_uri=_SCHEMAS_DIR.as_uri() + "/",
                referrer=_UNIFIED_EVIDENCE_SCHEMA,
            )
            jsonschema.validate(instance=unified, schema=_UNIFIED_EVIDENCE_SCHEMA, resolver=resolver)
        except jsonschema.ValidationError as ve:
            print(f"  [WARN] Output schema violation: {ve.message}")

    # Step 9: Write output
    write_json(output_path, unified)
    print(f"  [SAVE] Wrote unified_evidence.json ({len(annotated_items)} items, {len(findings)} findings)")

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
