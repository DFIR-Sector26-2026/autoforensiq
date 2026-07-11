"""Stage 5 (P5): ML anomaly detection. Contract: ALWAYS returns a dict (never None) and writes it
to output_path as shap_explanations.json — shape: {"explanations": {artifact_id: {is_anomaly,
score, confidence, severity, reason, ...}}, "summary": {...}, "generated_at": iso-ts}."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from src.ml.feature_engineering import extract_feature_matrix
from src.ml.anomaly_detector    import AnomalyDetector
from src.ml.xai_explainer       import (
    build_structured_explanation,
    compute_baseline_comparisons,
    compute_shap_explanations,
    explain,
)

log = logging.getLogger(__name__)


def _model_scope(record: Dict[str, Any]) -> str:
    """Collapse wrapper-specific evidence types into ML model families."""
    evidence_type = str(record.get("evidence_type", "")).lower()
    source_tool = str(record.get("source_tool", "")).lower()
    value = str(record.get("value", "")).lower()

    if (
        "network" in evidence_type
        or "connection" in evidence_type
        or "pcap" in evidence_type
        or source_tool == "tshark"
        or bool(record.get("has_network", False))
    ):
        return "network"

    if (
        "process" in evidence_type
        or "malfind" in evidence_type
        or source_tool == "volatility3"
        or bool(record.get("process_name"))
    ):
        return "process"

    if (
        "email" in evidence_type
        or "phishing" in evidence_type
        or source_tool == "email"
    ):
        return "email"

    if (
        "registry" in evidence_type
        or "hive" in evidence_type
        or source_tool == "regripper"
    ):
        return "registry"

    if (
        "browser" in evidence_type
        or source_tool == "browser"
    ):
        return "browser"

    if (
        "log" in evidence_type
        or "event" in evidence_type
        or source_tool == "plaso"
    ):
        return "log"

    if (
        "file" in evidence_type
        or "disk" in evidence_type
        or source_tool == "tsk_fls"
        or ".exe" in value
    ):
        return "file"

    return "generic"


def _group_records(records):
    groups = {}

    for idx, record in enumerate(records):
        scope = _model_scope(record)
        groups.setdefault(scope, []).append((idx, record))

    return groups


def _build_machine_index(evidence_records):
    # Build machine_id -> [full item] straight from evidence_records. The unified_evidence
    # `evidence_by_machine` index now holds artifact_id references rather than full objects (to keep
    # the file small), so rebuild the grouping here from the authoritative item list.
    machine_index = {}
    for record in evidence_records:
        machine_id = str(record.get("machine_id", "")).strip()
        if machine_id:
            machine_index.setdefault(machine_id, []).append(record)

    return machine_index


def _extract_artifact_ids(obj):
    ids = set()

    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "artifact_id" and isinstance(value, str):
                ids.add(value)
            elif key in (
                "artifact_ids",
                "linked_artifacts",
                "related_artifacts",
                "evidence_ids",
            ) and isinstance(value, list):
                ids.update(str(v) for v in value if isinstance(v, str))
            else:
                ids.update(_extract_artifact_ids(value))

    elif isinstance(obj, list):
        for value in obj:
            ids.update(_extract_artifact_ids(value))

    return ids


def _build_finding_lookup(findings):
    lookup = {}

    if not isinstance(findings, list):
        return lookup

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        for artifact_id in _extract_artifact_ids(finding):
            lookup.setdefault(artifact_id, []).append(finding)

    return lookup


def run_ml_pipeline(
    input_path:    str,
    output_path:   str,
    baseline_path: str,
) -> Dict[str, Any]:
    """unified_evidence.json + baseline_normal.json → shap_explanations.json. Always returns the
    output dict (see module docstring for the shape)."""

    # ── 1. Load data ──────────────────────────────────────────────────────────
    log.info("[P5] Loading baseline from %s", baseline_path)
    baseline_records = json.loads(Path(baseline_path).read_text())

    log.info("[P5] Loading evidence from %s", input_path)
    unified_evidence = json.loads(Path(input_path).read_text())
    evidence_records = unified_evidence.get("evidence_items", [])

    machine_index = _build_machine_index(evidence_records)
    findings_lookup = _build_finding_lookup(unified_evidence.get("findings", []))
    exfiltration_lookup = _build_finding_lookup(
        unified_evidence.get("exfiltration_findings", []))
    bulk_summary = unified_evidence.get("bulk_summary", {})

    # ── 2. Group evidence → train scoped models ───────────────────────────────
    baseline_groups = _group_records(baseline_records)
    evidence_groups = _group_records(evidence_records)
    grouped_explanations: Dict[int, Any] = {}
    anomaly_count = 0
    model_scopes = {}

    for scope, indexed_records in evidence_groups.items():
        matching_baseline = [
            record for _, record in baseline_groups.get(scope, [])
        ]
        baseline_scope = scope

        if not matching_baseline:
            matching_baseline = baseline_records
            baseline_scope = "all"

        records = [record for _, record in indexed_records]
        X_baseline, _ = extract_feature_matrix(matching_baseline)
        X_evidence, _ = extract_feature_matrix(records)

        detector = AnomalyDetector()
        detector.fit(X_baseline)
        predictions = detector.predict(X_evidence)
        shap_top_factors = compute_shap_explanations(
            detector=detector,
            X_baseline=X_baseline,
            X_evidence=X_evidence,
        )
        baseline_comparisons = compute_baseline_comparisons(
            X_baseline=X_baseline,
            X_evidence=X_evidence,
        )

        model_scopes[scope] = {
            "evidence_records": len(records),
            "baseline_scope": baseline_scope,
            "baseline_records_used": len(matching_baseline),
        }

        log.info(
            "[P5] Model scope=%s baseline_scope=%s baseline_records=%d evidence_records=%d",
            scope,
            baseline_scope,
            len(matching_baseline),
            len(records),
        )

        for local_idx, ((original_idx, record), pred) in enumerate(
            zip(indexed_records, predictions)
        ):
            explanation = explain(
                record     = record,
                features   = pred["features"],
                score      = pred["score"],
                is_anomaly = pred["is_anomaly"],
                confidence = pred["confidence"],
            )
            explanation["model_score"] = pred["model_score"]
            explanation["rule_score"] = pred["rule_score"]
            explanation["final_score"] = pred["score"]
            explanation["threshold"] = pred["threshold"]
            explanation["top_factors"] = shap_top_factors[local_idx]
            explanation["baseline_comparison"] = baseline_comparisons[local_idx]
            explanation["model_scope"] = scope
            explanation["baseline_scope"] = baseline_scope
            explanation["baseline_records_used"] = len(matching_baseline)
            explanation.update(
                build_structured_explanation(
                    record=record,
                    prediction=pred,
                    top_factors=shap_top_factors[local_idx],
                    baseline_comparison=baseline_comparisons[local_idx],
                    machine_items=machine_index.get(
                        str(record.get("machine_id", "")).strip(),
                        [],
                    ),
                    correlated_findings=findings_lookup.get(
                        str(record.get("artifact_id", "")),
                        [],
                    ),
                    exfiltration_findings=exfiltration_lookup.get(
                        str(record.get("artifact_id", "")),
                        [],
                    ),
                    bulk_summary=bulk_summary,
                )
            )

            grouped_explanations[original_idx] = explanation

            if explanation["is_anomaly"]:
                anomaly_count += 1

    # ── 3. Reassemble explanations in original evidence order ────────────────
    explanations: Dict[str, Any] = {}

    for idx, record in enumerate(evidence_records):
        artifact_id = str(record.get("artifact_id", "unknown"))
        explanations[artifact_id] = grouped_explanations[idx]

    # ── 4. Assemble output dict ───────────────────────────────────────────────
    output: Dict[str, Any] = {
        "explanations": explanations,
        "summary": {
            "total_items":        len(evidence_records),
            "anomalies_detected": anomaly_count,
            "normal_items":       len(evidence_records) - anomaly_count,
            "model_scopes":       model_scopes,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    # ── 5. Persist to output_path (required by autoforensiq.py) ──────────────
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)   # create output/ if needed
    out.write_text(json.dumps(output, indent=2))
    log.info("[P5] Results saved → %s  (%d anomalies / %d total)",
             out, anomaly_count, len(evidence_records))

    # ── 6. Always return the dict ─────────────────────────────────────────────
    return output
