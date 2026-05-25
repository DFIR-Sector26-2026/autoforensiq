"""
pipeline.py
-----------
Stage 5 of the AutoForensiq pipeline: ML-based anomaly detection.

Called by autoforensiq.py as:

    shap_explanations = run_ml_pipeline(input_path, output_path, baseline_path)

Contract
--------
* ALWAYS returns a dict (never None)
* ALWAYS writes that same dict to output_path as shap_explanations.json
* Output dict shape:
    {
        "explanations": { "<artifact_id>": { is_anomaly, score,
                                             confidence, severity, reason } },
        "summary":      { total_items, anomalies_detected, normal_items },
        "generated_at": "<ISO-8601 timestamp>"
    }
"""

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
    """
    Collapse wrapper-specific evidence types into ML model families.
    """
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


def run_ml_pipeline(
    input_path:    str,
    output_path:   str,
    baseline_path: str,
) -> Dict[str, Any]:
    """
    Parameters
    ----------
    input_path    : path to unified_evidence.json   (Stage 4 output)
    output_path   : destination for shap_explanations.json
    baseline_path : path to baseline_normal.json

    Returns
    -------
    dict — always; never None.
    {
        "explanations": { artifact_id: { is_anomaly, score, confidence,
                                         severity, reason } },
        "summary":      { total_items, anomalies_detected, normal_items },
        "generated_at": "<ISO timestamp>"
    }
    """

    # ── 1. Load data ──────────────────────────────────────────────────────────
    log.info("[P5] Loading baseline from %s", baseline_path)
    baseline_records = json.loads(Path(baseline_path).read_text())

    log.info("[P5] Loading evidence from %s", input_path)
    evidence_records = json.loads(Path(input_path).read_text())

    # unified_evidence.json may be wrapped in a top-level object:
    #   { "evidence_items": [...] }  OR just a plain list
    if isinstance(evidence_records, dict):
        evidence_records = (
            evidence_records.get("evidence_items")
            or evidence_records.get("items")
            or []
        )

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
