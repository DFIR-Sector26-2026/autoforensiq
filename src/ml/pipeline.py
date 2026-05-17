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
from src.ml.xai_explainer       import explain

log = logging.getLogger(__name__)


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

    # ── 2. Featurise baseline → train model ───────────────────────────────────
    X_baseline, _ = extract_feature_matrix(baseline_records)
    detector = AnomalyDetector()
    detector.fit(X_baseline)
    log.info("[P5] Model trained on %d baseline records.", len(baseline_records))

    # ── 3. Featurise evidence → score ─────────────────────────────────────────
    X_evidence, _ = extract_feature_matrix(evidence_records)
    predictions    = detector.predict(X_evidence)

    # ── 4. Build explanations ─────────────────────────────────────────────────
    explanations: Dict[str, Any] = {}
    anomaly_count = 0

    for record, pred in zip(evidence_records, predictions):
        artifact_id = str(record.get("artifact_id", "unknown"))
        explanation = explain(
            record     = record,
            features   = pred["features"],
            score      = pred["score"],
            is_anomaly = pred["is_anomaly"],
            confidence = pred["confidence"],
        )
        explanations[artifact_id] = explanation
        if explanation["is_anomaly"]:
            anomaly_count += 1

    # ── 5. Assemble output dict ───────────────────────────────────────────────
    output: Dict[str, Any] = {
        "explanations": explanations,
        "summary": {
            "total_items":        len(evidence_records),
            "anomalies_detected": anomaly_count,
            "normal_items":       len(evidence_records) - anomaly_count,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    # ── 6. Persist to output_path (required by autoforensiq.py) ──────────────
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)   # create output/ if needed
    out.write_text(json.dumps(output, indent=2))
    log.info("[P5] Results saved → %s  (%d anomalies / %d total)",
             out, anomaly_count, len(evidence_records))

    # ── 7. Always return the dict ─────────────────────────────────────────────
    return output
