"""
anomaly_detector.py
-------------------
Trains an IsolationForest on baseline-normal data, then scores new evidence.

Key design decisions
--------------------
1.  contamination=0.01  – we tell the model the baseline is almost pure normal;
    this pushes anomaly thresholds outward so real outliers score strongly.

2.  n_estimators=200    – more trees → more stable anomaly scores, important
    when the training set is small (5 records).

3.  Rule-based score boost – adds a deterministic penalty for features that
    are always anomalous regardless of the model (C2 ports, EXE in Temp, etc.).
    This prevents the model from under-scoring obvious threats just because the
    training set is tiny.

4.  Calibrated confidence – maps the raw IF score (typically -1 to +0.5) to a
    [0, 1] confidence band that is meaningful for an analyst.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from typing import List, Tuple, Dict, Any

from src.ml.feature_engineering import FEATURE_NAMES


# ── Rule-based booster ────────────────────────────────────────────────────────
# Maps feature-index → extra negative score to add when feature == 1.
# Negative = more anomalous (mirrors IsolationForest sign convention).
RULE_BOOSTS: Dict[int, float] = {
    1:  -0.30,   # is_suspicious_process
    2:  -0.20,   # suspicious_parent
    4:  -0.35,   # port_is_known_c2
    9:  -0.15,   # path_in_temp
    10: -0.30,   # path_has_exe_in_temp
    11: -0.35,   # keyword_c2_indicator
    12: -0.20,   # keyword_exfil
}

# Severity score (feature 13) amplifier
SEVERITY_AMPLIFIER = -0.25   # maximum penalty at severity=1.0 (critical)

ANOMALY_THRESHOLD = -0.10    # scores below this → anomaly


class AnomalyDetector:

    def __init__(self):
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.01,   # baseline is nearly 100 % clean
            max_samples="auto",
            random_state=42,
            bootstrap=False,
        )
        self._fitted = False

    # ── Training ──────────────────────────────────────────────────────────────

    def fit(self, X: np.ndarray) -> None:
        """Train on baseline-normal feature matrix."""
        self.model.fit(X)
        self._fitted = True

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _model_score(self, X: np.ndarray) -> np.ndarray:
        """Raw IsolationForest decision function scores (higher = more normal)."""
        return self.model.decision_function(X)

    def _rule_boost(self, X: np.ndarray) -> np.ndarray:
        """Deterministic penalty vector, one value per sample."""
        boosts = np.zeros(len(X))
        for feat_idx, penalty in RULE_BOOSTS.items():
            boosts += X[:, feat_idx] * penalty
        # Severity amplifier (feature 13 already in [0,1])
        boosts += X[:, 13] * SEVERITY_AMPLIFIER
        return boosts

    def score_components(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        if not self._fitted:
            raise RuntimeError("Call fit() before score_components().")

        model_scores = self._model_score(X)          # typically (-0.5, +0.5)
        rule_scores  = self._rule_boost(X)           # always ≤ 0
        final_scores = model_scores + rule_scores

        is_anomaly = final_scores < ANOMALY_THRESHOLD

        # Confidence: distance below threshold, clamped and normalised
        # At threshold → 0.5; at threshold-0.5 → ~1.0; above threshold → < 0.5
        confidence = np.clip(0.5 - final_scores, 0.0, 1.0)

        return {
            "model_scores": model_scores,
            "rule_scores": rule_scores,
            "final_scores": final_scores,
            "is_anomaly": is_anomaly,
            "confidence": confidence,
        }

    def score_samples(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Returns
        -------
        final_scores : ndarray shape (n,)   – combined score; negative = anomalous
        is_anomaly   : ndarray shape (n,)   – bool array
        confidence   : ndarray shape (n,)   – float in [0, 1]
        """
        components = self.score_components(X)
        return (
            components["final_scores"],
            components["is_anomaly"],
            components["confidence"],
        )

    # ── Convenience wrapper ───────────────────────────────────────────────────

    def predict(self, X: np.ndarray) -> List[Dict[str, Any]]:
        """Return a list of result dicts (one per sample)."""
        components = self.score_components(X)
        results = []
        for i in range(len(X)):
            results.append({
                "model_score": round(float(components["model_scores"][i]), 4),
                "rule_score": round(float(components["rule_scores"][i]), 4),
                "score":      round(float(components["final_scores"][i]), 4),
                "threshold":  ANOMALY_THRESHOLD,
                "is_anomaly": bool(components["is_anomaly"][i]),
                "confidence": round(float(components["confidence"][i]), 4),
                "features":   X[i].tolist(),
            })
        return results
