"""Baseline-distance novelty detector + a deterministic rule boost. Replaced the IsolationForest,
which couldn't split on the baseline's zero-variance discriminative features. Model scores are ≤ 0
(0 = matches a baseline profile), so novelty only ever adds to what the rules already flag."""

import numpy as np
from typing import List, Dict, Any


# ── Rule-based booster ────────────────────────────────────────────────────────
# Maps feature-index → extra negative score to add when feature == 1.
# Negative = more anomalous (lower score = more anomalous throughout).
RULE_BOOSTS: Dict[int, float] = {
    1:  -0.30,   # is_suspicious_process
    2:  -0.20,   # suspicious_parent
    4:  -0.35,   # port_is_known_c2
    9:  -0.15,   # path_in_temp
    10: -0.30,   # path_has_exe_in_temp
    11: -0.35,   # keyword_c2_indicator
    12: -0.20,   # keyword_exfil
    13: -0.35,   # has_ioc_match — a catalog hit is at least as strong as a known-C2 port
}

# Severity score (feature 14) amplifier
SEVERITY_AMPLIFIER = -0.25   # maximum penalty at severity=1.0 (critical)

ANOMALY_THRESHOLD = -0.10    # scores below this → anomaly

# ── Distance weights ──────────────────────────────────────────────────────────
# Severity (feature 14) is excluded from the distance: SEVERITY_AMPLIFIER already prices it, and
# the harvester admits only low-severity records so it carries no baseline variance anyway.
SEVERITY_IDX = 14
# Penalty per feature lit in the evidence but not in the nearest baseline profile.
NOVEL_FEATURE_PENALTY = 0.12
# Lacking a feature the profile has is only mildly unusual, not threatening.
MISSING_FEATURE_PENALTY = 0.03
MODEL_SCORE_FLOOR = -0.50


class AnomalyDetector:

    def __init__(self):
        self._profiles = None   # distinct baseline vectors over the binary features
        self._fitted = False

    # ── Training ──────────────────────────────────────────────────────────────

    def fit(self, X: np.ndarray) -> None:
        """Store the distinct baseline-normal profiles (binary features only)."""
        Xb = np.asarray(X, dtype=float)
        self._profiles = np.unique(Xb[:, :SEVERITY_IDX], axis=0)
        self._fitted = True

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _model_score(self, X: np.ndarray) -> np.ndarray:
        """Negative novelty vs the nearest baseline profile (higher = more normal, max 0)."""
        Xb = np.asarray(X, dtype=float)[:, :SEVERITY_IDX]
        diff = Xb[:, None, :] - self._profiles[None, :, :]
        novel   = np.clip(diff, 0.0, None).sum(axis=2)
        missing = np.clip(-diff, 0.0, None).sum(axis=2)
        novelty = (NOVEL_FEATURE_PENALTY * novel
                   + MISSING_FEATURE_PENALTY * missing).min(axis=1)
        return np.maximum(-novelty, MODEL_SCORE_FLOOR)

    def _rule_boost(self, X: np.ndarray) -> np.ndarray:
        """Deterministic penalty vector, one value per sample."""
        boosts = np.zeros(len(X))
        for feat_idx, penalty in RULE_BOOSTS.items():
            boosts += X[:, feat_idx] * penalty
        # Severity amplifier (already in [0,1])
        boosts += X[:, SEVERITY_IDX] * SEVERITY_AMPLIFIER
        return boosts

    def score_components(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        if not self._fitted:
            raise RuntimeError("Call fit() before score_components().")

        model_scores = self._model_score(X)          # in [-0.5, 0]
        rule_scores  = self._rule_boost(X)           # always ≤ 0
        final_scores = model_scores + rule_scores

        is_anomaly = final_scores < ANOMALY_THRESHOLD

        # Confidence: distance below threshold, clamped and normalised. At threshold → 0.5; at
        # threshold-0.5 → ~1.0; above threshold → < 0.5.
        confidence = np.clip(0.5 - final_scores, 0.0, 1.0)

        return {
            "model_scores": model_scores,
            "rule_scores": rule_scores,
            "final_scores": final_scores,
            "is_anomaly": is_anomaly,
            "confidence": confidence,
        }

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
