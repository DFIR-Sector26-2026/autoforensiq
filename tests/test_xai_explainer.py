import json

import numpy as np
import pytest

from src.ml import xai_explainer as xe
from src.ml.feature_engineering import FEATURE_NAMES


# ─────────────────────────────────────────────────────────────
# SHAP scalability regression (issue D3 — dedup by feature vector)
# ─────────────────────────────────────────────────────────────
#
# The win10ctf case produced ~23k evidence items, and the explainer ran one
# PermutationExplainer eval per row (~4 it/s → ~1.5h). The feature space is a
# handful of discrete features, so the rows collapse to a few dozen distinct
# vectors. A SHAP attribution is a pure function of (row, background, model),
# so we compute once per unique vector and scatter back — exact, but bounded by
# the number of distinct vectors instead of the item count.


class _StubDetector:
    """Minimal detector exposing the score_components contract the explainer
    uses, so these tests don't depend on the real model's training."""

    def score_components(self, X):
        X = np.asarray(X, dtype=float)
        # A deterministic, feature-dependent score so SHAP has signal to attribute.
        weights = np.linspace(-1.0, 1.0, X.shape[1])
        return {"final_scores": X @ weights}


def _make_evidence(n_rows, n_templates, seed=1):
    nfeat = len(FEATURE_NAMES)
    rng = np.random.default_rng(seed)
    templates = (rng.random((n_templates, nfeat)) > 0.6).astype(float)
    idx = rng.integers(0, n_templates, size=n_rows)
    X_baseline = (rng.random((120, nfeat)) > 0.7).astype(float)
    return X_baseline, templates[idx]


def test_compute_shap_returns_one_explanation_per_row():
    if not xe._SHAP_AVAILABLE:
        pytest.skip("shap not installed")
    X_baseline, X_evidence = _make_evidence(2000, 20)
    out = xe.compute_shap_explanations(_StubDetector(), X_baseline, X_evidence)
    assert len(out) == len(X_evidence)


def test_compute_shap_identical_vectors_get_identical_explanations():
    if not xe._SHAP_AVAILABLE:
        pytest.skip("shap not installed")
    X_baseline, X_evidence = _make_evidence(2000, 20)
    out = xe.compute_shap_explanations(_StubDetector(), X_baseline, X_evidence)

    # Group original rows by their exact feature vector; any two rows that share
    # a vector must receive byte-identical explanations (the dedup is exact).
    groups = {}
    for i, row in enumerate(X_evidence):
        groups.setdefault(row.tobytes(), []).append(i)
    shared = [v for v in groups.values() if len(v) >= 2]
    assert shared, "test fixture should contain repeated vectors"
    for members in shared:
        first = json.dumps(out[members[0]], sort_keys=True)
        for j in members[1:]:
            assert json.dumps(out[j], sort_keys=True) == first


def test_compute_shap_background_is_capped():
    # A baseline far larger than the cap must be subsampled deterministically so
    # per-eval cost stays bounded; the call must still succeed and explain rows.
    if not xe._SHAP_AVAILABLE:
        pytest.skip("shap not installed")
    nfeat = len(FEATURE_NAMES)
    rng = np.random.default_rng(2)
    X_baseline = (rng.random((5000, nfeat)) > 0.7).astype(float)
    X_evidence = (rng.random((50, nfeat)) > 0.6).astype(float)
    assert len(X_baseline) > xe._MAX_SHAP_BACKGROUND
    out = xe.compute_shap_explanations(_StubDetector(), X_baseline, X_evidence)
    assert len(out) == len(X_evidence)


def test_compute_shap_empty_evidence_returns_empty():
    out = xe.compute_shap_explanations(_StubDetector(), np.zeros((10, len(FEATURE_NAMES))), [])
    assert out == []
