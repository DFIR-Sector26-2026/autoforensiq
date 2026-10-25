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


def test_compute_shap_evaluates_once_per_unique_vector_not_per_item(monkeypatch):
    # The core D3 guarantee: explainer cost is bounded by the number of DISTINCT
    # feature vectors, NOT the item count. A flood of near-identical rows (the
    # ~22k over-extracted domains that took ~1.5h) must reach PermutationExplainer
    # only as many times as there are unique vectors. The correctness tests above
    # would still pass if the dedup were removed (per-item loop) — this one locks
    # in the performance contract by counting the rows the explainer actually sees.
    if not xe._SHAP_AVAILABLE:
        pytest.skip("shap not installed")
    nfeat = len(FEATURE_NAMES)
    rng = np.random.default_rng(7)
    templates = (rng.random((6, nfeat)) > 0.6).astype(float)
    idx = rng.integers(0, len(templates), size=5000)
    X_evidence = templates[idx]
    X_baseline = (rng.random((100, nfeat)) > 0.7).astype(float)
    n_unique = len(np.unique(X_evidence, axis=0))

    seen = {}
    real_cls = xe.shap.PermutationExplainer

    class _SpyExplainer:
        def __init__(self, *args, **kwargs):
            self._inner = real_cls(*args, **kwargs)

        def __call__(self, rows, *args, **kwargs):
            seen["rows"] = len(rows)
            return self._inner(rows, *args, **kwargs)

    monkeypatch.setattr(xe.shap, "PermutationExplainer", _SpyExplainer)

    out = xe.compute_shap_explanations(_StubDetector(), X_baseline, X_evidence)
    assert len(out) == 5000                       # every item still gets an explanation
    assert seen["rows"] == n_unique               # but the explainer saw only unique rows
    assert seen["rows"] <= len(templates) < 5000  # bounded by vectors, not item count


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


# ─────────────────────────────────────────────────────────────
# Feature-prose coverage guard (review-2 F3)
# ─────────────────────────────────────────────────────────────
#
# has_ioc_match was added to two of the three prose tables and forgotten in the
# third (F2), so catalog hits read as unexplained deviations. The tables now
# derive from FEATURE_PROSE; these assertions make that bug class impossible.


def test_feature_prose_covers_every_feature():
    assert set(xe.FEATURE_PROSE) == set(FEATURE_NAMES)
    for name, row in xe.FEATURE_PROSE.items():
        assert {"meaning", "review"} <= set(row), f"{name} missing meaning/review"


def test_indicator_rows_match_declared_exemptions():
    # Deliberate omissions must be named in NON_INDICATOR_FEATURES, not silent.
    indicator_features = {
        name for name, row in xe.FEATURE_PROSE.items() if "weight" in row
    }
    assert indicator_features == set(FEATURE_NAMES) - xe.NON_INDICATOR_FEATURES
    for name in indicator_features:
        row = xe.FEATURE_PROSE[name]
        assert {"weight", "label", "indicator"} <= set(row), f"{name} partial indicator row"
    assert {i[0] for i in xe.INDICATORS} == {
        FEATURE_NAMES.index(n) for n in indicator_features
    }
