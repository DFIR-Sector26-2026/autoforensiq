import numpy as np
import pytest

from src.ml.anomaly_detector import (
    ANOMALY_THRESHOLD,
    MISSING_FEATURE_PENALTY,
    MODEL_SCORE_FLOOR,
    NOVEL_FEATURE_PENALTY,
    AnomalyDetector,
)


def _vec(lit=(), severity=0.25):
    """15-feature vector with the given binary indices lit (severity is feature 14)."""
    v = [0.0] * 15
    for i in lit:
        v[i] = 1.0
    v[14] = severity
    return v


# Benign network profile: has_network + evidence_is_network, low severity — the shape the
# harvester actually produces from dns_query/network_connection items.
BASELINE = np.array([
    _vec(lit=(5, 7)),
    _vec(lit=(5, 7, 3)),   # nonstandard port also seen in normal traffic
    _vec(lit=(0,)),        # a system process
])


def _fitted():
    d = AnomalyDetector()
    d.fit(BASELINE)
    return d


def test_requires_fit():
    with pytest.raises(RuntimeError):
        AnomalyDetector().score_components(np.array([_vec()]))


def test_exact_baseline_match_scores_zero_and_stays_normal():
    pred = _fitted().predict(np.array([_vec(lit=(5, 7))]))[0]
    assert pred["model_score"] == 0.0
    assert not pred["is_anomaly"]


def test_model_score_is_never_positive():
    # Novelty only ever adds anomaly signal — it can't vouch a rule-flagged item back to normal.
    X = np.array([_vec(lit=combo) for combo in [(), (0,), (5,), (1, 4, 11), (3, 5, 7)]])
    assert (_fitted().score_components(X)["model_scores"] <= 0).all()


def test_novel_feature_is_penalized_via_nearest_profile():
    # keyword_c2 (11) never appears in the baseline → exactly one novel feature vs profile (5,7).
    d = _fitted()
    score = d.score_components(np.array([_vec(lit=(5, 7, 11))]))["model_scores"][0]
    assert score == pytest.approx(-NOVEL_FEATURE_PENALTY)


def test_missing_feature_is_cheaper_than_novel_feature():
    d = _fitted()
    missing = d.score_components(np.array([_vec(lit=(5,))]))["model_scores"][0]
    novel = d.score_components(np.array([_vec(lit=(5, 7, 11))]))["model_scores"][0]
    assert missing == pytest.approx(-MISSING_FEATURE_PENALTY)
    assert novel < missing < 0


def test_malware_shaped_item_flags_and_benign_item_does_not():
    # The regression that killed the IsolationForest baseline (0/309 on wannacry): a suspicious
    # process with C2 keyword at critical severity MUST flag; routine baseline traffic must not.
    d = _fitted()
    evil = _vec(lit=(1, 4, 11), severity=1.0)
    benign = _vec(lit=(5, 7))
    preds = d.predict(np.array([evil, benign]))
    assert preds[0]["is_anomaly"] and preds[0]["score"] < ANOMALY_THRESHOLD
    assert preds[0]["model_score"] == MODEL_SCORE_FLOOR or preds[0]["model_score"] < 0
    assert not preds[1]["is_anomaly"]


def test_severity_is_excluded_from_the_distance():
    # Same binary shape as a baseline profile but critical severity: the model half stays 0
    # (SEVERITY_AMPLIFIER prices severity in the rule half — no double counting).
    pred = _fitted().predict(np.array([_vec(lit=(5, 7), severity=1.0)]))[0]
    assert pred["model_score"] == 0.0
    assert pred["rule_score"] < 0


def test_ioc_matched_low_severity_item_flags():
    # Regression: the wannacry .onion C2 domains and killswitch are catalog IOC hits but carry
    # low severity and zero other features — pre-has_ioc_match they scored -0.0625 and passed.
    from src.ml.feature_engineering import extract_features, FEATURE_NAMES
    item = {"evidence_type": "suspicious_domain", "severity": "low",
            "value": "gx7ekbenv2riucmf.onion",
            "ioc_match": ["tor_hidden_service", "wannacry_c2"]}
    features = extract_features(item)
    assert features[FEATURE_NAMES.index("has_ioc_match")] == 1.0
    baseline_twin = dict(item)
    del baseline_twin["ioc_match"]
    assert extract_features(baseline_twin)[FEATURE_NAMES.index("has_ioc_match")] == 0.0

    d = AnomalyDetector()
    # Baseline contains the item's exact binary shape minus the IOC hit — the hit alone must flag.
    d.fit(np.array([extract_features(baseline_twin)]))
    pred = d.predict(np.array([features]))[0]
    assert pred["is_anomaly"] and pred["score"] < ANOMALY_THRESHOLD
