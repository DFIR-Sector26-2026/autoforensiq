import json
import os
from datetime import datetime, timezone

from .feature_engineering import load_data, create_features
from .anomaly_detector import train_model, predict
from .xai_explainer import generate_shap, explain_instance


def run_ml_pipeline(
    input_path,
    output_path,
    baseline_path="data/baseline_normal.json"
):

    try:
        # ---------- FILE CHECKS ----------
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")

        if not os.path.exists(baseline_path):
            raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

        # ---------- LOAD DATA ----------
        df = load_data(input_path)
        baseline_df = load_data(baseline_path)

        if df.empty:
            raise ValueError("Input data is empty")

        if baseline_df.empty:
            raise ValueError("Baseline data is empty")

        # ---------- FEATURE ENGINEERING ----------
        X = create_features(df)
        X_baseline = create_features(baseline_df)

        # ---------- MODEL ----------
        model = train_model(X_baseline)
        preds, scores = predict(model, X)

        # ---------- EXPLANATIONS ----------
        shap_values = generate_shap(model, X)

        # ---------- BUILD OUTPUT (DICT) ----------
        results = {}

        for i in range(len(df)):
            aid = df.iloc[i]["artifact_id"]

            results[aid] = {
                "is_anomaly": bool(preds[i] == -1),
                "score": float(scores[i]),
                "feature_weights": dict(
                    zip(FEATURE_NAMES, [float(v) for v in shap_values[i]])
                ),
                "reason": explain_instance(shap_values[i], df.iloc[i])
            }

        output = {
            "explanations": results,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

        # ---------- SAVE OUTPUT ----------
        parent = os.path.dirname(output_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)

        print("DONE — output saved.")

    except Exception as e:
        print(f"[ERROR] Pipeline failed: {str(e)}")