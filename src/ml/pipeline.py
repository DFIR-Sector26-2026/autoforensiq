import json
import os
from datetime import datetime, timezone

from .feature_engineering import load_data, create_features
from .anomaly_detector import train_model, predict
from .xai_explainer import generate_shap, explain_instance, FEATURE_NAMES


def run_ml_pipeline(input_path, output_path, baseline_path):
    try:
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")

        if not os.path.exists(baseline_path):
            raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

        df = load_data(input_path)
        baseline_df = load_data(baseline_path)

        if df.empty:
            raise ValueError("Input data is empty")

        if baseline_df.empty:
            raise ValueError("Baseline data is empty")

        X = create_features(df)
        X_baseline = create_features(baseline_df)

        model = train_model(X_baseline)
        preds, scores = predict(model, X)

        shap_values = generate_shap(model, X)

        results = []

        for i in range(len(df)):
            results.append({
                "artifact_id": df.iloc[i]["artifact_id"],
                "is_anomaly": bool(preds[i] == -1),
                "score": float(scores[i]),
                "feature_weights": dict(zip(FEATURE_NAMES, [float(v) for v in shap_values[i]])),
                "reason": explain_instance(shap_values[i], df.iloc[i])
            })

        output = {
            "explanations": results,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

        parent = os.path.dirname(output_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)

        print("  [P5] DONE — output saved.")
        return output

    except Exception as e:
        print(f"  [ERROR] ML pipeline failed: {str(e)}")
        return {"explanations": [], "generated_at": ""}
