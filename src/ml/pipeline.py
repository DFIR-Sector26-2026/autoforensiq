import json
import os

from .feature_engineering import load_data, create_features
from .anomaly_detector import train_model, predict
from .xai_explainer import generate_shap, explain_instance


def run_ml_pipeline(input_path, output_path, baseline_path):

    try:
        # file checks
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")

        if not os.path.exists(baseline_path):
            raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

        # data
        df = load_data(input_path)
        baseline_df = load_data(baseline_path)

        if df.empty:
            raise ValueError("Input data is empty")

        if baseline_df.empty:
            raise ValueError("Baseline data is empty")

        # feature
        X = create_features(df)
        X_baseline = create_features(baseline_df)

        # model
        model = train_model(X_baseline)
        preds, scores = predict(model, X)

        # shap
        shap_values = generate_shap(model, X)

        results = []

        for i in range(len(df)):
            results.append({
                "artifact_id": df.iloc[i]["artifact_id"],
                "is_anomaly": True if preds[i] == -1 else False,
                "score": float(scores[i]),
                "explanation": explain_instance(shap_values[i], df.iloc[i])
            })

        output = {
            "anomalies": results
        }

        # o/p
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)

        print("DONE — output saved.")

    except Exception as e:
        print(f"[ERROR] Pipeline failed: {str(e)}")