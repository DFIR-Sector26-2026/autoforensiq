import json
from .feature_engineering import load_data, create_features
from .model import train_model, predict
from .explain import generate_shap

def run_ml_pipeline(input_path, output_path):

    df = load_data(input_path)
    X = create_features(df)

    model = train_model(X)
    preds, scores = predict(model, X)
    shap_values = generate_shap(model, X)

    results = []

    for i in range(len(df)):
        results.append({
            "artifact_id": df.iloc[i]["artifact_id"],
            "is_anomaly": True if preds[i] == -1 else False,
            "score": float(scores[i]),
            "explanation": str(shap_values[i].tolist())
        })

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print("DONE — output saved.")