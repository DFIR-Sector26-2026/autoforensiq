from src.ml.pipeline import run_ml_pipeline

run_ml_pipeline(
    input_path="data/mock_unified_evidence.json",
    output_path="output/shap_explanations.json",
    baseline_path="data/baseline_normal.json"
)