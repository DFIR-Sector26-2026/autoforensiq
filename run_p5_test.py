from src.ml.pipeline import run_ml_pipeline

run_ml_pipeline(
    "data/mock_unified_evidence.json",
    "output/shap_explanations.json"
)
