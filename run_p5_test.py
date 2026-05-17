import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.ml.pipeline import run_ml_pipeline


def main():
    base_dir      = Path(__file__).parent
    baseline_path = base_dir / "src" / "data" / "baseline_normal.json"
    real_input    = base_dir / "output" / "unified_evidence.json"
    mock_input    = base_dir / "src" / "data" / "mock_unified_evidence.json"
    output_path   = base_dir / "output" / "shap_explanations.json"

    input_path = real_input if real_input.exists() else mock_input

    if not input_path.exists():
        sys.exit(f"[ERROR] No evidence file found at {real_input} or {mock_input}")
    if not baseline_path.exists():
        sys.exit(f"[ERROR] Baseline not found: {baseline_path}")

    results = run_ml_pipeline(
        input_path    = str(input_path),
        output_path   = str(output_path),
        baseline_path = str(baseline_path),
    )

    for artifact_id, finding in results["explanations"].items():
        if finding["is_anomaly"]:
            print(f"[{finding['severity'].upper()}] {artifact_id} "
                  f"| score={finding['score']:+.3f} "
                  f"| confidence={finding['confidence']:.0%}")
            print(f"  {finding['reason']}\n")


if __name__ == "__main__":
    main()