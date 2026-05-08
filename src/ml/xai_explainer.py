import shap
import numpy as np

from .feature_engineering import FEATURE_NAMES


def generate_shap(model, X):
    background = X.sample(min(10, len(X)), random_state=42)

    explainer = shap.KernelExplainer(
        model.decision_function,
        background
    )

    shap_values = explainer.shap_values(X, nsamples=50)

    return shap_values


def explain_instance(shap_vals, row):
    explanation_parts = []

    for i, val in enumerate(shap_vals):
        if i >= len(FEATURE_NAMES):
            continue

        if abs(val) > 0.005:
            feature = FEATURE_NAMES[i]

            if feature == "severity_score":
                explanation_parts.append(
                    f"High severity indicator ({row['severity']})"
                )

            elif feature == "confidence":
                explanation_parts.append(
                    f"High detection confidence ({float(row['confidence']):.0%})"
                )

            elif feature == "value_entropy":
                explanation_parts.append(
                    "Unusual pattern in evidence value"
                )

            elif feature == "has_links":
                count = len(row['linked_artifacts']) if row['linked_artifacts'] else 0
                explanation_parts.append(
                    f"Linked to {count} other artifact(s)"
                )

            elif feature == "is_network":
                explanation_parts.append(
                    "Network activity involved"
                )

            elif feature == "is_suspicious_type":
                explanation_parts.append(
                    f"Suspicious evidence type ({row['evidence_type']})"
                )

            elif feature == "value_length":
                explanation_parts.append(
                    "Unusually detailed evidence value"
                )

    if not explanation_parts:
        return "No strong anomaly signals detected"

    return ", ".join(explanation_parts)
