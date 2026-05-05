import shap
import numpy as np

FEATURE_NAMES = [
    "high_entropy",
    "rare_process",
    "unusual_parent",
    "parent_mismatch",
    "port_suspicious",
    "network_flag",
    "name_length"
]


def generate_shap(model, X):
    # Background sample (for performance)
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

        if val > 0.02:  # lower threshold for small datasets
            feature = FEATURE_NAMES[i]

            if feature == "unusual_parent":
                explanation_parts.append(
                    f"Unusual parent process ({row['parent_process']})"
                )

            elif feature == "parent_mismatch":
                explanation_parts.append(
                    "Suspicious parent-child relationship"
                )

            elif feature == "port_suspicious":
                explanation_parts.append(
                    f"Suspicious port ({row['port']})"
                )

            elif feature == "high_entropy":
                explanation_parts.append(
                    f"Random-looking process name ({row['process_name']})"
                )

            elif feature == "rare_process":
                explanation_parts.append(
                    f"Rare process ({row['process_name']})"
                )

            elif feature == "network_flag":
                explanation_parts.append(
                    "Network activity observed"
                )

            elif feature == "name_length":
                if len(row['process_name']) > 12:
                    explanation_parts.append(
                        "Unusually long process name"
                    )

    if not explanation_parts:
        return "No strong anomaly signals detected"

    return ", ".join(explanation_parts)