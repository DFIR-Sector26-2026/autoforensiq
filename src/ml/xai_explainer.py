"""
xai_explainer.py

Converts a feature vector + raw record into a human-readable, analyst-grade
explanation.  No LLM required – rule-driven prose that mirrors how a SOC
analyst would write a finding.

Design

*  Each active feature contributes a specific "indicator" sentence.
*  Indicators are ranked by severity so the most critical finding leads.
*  The final reason is assembled as a coherent paragraph, not a bullet dump.
*  Severity is derived from both the explicit field AND the active features.
"""

from typing import Dict, Any, List

import numpy as np
import shap

from src.ml.feature_engineering import FEATURE_NAMES


# ── Indicator templates ───────────────────────────────────────────────────────
# Each entry: (feature_index, weight, short_label, analyst_sentence)
# Weight controls sort order (higher = more suspicious, appears first).

INDICATORS = [
    (4,  10, "C2 port",
     "Network connection established on a known command-and-control port "
     "(commonly used by Metasploit, Netcat, or custom RAT frameworks)."),

    (10,  9, "EXE dropped in Temp",
     "An executable file was written to a user-writable Temp/AppData path, "
     "a hallmark of dropper-stage malware or exploit delivery."),

    (11,  9, "C2 keyword in value",
     "The artifact description contains terms associated with reverse shells, "
     "C2 beaconing, or remote-access tooling."),

    (1,   8, "Suspicious process",
     "The process binary is on the known LOLBin / malware watchlist "
     "(e.g., certutil, mshta, mimikatz, or a named malware sample)."),

    (2,   8, "Suspicious parent process",
     "The process was spawned by a shell or scripting host (cmd.exe, "
     "powershell.exe, wscript.exe), which is abnormal for legitimate "
     "system services."),

    (12,  7, "Data exfiltration indicator",
     "Keywords consistent with data exfiltration were detected "
     "(e.g., outbound upload, DNS tunnelling, or covert POST request)."),

    (9,   6, "Temp/AppData path",
     "File or process path is rooted in a Temp or AppData subdirectory – "
     "commonly abused for staging malware away from Program Files."),

    (3,   5, "Non-standard port",
     "Network activity observed on a port outside the common web-traffic "
     "set, suggesting custom protocol or evasion of standard firewall rules."),

    (7,   4, "Network evidence type",
     "The artifact is a network connection record; combined with other "
     "indicators this increases lateral-movement or beaconing likelihood."),

    (6,   4, "File-system evidence",
     "A suspicious filesystem artifact was observed; treat as potential "
     "persistence mechanism or dropped payload."),

    (8,   4, "Email evidence",
     "Email artefact detected; may indicate phishing delivery or data "
     "exfiltration via mail channel."),

    (0,   3, "System process anomaly",
     "A core Windows system process exhibited behaviour deviating from the "
     "normal baseline (unexpected parent or network activity)."),

    (5,   2, "Network activity",
     "Network connectivity was recorded; alone this is low-signal but "
     "elevates risk when combined with other indicators."),
]

SEVERITY_LABEL = {
    1.0:  "Critical",
    0.75: "High",
    0.50: "Medium",
    0.25: "Low",
    0.0:  "Informational",
}

FEATURE_MEANINGS = {
    "is_system_process":
        "A core Windows process showed unusual behavior.",
    "is_suspicious_process":
        "The process name matches a known LOLBin or suspicious tool.",
    "suspicious_parent":
        "The parent process is commonly abused for script or shell execution.",
    "port_is_nonstandard":
        "The connection used a non-standard network port.",
    "port_is_known_c2":
        "The connection used a port commonly associated with command-and-control.",
    "has_network":
        "The artifact contains network activity.",
    "evidence_is_file":
        "The artifact is filesystem evidence.",
    "evidence_is_network":
        "The artifact is network evidence.",
    "evidence_is_email":
        "The artifact is email evidence.",
    "path_in_temp":
        "The path is in a user-writable staging directory.",
    "path_has_exe_in_temp":
        "An executable appeared in Temp/AppData/Downloads.",
    "keyword_c2_indicator":
        "The artifact contains C2, beacon, shell, or RAT indicators.",
    "keyword_exfil":
        "The artifact contains data exfiltration indicators.",
    "severity_score":
        "The original evidence severity increased the anomaly score.",
}

REVIEW_ACTIONS = {
    "is_system_process":
        "Inspect the process tree and loaded modules for the system process.",
    "is_suspicious_process":
        "Validate the process hash, command line, and execution location.",
    "suspicious_parent":
        "Review parent-child process lineage around the artifact timestamp.",
    "port_is_nonstandard":
        "Confirm whether the destination port is expected for this host.",
    "port_is_known_c2":
        "Check destination IP/domain reputation and related network sessions.",
    "has_network":
        "Correlate this artifact with firewall, proxy, and packet-capture logs.",
    "evidence_is_file":
        "Review file hash, signer, creation time, and adjacent filesystem events.",
    "evidence_is_network":
        "Pivot on source, destination, protocol, and session timing.",
    "evidence_is_email":
        "Inspect sender, headers, links, attachments, and recipient activity.",
    "path_in_temp":
        "Check whether the path was used for staging or payload execution.",
    "path_has_exe_in_temp":
        "Quarantine or hash the executable and inspect persistence paths.",
    "keyword_c2_indicator":
        "Search for repeated beaconing, reverse shells, or remote-access tooling.",
    "keyword_exfil":
        "Review outbound transfer volume, destination, and sensitive data access.",
    "severity_score":
        "Correlate with the original evidence source that assigned severity.",
}


def compute_shap_explanations(
    detector,
    X_baseline,
    X_evidence,
    max_features=5,
) -> List[List[Dict[str, Any]]]:
    """
    Compute SHAP feature attributions for the final anomaly score.

    Lower final scores are more anomalous, so negative SHAP values push an
    artifact toward the anomaly decision.
    """
    if len(X_evidence) == 0:
        return []

    X_baseline = np.asarray(X_baseline)
    X_evidence = np.asarray(X_evidence)

    def score_fn(X):
        components = detector.score_components(np.asarray(X))
        return components["final_scores"]

    explainer = shap.PermutationExplainer(score_fn, X_baseline)
    shap_result = explainer(X_evidence)

    all_explanations = []

    for row_idx, shap_row in enumerate(shap_result.values):
        ranked = sorted(
            zip(FEATURE_NAMES, X_evidence[row_idx], shap_row),
            key=lambda item: abs(item[2]),
            reverse=True,
        )[:max_features]

        top_factors = []

        for feature, value, shap_value in ranked:
            direction = (
                "increased anomaly likelihood"
                if shap_value < 0
                else "reduced anomaly likelihood"
            )

            top_factors.append({
                "feature": feature,
                "value": float(value),
                "shap_value": round(float(shap_value), 4),
                "direction": direction,
                "meaning": FEATURE_MEANINGS.get(
                    feature,
                    "No explanation available."
                ),
            })

        all_explanations.append(top_factors)

    return all_explanations


def compute_baseline_comparisons(
    X_baseline,
    X_evidence,
    max_features=5,
) -> List[List[Dict[str, Any]]]:
    """
    Compare each evidence vector against the average normal baseline.
    """
    if len(X_evidence) == 0:
        return []

    X_baseline = np.asarray(X_baseline)
    X_evidence = np.asarray(X_evidence)

    if len(X_baseline) == 0:
        return [[] for _ in range(len(X_evidence))]

    baseline_mean = X_baseline.mean(axis=0)
    all_comparisons = []

    for row in X_evidence:
        comparisons = []

        for feature, artifact_value, normal_value in zip(
            FEATURE_NAMES,
            row,
            baseline_mean,
        ):
            difference = abs(float(artifact_value) - float(normal_value))

            if difference <= 0.0:
                continue

            direction = (
                "above baseline"
                if artifact_value > normal_value
                else "below baseline"
            )

            comparisons.append({
                "feature": feature,
                "artifact_value": float(artifact_value),
                "baseline_average": round(float(normal_value), 4),
                "difference": round(difference, 4),
                "direction": direction,
                "meaning": FEATURE_MEANINGS.get(
                    feature,
                    "No explanation available."
                ),
            })

        comparisons.sort(
            key=lambda item: item["difference"],
            reverse=True,
        )
        all_comparisons.append(comparisons[:max_features])

    return all_comparisons


def build_structured_explanation(
    record: Dict[str, Any],
    prediction: Dict[str, Any],
    top_factors: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Build report-ready explanation fields from SHAP-ranked factors.
    """
    artifact_id = record.get("artifact_id", "?")
    evidence_type = str(record.get("evidence_type", "artifact")).lower()
    score = prediction.get("score", 0.0)
    threshold = prediction.get("threshold", -0.1)
    is_anomaly = prediction.get("is_anomaly", False)
    confidence = prediction.get("confidence", 0.0)

    anomaly_drivers = [
        factor for factor in top_factors
        if factor.get("direction") == "increased anomaly likelihood"
    ]
    named_drivers = [
        factor["feature"] for factor in anomaly_drivers[:3]
    ]

    if is_anomaly and named_drivers:
        plain_english = (
            f"Artifact {artifact_id} was flagged because its strongest "
            f"anomaly drivers were {', '.join(named_drivers)}."
        )
    elif is_anomaly:
        plain_english = (
            f"Artifact {artifact_id} was flagged because its final score "
            f"fell below the anomaly threshold."
        )
    else:
        plain_english = (
            f"Artifact {artifact_id} appears consistent with the trained "
            f"baseline for this {evidence_type} evidence."
        )

    technical_explanation = (
        f"Model score {prediction.get('model_score', 0.0):+.4f}, "
        f"rule score {prediction.get('rule_score', 0.0):+.4f}, "
        f"final score {score:+.4f}, threshold {threshold:+.4f}, "
        f"confidence {confidence:.0%}."
    )

    recommended_review = []
    for factor in anomaly_drivers:
        action = REVIEW_ACTIONS.get(factor.get("feature"))
        if action and action not in recommended_review:
            recommended_review.append(action)

    if is_anomaly and not recommended_review:
        recommended_review.append(
            "Manually review the artifact and correlate it with nearby timeline events."
        )

    return {
        "plain_english": plain_english,
        "technical_explanation": technical_explanation,
        "recommended_review": recommended_review[:5],
    }


def _severity_from_score(score: float, explicit_severity: str) -> str:
    """Derive a final severity label from both the anomaly score and the
    explicit severity field in the record."""
    explicit = explicit_severity.strip().capitalize()
    if explicit in ("Critical", "High", "Medium", "Low"):
        # If the model also flags it, trust whichever is higher
        score_sev = "Informational"
        if score < -0.40:
            score_sev = "Critical"
        elif score < -0.25:
            score_sev = "High"
        elif score < -0.10:
            score_sev = "Medium"

        order = ["Critical", "High", "Medium", "Low", "Informational"]
        return explicit if order.index(explicit) <= order.index(score_sev) else score_sev
    # Fall back to score-only
    if score < -0.40:
        return "Critical"
    if score < -0.25:
        return "High"
    if score < -0.10:
        return "Medium"
    if score < 0.0:
        return "Low"
    return "Informational"


def explain(
    record: Dict[str, Any],
    features: List[float],
    score: float,
    is_anomaly: bool,
    confidence: float,
) -> Dict[str, Any]:
    """
    Build a complete explanation dict for one evidence record.

    Returns
    -------
    dict with keys: is_anomaly, score, confidence, severity, reason
    """
    explicit_sev = str(record.get("severity", "")).lower()
    severity     = _severity_from_score(score, explicit_sev)

    # ── Collect active indicators ────────────────────────────────────────────
    active = []
    for feat_idx, weight, label, sentence in INDICATORS:
        if feat_idx < len(features) and features[feat_idx] >= 0.5:
            active.append((weight, label, sentence))

    # Sort descending by weight so the most critical finding leads
    active.sort(key=lambda x: x[0], reverse=True)

    # ── Build reason prose ───────────────────────────────────────────────────
    artifact_id   = record.get("artifact_id", "?")
    evidence_type = str(record.get("evidence_type", "artifact")).lower()
    value_snippet = str(record.get("value", ""))[:120]

    if not is_anomaly:
        reason = (
            f"Artifact {artifact_id} ({evidence_type}) matches expected baseline behaviour. "
            f"No suspicious indicators were triggered. "
            f"Anomaly score {score:+.3f} is within the normal operating range."
        )
        severity = "Informational"
    elif not active:
        # Model flagged it but no discrete rule triggered – rely on score
        reason = (
            f"Artifact {artifact_id} ({evidence_type}) was flagged as statistically "
            f"anomalous (score {score:+.3f}) due to a combination of feature values "
            f"that deviate from the trained baseline. "
            f"Manual review is recommended: \"{value_snippet}\"."
        )
    else:
        lead_label, lead_sentence = active[0][1], active[0][2]
        supporting = [s for _, _, s in active[1:3]]   # up to 2 more

        intro = (
            f"Potentially malicious activity detected in {evidence_type} artifact "
            f"{artifact_id} (anomaly score {score:+.3f}, confidence "
            f"{confidence:.0%}). "
        )
        detail = f"Primary indicator — {lead_label}: {lead_sentence}"

        if supporting:
            detail += " Additionally: " + " ".join(supporting)

        detail += f' Observed value: "{value_snippet}".'

        reason = intro + detail

    return {
        "is_anomaly": is_anomaly,
        "score":      round(score, 4),
        "confidence": round(confidence, 4),
        "severity":   severity,
        "reason":     reason,
    }
