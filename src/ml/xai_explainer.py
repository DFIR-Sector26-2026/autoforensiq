"""Feature vector + record → analyst-grade explanation, rule-driven (no LLM). Each active feature
contributes a ranked indicator sentence; the reason is assembled as a paragraph; severity derives
from the explicit field AND the active features."""

from typing import Dict, Any, List, Optional

import numpy as np
try:
    import shap
    _SHAP_AVAILABLE = True
except ImportError:
    _SHAP_AVAILABLE = False

from src.ml.feature_engineering import FEATURE_NAMES

# SHAP background cost scales with the number of background rows. A small, summarized background is
# the SHAP-recommended practice, so cap it (issue D3).
_MAX_SHAP_BACKGROUND = 64


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

    if not _SHAP_AVAILABLE:
        # shap not installed — fall back to empty top_factors; rule-based reason still works
        return [[] for _ in range(len(X_evidence))]

    # Cap the background deterministically (issue D3): PermutationExplainer cost scales with
    # background size, so a large baseline makes every eval slow.
    if len(X_baseline) > _MAX_SHAP_BACKGROUND:
        rng = np.random.default_rng(0)
        sampled = rng.choice(len(X_baseline), size=_MAX_SHAP_BACKGROUND, replace=False)
        background = X_baseline[sampled]
    else:
        background = X_baseline

    # SHAP is a pure function of (row, background, model) and the discrete feature space collapses
    # thousands of rows to a few dozen distinct vectors — compute once per unique row and scatter
    # back (exact; ~23k evals → a few dozen, D3).
    unique_rows, inverse = np.unique(X_evidence, axis=0, return_inverse=True)
    # numpy has returned `inverse` with varying shapes across versions; flatten so it is always a
    # 1-D row→unique-index map.
    inverse = np.asarray(inverse).reshape(-1)

    explainer = shap.PermutationExplainer(score_fn, background, max_evals=100)
    shap_result = explainer(unique_rows)

    unique_explanations = []

    for row_idx, shap_row in enumerate(shap_result.values):
        ranked = sorted(
            zip(FEATURE_NAMES, unique_rows[row_idx], shap_row),
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

        unique_explanations.append(top_factors)

    # Scatter the per-unique-row explanations back into original evidence order.
    return [unique_explanations[i] for i in inverse]


def compute_baseline_comparisons(
    X_baseline,
    X_evidence,
    max_features=5,
) -> List[List[Dict[str, Any]]]:
    """Compare each evidence vector against the average normal baseline."""
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
    baseline_comparison: Optional[List[Dict[str, Any]]] = None,
    machine_items: Optional[List[Dict[str, Any]]] = None,
    correlated_findings: Optional[List[Dict[str, Any]]] = None,
    exfiltration_findings: Optional[List[Dict[str, Any]]] = None,
    bulk_summary: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build report-ready explanation fields from SHAP-ranked factors."""
    artifact_id = record.get("artifact_id", "?")
    evidence_type = str(record.get("evidence_type", "artifact")).lower()
    machine_id = str(record.get("machine_id", "")).strip()
    observed_value = str(
        record.get("normalized_value")
        or record.get("value")
        or record.get("raw_value")
        or ""
    )[:180]
    score = prediction.get("score", 0.0)
    threshold = prediction.get("threshold", -0.1)
    is_anomaly = prediction.get("is_anomaly", False)
    confidence = prediction.get("confidence", 0.0)
    baseline_comparison = baseline_comparison or []
    machine_items = machine_items or []
    correlated_findings = correlated_findings or []
    exfiltration_findings = exfiltration_findings or []
    bulk_summary = bulk_summary or {}

    anomaly_drivers = [
        factor for factor in top_factors
        if factor.get("direction") == "increased anomaly likelihood"
    ]
    named_drivers = [
        str(
            factor.get("meaning", factor.get("feature", "unknown factor"))
        ).rstrip(".")
        for factor in anomaly_drivers[:3]
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

    machine_context = _build_machine_context(machine_id, machine_items)
    correlation_context = _build_correlation_context(record)
    case_finding_context = _build_case_finding_context(
        correlated_findings,
        exfiltration_findings,
        bulk_summary,
    )
    explain_instance = _build_explain_instance(
        artifact_id=artifact_id,
        evidence_type=evidence_type,
        machine_id=machine_id,
        observed_value=observed_value,
        is_anomaly=is_anomaly,
        score=score,
        threshold=threshold,
        confidence=confidence,
        anomaly_drivers=anomaly_drivers,
        baseline_comparison=baseline_comparison,
        correlation_context=correlation_context,
        case_finding_context=case_finding_context,
        recommended_review=recommended_review,
    )

    return {
        "plain_english": plain_english,
        "technical_explanation": technical_explanation,
        "explain_instance": explain_instance,
        "machine_context": machine_context,
        "correlation_context": correlation_context,
        "case_finding_context": case_finding_context,
        "recommended_review": recommended_review[:5],
    }


def _build_machine_context(
    machine_id: str,
    machine_items: List[Dict[str, Any]],
) -> Dict[str, Any]:
    evidence_types = sorted({
        str(item.get("evidence_type", "unknown"))
        for item in machine_items
        if isinstance(item, dict)
    })
    related_artifacts = [
        str(item.get("artifact_id"))
        for item in machine_items
        if isinstance(item, dict) and item.get("artifact_id")
    ]

    return {
        "machine_id": machine_id or "",
        "total_evidence_on_machine": len(machine_items),
        "machine_evidence_types": evidence_types,
        "related_artifacts": related_artifacts[:20],
        "has_machine_context": bool(machine_id and machine_items),
    }


def _build_correlation_context(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    context = []

    correlations = record.get("correlations", [])
    if isinstance(correlations, list):
        for entry in correlations:
            if not isinstance(entry, dict):
                continue
            context.append({
                "artifact_id": str(entry.get("artifact_id", "")),
                "correlation_type": str(
                    entry.get("correlation_type", "correlated_artifact")
                ),
                "matches": entry.get("matches", [])
                if isinstance(entry.get("matches", []), list)
                else [],
                "confidence": entry.get("confidence"),
            })

    linked_artifacts = record.get("linked_artifacts", [])
    if isinstance(linked_artifacts, list):
        existing = {item.get("artifact_id") for item in context}
        for artifact_id in linked_artifacts:
            if not isinstance(artifact_id, str) or artifact_id in existing:
                continue
            context.append({
                "artifact_id": artifact_id,
                "correlation_type": "linked_artifact",
                "matches": [],
                "confidence": None,
            })

    return context


def _finding_summary(finding: Dict[str, Any]) -> str:
    for key in ("summary", "description", "reason", "value", "finding_type", "type"):
        value = finding.get(key)
        if value:
            return str(value)[:180]
    return "Aggregator finding linked to this artifact."


def _build_case_finding_context(
    correlated_findings: List[Dict[str, Any]],
    exfiltration_findings: List[Dict[str, Any]],
    bulk_summary: Dict[str, Any],
) -> Dict[str, Any]:
    finding_summaries = [
        _finding_summary(finding)
        for finding in correlated_findings[:5]
        if isinstance(finding, dict)
    ]
    exfiltration_summaries = [
        _finding_summary(finding)
        for finding in exfiltration_findings[:5]
        if isinstance(finding, dict)
    ]

    return {
        "appears_in_correlated_finding": bool(correlated_findings),
        "appears_in_exfiltration_finding": bool(exfiltration_findings),
        "correlated_finding_count": len(correlated_findings),
        "exfiltration_finding_count": len(exfiltration_findings),
        "finding_summaries": finding_summaries,
        "exfiltration_summaries": exfiltration_summaries,
        "bulk_summary": bulk_summary if isinstance(bulk_summary, dict) else {},
    }


def _join_sentence_parts(parts: List[str]) -> str:
    return " ".join(part.strip() for part in parts if part and part.strip())


def _driver_sentence(anomaly_drivers: List[Dict[str, Any]]) -> str:
    if not anomaly_drivers:
        return (
            "the combined feature pattern deviated from the trained baseline"
        )

    phrases = []
    for factor in anomaly_drivers[:3]:
        feature = factor.get("feature", "unknown_feature")
        meaning = factor.get("meaning", "No explanation available.")
        shap_value = factor.get("shap_value", 0.0)
        phrases.append(
            f"{feature} ({meaning}; SHAP {shap_value:+.4f})"
        )

    return ", ".join(phrases)


def _baseline_sentence(
    baseline_comparison: List[Dict[str, Any]],
) -> str:
    suspicious = [
        item for item in baseline_comparison
        if item.get("direction") == "above baseline"
    ]
    selected = suspicious[:2] or baseline_comparison[:2]

    if not selected:
        return ""

    pieces = []
    for item in selected:
        pieces.append(
            f"{item.get('feature')} was {item.get('direction')} "
            f"(artifact {item.get('artifact_value')}, baseline "
            f"{item.get('baseline_average')})"
        )

    return (
        "Compared with the relevant normal baseline, "
        + "; ".join(pieces)
        + "."
    )


def _correlation_sentence(
    correlation_context: List[Dict[str, Any]],
) -> str:
    if not correlation_context:
        return ""

    parts = []
    for item in correlation_context[:3]:
        artifact_id = item.get("artifact_id") or "another artifact"
        corr_type = item.get("correlation_type") or "correlation"
        matches = item.get("matches") or []
        match_text = (
            f" with matching values {', '.join(map(str, matches[:3]))}"
            if matches
            else ""
        )
        parts.append(f"{artifact_id} via {corr_type}{match_text}")

    return "P4 correlation links this artifact to " + "; ".join(parts) + "."


def _case_finding_sentence(case_finding_context: Dict[str, Any]) -> str:
    parts = []

    if case_finding_context.get("appears_in_correlated_finding"):
        parts.append(
            f"it appears in {case_finding_context.get('correlated_finding_count')} "
            "aggregator correlation finding(s)"
        )

    if case_finding_context.get("appears_in_exfiltration_finding"):
        parts.append(
            f"it appears in {case_finding_context.get('exfiltration_finding_count')} "
            "exfiltration finding(s)"
        )

    if not parts:
        return ""

    return "At the case level, " + " and ".join(parts) + "."


def _review_sentence(recommended_review: List[str]) -> str:
    if not recommended_review:
        return ""

    return "Recommended review: " + " ".join(recommended_review[:3])


def _build_explain_instance(
    artifact_id: str,
    evidence_type: str,
    machine_id: str,
    observed_value: str,
    is_anomaly: bool,
    score: float,
    threshold: float,
    confidence: float,
    anomaly_drivers: List[Dict[str, Any]],
    baseline_comparison: List[Dict[str, Any]],
    correlation_context: List[Dict[str, Any]],
    case_finding_context: Dict[str, Any],
    recommended_review: List[str],
) -> str:
    location = f" on {machine_id}" if machine_id else ""

    if is_anomaly:
        opening = (
            f"Artifact {artifact_id}{location} was classified as anomalous "
            f"because {_driver_sentence(anomaly_drivers)}."
        )
    else:
        opening = (
            f"Artifact {artifact_id}{location} was not classified as anomalous "
            f"because its final score stayed within the expected baseline range."
        )

    observed = (
        f"Observed evidence ({evidence_type}): \"{observed_value}\"."
        if observed_value
        else f"Observed evidence type: {evidence_type}."
    )
    baseline = _baseline_sentence(baseline_comparison)
    correlation = _correlation_sentence(correlation_context)
    case_finding = _case_finding_sentence(case_finding_context)
    scoring = (
        f"The final anomaly score was {score:+.4f} against threshold "
        f"{threshold:+.4f}, with confidence {confidence:.0%}."
    )
    review = _review_sentence(recommended_review)

    return _join_sentence_parts([
        opening,
        observed,
        baseline,
        correlation,
        case_finding,
        scoring,
        review,
    ])


def _severity_from_score(score: float, explicit_severity: str) -> str:
    """Derive a final severity label from both the anomaly score and the explicit severity field
    in the record."""
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
    value_snippet = str(
        record.get("normalized_value")
        or record.get("value")
        or record.get("raw_value")
        or ""
    )[:120]

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