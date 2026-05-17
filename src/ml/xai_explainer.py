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
