"""
xai_explainer.py

Converts a feature vector + raw record into a human-readable, analyst-grade
explanation.  No LLM required – rule-driven prose that mirrors how a SOC
analyst would write a finding.

Design

*  Each indicator carries three layers: what was found, why it is suspicious,
   and what the investigator should do next.
*  Indicators are ranked by weight so the most critical finding leads.
*  The final reason is assembled as a coherent paragraph, not a bullet dump.
*  Severity is derived from both the explicit field AND the active features.
"""

from typing import Dict, Any, List


# ── Indicator definitions ─────────────────────────────────────────────────────
# Each entry is a dict with:
#   feat_idx      : index into the 14-element feature vector
#   weight        : sort priority (higher = more suspicious, appears first)
#   short_label   : compact label used in summaries
#   what_found    : factual statement of what was detected
#   why_suspicious: explanation of why this is a security concern
#   next_steps    : concrete action the investigator should take
#   analyst_sentence: backward-compatible prose sentence for reason assembly

INDICATORS: List[Dict[str, Any]] = [
    {
        "feat_idx": 4,
        "weight": 10,
        "short_label": "C2 port",
        "what_found": (
            "A network connection was established on a known command-and-control port "
            "(commonly 4444, 1337, 31337, or similar RAT defaults)."
        ),
        "why_suspicious": (
            "These ports are default listeners for Metasploit, Netcat, and custom RAT "
            "frameworks; no legitimate system service binds to them under normal operations."
        ),
        "next_steps": (
            "Capture full packet payload on this port; identify the remote endpoint and "
            "check against threat-intel feeds; locate and terminate the listening process; "
            "search for persistence mechanisms that re-establish the connection at startup."
        ),
        "analyst_sentence": (
            "Network connection established on a known command-and-control port "
            "(commonly used by Metasploit, Netcat, or custom RAT frameworks)."
        ),
    },
    {
        "feat_idx": 10,
        "weight": 9,
        "short_label": "EXE dropped in Temp",
        "what_found": (
            "An executable binary was written to a user-writable %TEMP% or %APPDATA% path."
        ),
        "why_suspicious": (
            "Malware stages payloads in user-writable directories to bypass application "
            "whitelisting and avoid detection in monitored folders such as Program Files."
        ),
        "next_steps": (
            "Hash the file and search VirusTotal / internal threat-intel; inspect the binary "
            "with strings and PE analysis; identify which process wrote it and trace its full "
            "parent chain back to the initial execution vector."
        ),
        "analyst_sentence": (
            "An executable file was written to a user-writable Temp/AppData path, "
            "a hallmark of dropper-stage malware or exploit delivery."
        ),
    },
    {
        "feat_idx": 11,
        "weight": 9,
        "short_label": "C2 keyword in value",
        "what_found": (
            "The artifact value contains terms directly associated with reverse shells, "
            "C2 beaconing, or remote-access tooling (e.g. 'meterpreter', 'beacon', 'c2', "
            "'reverse_shell')."
        ),
        "why_suspicious": (
            "These terms appear in artefact fields only when malicious tooling has been "
            "executed or its configuration has been written to disk or registry."
        ),
        "next_steps": (
            "Review the full artifact context and surrounding timeline; search for related "
            "network connections originating from the same process; pivot to a super-timeline "
            "analysis covering +-30 minutes around the artifact timestamp."
        ),
        "analyst_sentence": (
            "The artifact description contains terms associated with reverse shells, "
            "C2 beaconing, or remote-access tooling."
        ),
    },
    {
        "feat_idx": 1,
        "weight": 8,
        "short_label": "Suspicious process",
        "what_found": (
            "The process binary name matches a known malicious tool or dual-use LOLBin "
            "(e.g. certutil, mshta, regsvr32, mimikatz, or a named malware sample)."
        ),
        "why_suspicious": (
            "LOLBins are routinely abused for credential theft, code execution, and lateral "
            "movement because they are signed by Microsoft and often trusted by security tools."
        ),
        "next_steps": (
            "Capture process memory for shellcode and string analysis; review the full command "
            "line including arguments; check loaded DLL modules for unsigned or unexpected "
            "entries; correlate with any network connections made by this process."
        ),
        "analyst_sentence": (
            "The process binary is on the known LOLBin / malware watchlist "
            "(e.g., certutil, mshta, mimikatz, or a named malware sample)."
        ),
    },
    {
        "feat_idx": 2,
        "weight": 8,
        "short_label": "Suspicious parent process",
        "what_found": (
            "The process was spawned by a command interpreter or scripting host "
            "(cmd.exe, powershell.exe, wscript.exe, cscript.exe, or mshta.exe)."
        ),
        "why_suspicious": (
            "Legitimate Windows system services do not spawn from scripting hosts; this "
            "parent-child pattern is a strong indicator of script-based malware execution or "
            "a post-exploitation framework initiating a new session."
        ),
        "next_steps": (
            "Review the parent process command line in full; trace back through the process "
            "tree to identify the initial execution vector; check for scheduled tasks, "
            "run keys, or WMI subscriptions that launched the parent."
        ),
        "analyst_sentence": (
            "The process was spawned by a shell or scripting host (cmd.exe, "
            "powershell.exe, wscript.exe), which is abnormal for legitimate system services."
        ),
    },
    {
        "feat_idx": 12,
        "weight": 7,
        "short_label": "Data exfiltration indicator",
        "what_found": (
            "Keywords or patterns consistent with data staging or outbound transfer were "
            "detected (e.g. large outbound transfer, DNS TXT queries with encoded payloads, "
            "covert HTTP POST to an external endpoint)."
        ),
        "why_suspicious": (
            "Active data theft in progress is indicated by staging artefacts combined with "
            "outbound transfer patterns; delay in response significantly increases data-loss "
            "impact."
        ),
        "next_steps": (
            "Quantify the total volume of data transferred; identify and block the destination "
            "IP/domain immediately; search the file system for staged archives (.zip/.rar/.7z) "
            "in user directories; notify the data protection officer if personal or regulated "
            "data may be involved."
        ),
        "analyst_sentence": (
            "Keywords consistent with data exfiltration were detected "
            "(e.g., outbound upload, DNS tunnelling, or covert POST request)."
        ),
    },
    {
        "feat_idx": 9,
        "weight": 6,
        "short_label": "Temp/AppData path",
        "what_found": (
            "A file or process path is rooted under %TEMP%, %APPDATA%, or %LOCALAPPDATA%."
        ),
        "why_suspicious": (
            "These are user-writable locations not monitored by default application control "
            "policies; malware consistently uses them for payload staging away from "
            "application whitelisting enforcement points."
        ),
        "next_steps": (
            "Enumerate all executables currently present in these directories and hash each "
            "one; verify against a known-good software inventory; check file creation "
            "timestamps against the incident timeline."
        ),
        "analyst_sentence": (
            "File or process path is rooted in a Temp or AppData subdirectory - "
            "commonly abused for staging malware away from Program Files."
        ),
    },
    {
        "feat_idx": 3,
        "weight": 5,
        "short_label": "Non-standard port",
        "what_found": (
            "Network activity was observed on a port outside the standard web-traffic range "
            "(not 80, 443, 8080, or 8443)."
        ),
        "why_suspicious": (
            "Non-standard ports may carry custom C2 protocols, encrypted tunnels, or "
            "deliberate evasion of perimeter firewall rules that only monitor well-known "
            "service ports."
        ),
        "next_steps": (
            "Identify the application bound to this port using netstat/lsof; capture and "
            "decode the traffic payload; check the destination against threat-intelligence "
            "feeds for known malicious infrastructure."
        ),
        "analyst_sentence": (
            "Network activity observed on a port outside the common web-traffic "
            "set, suggesting custom protocol or evasion of standard firewall rules."
        ),
    },
    {
        "feat_idx": 7,
        "weight": 4,
        "short_label": "Network evidence type",
        "what_found": (
            "A network connection record is associated with this artifact."
        ),
        "why_suspicious": (
            "Combined with other active indicators, network artefacts significantly elevate "
            "the likelihood of active C2 communication, beaconing, or lateral movement."
        ),
        "next_steps": (
            "Cross-reference connection timestamps with process execution times on the same "
            "host; look for beaconing patterns by plotting inter-connection intervals; "
            "correlate source/destination pairs across the full PCAP evidence."
        ),
        "analyst_sentence": (
            "The artifact is a network connection record; combined with other "
            "indicators this increases lateral-movement or beaconing likelihood."
        ),
    },
    {
        "feat_idx": 6,
        "weight": 4,
        "short_label": "File-system evidence",
        "what_found": (
            "A suspicious filesystem artifact (unexpected file, modified timestamp, or "
            "unusual file in a system directory) was detected."
        ),
        "why_suspicious": (
            "Unexpected files in system directories or user temp paths may represent dropped "
            "payloads, persistence scripts, or files modified to conceal attacker activity."
        ),
        "next_steps": (
            "Hash the file and check against known-good baselines; compare MAC timestamps "
            "against the incident timeline; look for alternate data streams (ADS) that may "
            "conceal additional payloads."
        ),
        "analyst_sentence": (
            "A suspicious filesystem artifact was observed; treat as potential "
            "persistence mechanism or dropped payload."
        ),
    },
    {
        "feat_idx": 8,
        "weight": 4,
        "short_label": "Email evidence",
        "what_found": (
            "An email artifact was recovered that is linked to the incident."
        ),
        "why_suspicious": (
            "Email is the primary phishing delivery vector; malicious attachments or links "
            "in recovered emails may identify the initial access vector and additional "
            "targeted recipients."
        ),
        "next_steps": (
            "Inspect all email headers for domain spoofing or header injection; extract and "
            "sandbox any attachments; identify all recipients of the same campaign and "
            "check their endpoints for signs of execution."
        ),
        "analyst_sentence": (
            "Email artefact detected; may indicate phishing delivery or data "
            "exfiltration via mail channel."
        ),
    },
    {
        "feat_idx": 0,
        "weight": 3,
        "short_label": "System process anomaly",
        "what_found": (
            "A core Windows system process (e.g. svchost.exe, lsass.exe, explorer.exe) "
            "exhibited behaviour that deviates from the normal baseline."
        ),
        "why_suspicious": (
            "Attackers hollow legitimate system processes or inject code into them to hide "
            "malicious activity; deviations in parent process or unexpected network "
            "connections from these processes indicate hollowing or DLL injection."
        ),
        "next_steps": (
            "Compare the in-memory process image against the on-disk binary using a "
            "memory forensics tool; enumerate loaded modules and flag any that are unsigned "
            "or loaded from non-standard paths; check for VAD anomalies indicative of "
            "process hollowing."
        ),
        "analyst_sentence": (
            "A core Windows system process exhibited behaviour deviating from the "
            "normal baseline (unexpected parent or network activity)."
        ),
    },
    {
        "feat_idx": 5,
        "weight": 2,
        "short_label": "Network activity",
        "what_found": (
            "Network connectivity was recorded for this artifact."
        ),
        "why_suspicious": (
            "Standalone this is low-signal, but unexpected network activity from "
            "non-network processes (e.g. Word, Notepad, or a system service that should "
            "not reach out) is inherently suspicious."
        ),
        "next_steps": (
            "Determine whether network activity is expected for this specific process; "
            "check destination reputation via threat-intel lookups; correlate with other "
            "network artifacts across the same investigation window."
        ),
        "analyst_sentence": (
            "Network connectivity was recorded; alone this is low-signal but "
            "elevates risk when combined with other indicators."
        ),
    },
]


SEVERITY_LABEL = {
    1.0:  "Critical",
    0.75: "High",
    0.50: "Medium",
    0.25: "Low",
    0.0:  "Informational",
}


def _severity_from_score(score: float, explicit_severity: str) -> str:
    explicit = explicit_severity.strip().capitalize()
    if explicit in ("Critical", "High", "Medium", "Low"):
        score_sev = "Informational"
        if score < -0.40:
            score_sev = "Critical"
        elif score < -0.25:
            score_sev = "High"
        elif score < -0.10:
            score_sev = "Medium"
        order = ["Critical", "High", "Medium", "Low", "Informational"]
        return explicit if order.index(explicit) <= order.index(score_sev) else score_sev
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
    dict with keys:
        is_anomaly        : bool
        score             : float
        confidence        : float
        severity          : str
        reason            : str   - cohesive analyst-grade paragraph
        what_found        : str   - factual statement of the primary finding
        why_suspicious    : str   - why the primary indicator is concerning
        next_steps        : str   - concrete investigator action
        active_indicators : list  - all triggered indicator short_labels ranked by weight
    """
    explicit_sev = str(record.get("severity", "")).lower()
    severity     = _severity_from_score(score, explicit_sev)

    active = []
    for ind in INDICATORS:
        feat_idx = ind["feat_idx"]
        if feat_idx < len(features) and features[feat_idx] >= 0.5:
            active.append(ind)

    active.sort(key=lambda x: x["weight"], reverse=True)

    artifact_id   = record.get("artifact_id", "?")
    evidence_type = str(record.get("evidence_type", "artifact")).lower()
    value_snippet = str(record.get("value", ""))[:120]

    if not is_anomaly:
        reason = (
            f"Artifact {artifact_id} ({evidence_type}) matches expected baseline behaviour. "
            f"No suspicious indicators were triggered. "
            f"Anomaly score {score:+.3f} is within the normal operating range."
        )
        what_found     = f"Artifact {artifact_id} is within normal baseline parameters."
        why_suspicious = "No suspicious indicators are active."
        next_steps     = "No immediate action required. Continue routine monitoring."
        severity       = "Informational"

    elif not active:
        reason = (
            f"Artifact {artifact_id} ({evidence_type}) was flagged as statistically "
            f"anomalous (score {score:+.3f}) due to a combination of feature values "
            f"that deviate from the trained baseline. "
            f"Manual review is recommended: \"{value_snippet}\"."
        )
        what_found = (
            f"Artifact {artifact_id} ({evidence_type}) exhibits a statistically anomalous "
            f"feature profile (score {score:+.3f}) without a single dominant indicator."
        )
        why_suspicious = (
            "The Isolation Forest model detected a deviation from baseline behaviour across "
            "multiple feature dimensions simultaneously, suggesting a combination of subtle "
            "anomalies rather than one clear-cut indicator."
        )
        next_steps = (
            f"Manually inspect the raw artifact value: \"{value_snippet}\". "
            "Cross-reference with peer artifacts from the same time window. "
            "Escalate if additional context confirms malicious intent."
        )

    else:
        lead                 = active[0]
        supporting_sentences = [ind["analyst_sentence"] for ind in active[1:3]]

        intro = (
            f"Anomalous activity detected in {evidence_type} artifact "
            f"{artifact_id} (anomaly score {score:+.3f}, confidence "
            f"{confidence:.0%}). "
        )
        _lbl = lead['short_label']
        _sent = lead['analyst_sentence']
        detail = f"Primary indicator - {_lbl}: {_sent}"

        if supporting_sentences:
            detail += " Additionally: " + " ".join(supporting_sentences)

        detail += f' Observed value: \"{value_snippet}\".' 

        reason         = intro + detail
        what_found     = lead["what_found"]
        why_suspicious = lead["why_suspicious"]
        next_steps     = lead["next_steps"]

    return {
        "is_anomaly":        is_anomaly,
        "score":             round(score, 4),
        "confidence":        round(confidence, 4),
        "severity":          severity,
        "reason":            reason,
        "what_found":        what_found,
        "why_suspicious":    why_suspicious,
        "next_steps":        next_steps,
        "active_indicators": [ind["short_label"] for ind in active],
    }
