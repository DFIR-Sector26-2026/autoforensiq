"""
AutoForensiq — Report Generator
"""

import json
import os
import re
import yaml

from datetime import datetime, timezone
from pathlib import Path


# ─────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────

ROOT_DIR = Path(__file__).resolve().parents[2]

CONFIG_PATH = ROOT_DIR / "config.yaml"


# ─────────────────────────────────────────────────────────────
# MITRE ATT&CK MAPPING
# ─────────────────────────────────────────────────────────────

MITRE_BY_CASE = {
    "ransomware": [
        ("T1486", "Data Encrypted for Impact", "Impact"),
        ("T1204", "User Execution", "Execution"),
        ("T1547", "Boot/Logon Autostart Execution", "Persistence"),
        ("T1083", "File and Directory Discovery", "Discovery"),
    ],
    "malware": [
        ("T1055", "Process Injection", "Defense Evasion"),
        ("T1059", "Command and Scripting Interpreter", "Execution"),
        ("T1547", "Boot/Logon Autostart Execution", "Persistence"),
        ("T1071", "Application Layer Protocol", "C2"),
    ],
    "data_exfiltration": [
        ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
        ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
        ("T1560", "Archive Collected Data", "Collection"),
        ("T1083", "File and Directory Discovery", "Discovery"),
    ],
    "insider_threat": [
        ("T1078", "Valid Accounts", "Persistence"),
        ("T1213", "Data from Information Repositories", "Collection"),
        ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
    ],
    "network_intrusion": [
        ("T1190", "Exploit Public-Facing Application", "Initial Access"),
        ("T1021", "Remote Services", "Lateral Movement"),
        ("T1071", "Application Layer Protocol", "C2"),
        ("T1046", "Network Service Discovery", "Discovery"),
    ],
    "phishing": [
        ("T1566", "Phishing", "Initial Access"),
        ("T1204", "User Execution", "Execution"),
        ("T1059", "Command and Scripting Interpreter", "Execution"),
        ("T1547", "Boot/Logon Autostart Execution", "Persistence"),
    ],
    "unknown": [
        ("T1059", "Command and Scripting Interpreter", "Execution"),
        ("T1071", "Application Layer Protocol", "C2"),
    ],
}


# ─────────────────────────────────────────────────────────────
# RECOMMENDATIONS BY CASE TYPE
# ─────────────────────────────────────────────────────────────

RECOMMENDATIONS_BY_CASE = {
    "ransomware": [
        "Immediately isolate affected systems from the network to prevent further encryption spread.",
        "Do NOT power off affected systems — preserve volatile memory for forensic analysis.",
        "Identify and revoke all compromised credentials associated with the initial access vector.",
        "Restore systems from verified clean backups only after confirming backup integrity.",
        "Engage law enforcement and notify relevant regulatory bodies as required.",
    ],
    "malware": [
        "Isolate affected hosts and block identified C2 IP addresses and domains at the perimeter firewall.",
        "Run a full AV/EDR scan with updated signatures on all potentially exposed systems.",
        "Review and harden PowerShell and script execution policies (constrained language mode).",
        "Audit scheduled tasks, run keys, and startup folders for persistence mechanisms.",
        "Deploy network monitoring rules to detect further beaconing activity from identified IOCs.",
    ],
    "data_exfiltration": [
        "Immediately block outbound connections to all identified exfiltration endpoints.",
        "Determine the full scope of data accessed by reviewing DLP logs and file access audit trails.",
        "Notify the relevant data protection officer and assess breach notification obligations.",
        "Rotate all credentials that may have been accessed or exfiltrated during the incident.",
        "Implement strict egress filtering and monitor for DNS tunnelling or covert channel patterns.",
    ],
    "insider_threat": [
        "Suspend the implicated account(s) pending investigation — do not alert the subject prematurely.",
        "Preserve all relevant logs, email, and file access records under formal legal hold.",
        "Engage HR and legal counsel before taking any disciplinary action against the individual.",
        "Audit access rights across all shared repositories and sensitive data stores.",
        "Implement User and Entity Behaviour Analytics (UEBA) for ongoing behavioural monitoring.",
    ],
    "network_intrusion": [
        "Patch all externally-facing services and audit for additional exploitation attempts.",
        "Rotate all service account and privileged credentials on affected systems immediately.",
        "Review and tighten firewall rules — remove any unnecessary port exposures.",
        "Conduct a full Active Directory audit for unauthorised account creation or privilege changes.",
        "Deploy honeypot assets to detect and track further lateral movement attempts.",
    ],
    "phishing": [
        "Reset credentials for all accounts that interacted with the phishing link or opened the attachment.",
        "Block the phishing sender domain and URL at the email gateway and proxy.",
        "Conduct targeted security awareness training for all affected users.",
        "Search mail logs for additional recipients of the same phishing campaign.",
        "Review endpoint telemetry for post-exploitation activity on systems that executed the attachment.",
    ],
    "unknown": [
        "Conduct a full manual triage of all flagged artifacts with an experienced analyst.",
        "Preserve all evidence in its current state pending further investigation and chain-of-custody documentation.",
        "Expand evidence collection to include any missing evidence types identified in the coverage section.",
        "Review network logs for anomalous outbound connections over the full investigation period.",
    ],
}


# ─────────────────────────────────────────────────────────────
# CONFIG LOADER
# ─────────────────────────────────────────────────────────────

def _load_config():

    if not CONFIG_PATH.exists():

        raise FileNotFoundError(
            f"config.yaml not found at {CONFIG_PATH}"
        )

    with open(CONFIG_PATH) as f:

        return yaml.safe_load(f)


# ─────────────────────────────────────────────────────────────
# SYSTEM PROMPT
# ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """
You are a senior digital forensics analyst.

Write a professional forensic report in Markdown.
"""


# ─────────────────────────────────────────────────────────────
# USER PROMPT BUILDER
# ─────────────────────────────────────────────────────────────

def _build_user_prompt(
    unified_evidence,
    shap_explanations,
    case_context
):

    anomaly_lookup = {}

    explanations = shap_explanations.get("explanations", [])

    # ML pipeline outputs a dict keyed by artifact_id; list format is legacy.
    if isinstance(explanations, dict):
        explanations = [
            {"artifact_id": k, **v}
            for k, v in explanations.items()
        ]
    elif not isinstance(explanations, list):
        explanations = []

    for item in explanations:

        if not isinstance(item, dict):
            continue

        if item.get("is_anomaly"):

            anomaly_lookup[
                item.get("artifact_id", "")
            ] = item.get("reason", "")

    priority_items = [

        e for e in unified_evidence.get(
            "evidence_items",
            []
        )

        if isinstance(e, dict)
        and e.get("severity") in (
            "critical",
            "high"
        )
    ][:20]

    if not priority_items:

        priority_items = unified_evidence.get(
            "evidence_items",
            []
        )[:20]

    for item in priority_items:

        if not isinstance(item, dict):
            continue

        aid = item.get("artifact_id", "")

        if aid in anomaly_lookup:

            item["_shap_reason"] = anomaly_lookup[aid]

    prompt_parts = [

        "## Case Context",

        json.dumps(case_context, indent=2),

        "",

        "## Evidence",

        json.dumps(priority_items, indent=2),

        "",

        "## Tools",

        ", ".join(
            unified_evidence.get(
                "tools_aggregated",
                []
            )
        )
    ]

    return "\n".join(prompt_parts)


# ─────────────────────────────────────────────────────────────
# OPENAI CALLER
# ─────────────────────────────────────────────────────────────

def _call_openai(user_prompt, cfg):

    from openai import OpenAI

    api_key = os.environ.get(
        cfg["llm"].get(
            "openai_api_key_env",
            "OPENAI_API_KEY"
        )
    )

    client = OpenAI(api_key=api_key)

    model = cfg["llm"].get(
        "openai_model",
        "gpt-4o"
    )

    resp = client.chat.completions.create(

        model=model,

        max_tokens=cfg["llm"].get(
            "max_tokens",
            2048
        ),

        temperature=cfg["llm"].get(
            "temperature",
            0.2
        ),

        messages=[

            {
                "role": "system",
                "content": SYSTEM_PROMPT
            },

            {
                "role": "user",
                "content": user_prompt
            }
        ]
    )

    return resp.choices[0].message.content


# ─────────────────────────────────────────────────────────────
# MOCK REPORT HELPERS
# ─────────────────────────────────────────────────────────────

_SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
}

MITRE_BY_CASE = {
    "ransomware": [
        ("T1486", "Data Encrypted for Impact", "Impact"),
        ("T1204", "User Execution", "Execution"),
        ("T1547", "Boot/Logon Autostart Execution", "Persistence"),
        ("T1083", "File and Directory Discovery", "Discovery"),
    ],
    "malware": [
        ("T1055", "Process Injection", "Defense Evasion"),
        ("T1059", "Command and Scripting Interpreter", "Execution"),
        ("T1547", "Boot/Logon Autostart Execution", "Persistence"),
        ("T1071", "Application Layer Protocol", "C2"),
    ],
    "data_exfiltration": [
        ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
        ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
        ("T1560", "Archive Collected Data", "Collection"),
        ("T1083", "File and Directory Discovery", "Discovery"),
    ],
    "insider_threat": [
        ("T1078", "Valid Accounts", "Persistence"),
        ("T1213", "Data from Information Repositories", "Collection"),
        ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
    ],
    "network_intrusion": [
        ("T1190", "Exploit Public-Facing Application", "Initial Access"),
        ("T1021", "Remote Services", "Lateral Movement"),
        ("T1071", "Application Layer Protocol", "C2"),
        ("T1046", "Network Service Discovery", "Discovery"),
    ],
    "phishing": [
        ("T1566", "Phishing", "Initial Access"),
        ("T1204", "User Execution", "Execution"),
        ("T1059", "Command and Scripting Interpreter", "Execution"),
        ("T1547", "Boot/Logon Autostart Execution", "Persistence"),
    ],
    "unknown": [
        ("T1059", "Command and Scripting Interpreter", "Execution"),
        ("T1071", "Application Layer Protocol", "C2"),
    ],
}

RECOMMENDATIONS_BY_CASE = {
    "ransomware": [
        "Immediately isolate affected systems from the network to prevent further encryption spread.",
        "Do NOT power off affected systems - preserve volatile memory for forensic analysis.",
        "Identify and revoke all compromised credentials associated with the initial access vector.",
        "Restore systems from verified clean backups only after confirming backup integrity.",
        "Engage law enforcement and notify relevant regulatory bodies as required.",
    ],
    "malware": [
        "Isolate affected hosts and block identified C2 IP addresses and domains at the perimeter.",
        "Run a full AV/EDR scan with updated signatures on all potentially exposed systems.",
        "Review and harden PowerShell and script execution policies (constrained language mode).",
        "Audit scheduled tasks, run keys, and startup folders for persistence mechanisms.",
        "Deploy network monitoring rules to detect further beaconing activity from identified IOCs.",
    ],
    "data_exfiltration": [
        "Immediately block outbound connections to all identified exfiltration endpoints.",
        "Determine the full scope of data accessed by reviewing DLP logs and file access audit trails.",
        "Notify the relevant data protection officer and assess breach notification obligations.",
        "Rotate all credentials that may have been accessed or exfiltrated during the incident.",
        "Implement strict egress filtering and monitor for DNS tunnelling or covert channel patterns.",
    ],
    "insider_threat": [
        "Suspend the implicated account(s) pending investigation - do not alert the subject prematurely.",
        "Preserve all relevant logs, email, and file access records under formal legal hold.",
        "Engage HR and legal counsel before taking any disciplinary action against the individual.",
        "Audit access rights across all shared repositories and sensitive data stores.",
        "Implement User and Entity Behaviour Analytics (UEBA) for ongoing behavioural monitoring.",
    ],
    "network_intrusion": [
        "Patch all externally-facing services and audit for additional exploitation attempts.",
        "Rotate all service account and privileged credentials on affected systems immediately.",
        "Review and tighten firewall rules - remove any unnecessary port exposures.",
        "Conduct a full Active Directory audit for unauthorised account creation or privilege changes.",
        "Deploy honeypot assets to detect and track further lateral movement attempts.",
    ],
    "phishing": [
        "Reset credentials for all accounts that interacted with the phishing link or opened the attachment.",
        "Block the phishing sender domain and URL at the email gateway and proxy.",
        "Conduct targeted security awareness training for all affected users.",
        "Search mail logs for additional recipients of the same phishing campaign.",
        "Review endpoint telemetry for post-exploitation activity on systems that executed the attachment.",
    ],
    "unknown": [
        "Conduct a full manual triage of all flagged artifacts with an experienced analyst.",
        "Preserve all evidence in its current state pending further investigation.",
        "Expand evidence collection to include any missing evidence types identified in the coverage section.",
        "Review network logs for anomalous outbound connections over the full investigation period.",
    ],
}

_TOOL_TO_EVIDENCE = {
    "volatility3": "memory_dump",
    "tshark":      "pcap",
    "tsk_fls":     "disk_image",
    "regripper":   "registry_hive",
    "plaso":       "log_files",
    "email":       "email",
    "browser":     "browser",
}

_ALL_EVIDENCE_TYPES = [
    "memory_dump", "pcap", "disk_image",
    "registry_hive", "log_files", "email", "browser",
]

_ACQUIRE_NOTES = {
    "memory_dump":   "Acquire a memory dump (.dmp/.mem) using WinPmem, DumpIt, or LiME.",
    "pcap":          "Capture network traffic (.pcap) via Wireshark or tcpdump.",
    "disk_image":    "Acquire a disk image (.img/.dd/.e01) using FTK Imager or dd.",
    "registry_hive": "Export registry hives (NTUSER.DAT/SYSTEM/SOFTWARE) from the host.",
    "log_files":     "Export Windows event logs (.evtx) via Event Viewer or wevtutil.",
    "email":         "Export email artifacts (.eml/.msg) from the affected mail client.",
    "browser":       "Export browser History files from the user profile directory.",
}


def _derive_severity(anomaly_items):
    best = "informational"
    for item in anomaly_items:
        sev = str(item.get("severity", "")).lower()
        if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(best, 0):
            best = sev
    return best.capitalize() if best else "Informational"


def _extract_iocs(evidence_items):
    import re as _re
    IP_RE = _re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    HASH_RE = _re.compile(r"\b[0-9a-fA-F]{32,64}\b")
    FNAME_EXTS = (".exe", ".dll", ".bat", ".ps1", ".vbs", ".cmd", ".scr")
    iocs = []
    seen = set()
    for item in evidence_items:
        if not isinstance(item, dict):
            continue
        val = str(item.get("value", ""))
        tool = item.get("source_tool", "-")
        for ip in IP_RE.findall(val):
            parts = ip.split(".")
            if parts[0] in ("127", "0", "255", "169"):
                continue
            key = ("IP Address", ip)
            if key not in seen:
                seen.add(key)
                iocs.append({"type": "IP Address", "indicator": ip, "tool": tool})
        for h in HASH_RE.findall(val):
            if len(h) in (32, 64):
                htype = "MD5 Hash" if len(h) == 32 else "SHA-256 Hash"
                key = (htype, h)
                if key not in seen:
                    seen.add(key)
                    iocs.append({"type": htype, "indicator": h[:20] + "...", "tool": tool})
        for ext in FNAME_EXTS:
            if ext in val.lower():
                for tok in val.split():
                    if tok.lower().endswith(ext):
                        key = ("Suspicious File", tok)
                        if key not in seen:
                            seen.add(key)
                            iocs.append({"type": "Suspicious File", "indicator": tok[:60], "tool": tool})
        if val.startswith(("HKEY", "HKLM", "HKCU")):
            key = ("Registry Key", val[:60])
            if key not in seen:
                seen.add(key)
                iocs.append({"type": "Registry Key", "indicator": val[:60], "tool": tool})
    return iocs


def _build_process_tree(evidence_items, anomaly_ids):
    import re as _re
    procs = [
        e for e in evidence_items
        if isinstance(e, dict)
        and (e.get("evidence_type") == "process" or "pid" in str(e.get("value", "")).lower())
    ]
    if not procs:
        return "_No process artifacts in evidence._"
    lines = []
    for item in procs[:20]:
        val = str(item.get("value", ""))
        sev = str(item.get("severity", "")).lower()
        aid = item.get("artifact_id", "")
        flag = "[!]" if sev in ("critical", "high") or aid in anomaly_ids else "[ ]"
        pid_m = _re.search(r"pid[:\s=]+(\d+)", val, _re.IGNORECASE)
        ppid_m = _re.search(r"ppid[:\s=]+(\d+)", val, _re.IGNORECASE)
        pid = pid_m.group(1) if pid_m else "?"
        ppid = ppid_m.group(1) if ppid_m else "?"
        proc_name = (val[:40].split()[0] if val.split() else item.get("artifact_id", "unknown"))
        lines.append(f"  {flag}  {proc_name:<36}  PID {pid:<6}  PPID {ppid}")
    return "\n".join(lines)


def _evaluate_hypothesis(hypothesis, anomaly_reason_texts, n_anomalies):
    """
    Evaluate a single hypothesis against the anomaly evidence.

    Uses anomaly count as the primary signal — the word-overlap approach
    was replaced because XAI reason vocabulary never matched forensic
    hypothesis vocabulary, producing a permanently-inconclusive result.
    """
    if n_anomalies == 0:
        return "**Not Evidenced** — no anomalous artifacts detected in the current evidence set"
    if n_anomalies >= 3:
        return "**Supported** — multiple anomalous artifacts corroborate this hypothesis"
    if n_anomalies >= 1:
        return "**Partially Supported** — anomalous artifact(s) detected; further manual review recommended"
    return "**Inconclusive** — anomaly evidence is insufficient to confirm or refute this hypothesis"


def _build_analyst_verdict(case_type, overall_sev, n_anomalies, confidence):
    ct = case_type.replace("_", " ").title()
    sev_lower = overall_sev.lower()
    if sev_lower == "critical" or n_anomalies >= 3:
        _plur = "y" if n_anomalies == 1 else "ies"
        _verb = "was" if n_anomalies == 1 else "were"
        return (
            f"This investigation reveals strong indicators of a confirmed {ct} incident. "
            f"{n_anomalies} high-confidence anomal{_plur} {_verb} detected across the evidence set. "
            "Immediate escalation to incident response is warranted."
        )
    elif sev_lower == "high" or n_anomalies >= 1:
        return (
            f"Evidence is consistent with {ct} activity. "
            f"{n_anomalies} anomalous artifact(s) were identified with high confidence. "
            "Analyst review and targeted containment steps are recommended."
        )
    elif n_anomalies > 0:
        return (
            f"Evidence shows suspicious activity consistent with early-stage {ct} indicators. "
            f"{n_anomalies} artifact(s) triggered anomaly detection. "
            "Further monitoring and expanded evidence collection are advised."
        )
    else:
        return (
            f"No anomalous artifacts were detected in the current evidence set. "
            f"The incident report was classified as {ct} with {confidence:.0%} confidence. "
            "Manual review is recommended to confirm benign status or expand evidence scope."
        )


def _build_evidence_coverage(tools_ran):
    covered = set()
    for t in tools_ran:
        ev = _TOOL_TO_EVIDENCE.get(t)
        if ev:
            covered.add(ev)
    tool_by_ev = {v: k for k, v in _TOOL_TO_EVIDENCE.items()}
    rows = [
        "| Evidence Type | Status | Forensic Tool | Notes |",
        "|---------------|--------|---------------|-------|",
    ]
    for ev in _ALL_EVIDENCE_TYPES:
        ev_label = ev.replace("_", " ").title()
        if ev in covered:
            rows.append(
                f"| {ev_label} | OK Analysed "
                f"| {tool_by_ev.get(ev, '-')} | - |"
            )
        else:
            note = _ACQUIRE_NOTES.get(ev, "Collect evidence to enable analysis.")
            rows.append(
                f"| {ev_label} | NOT Not provided "
                f"| - | {note} |"
            )
    return "\n".join(rows)


# ─────────────────────────────────────────────────────────────
# MOCK REPORT BUILDER
# ─────────────────────────────────────────────────────────────

def _mock_report(unified_evidence, shap_explanations, case_context):

    explanations = shap_explanations.get("explanations", [])
    if isinstance(explanations, dict):
        explanations = [{"artifact_id": k, **v} for k, v in explanations.items()]
    elif not isinstance(explanations, list):
        explanations = []

    anomaly_items        = [e for e in explanations if isinstance(e, dict) and e.get("is_anomaly")]
    anomaly_ids          = {e.get("artifact_id", "") for e in anomaly_items}
    anomaly_lookup       = {e.get("artifact_id", ""): e.get("reason", "") for e in anomaly_items}
    anomaly_reason_texts = [e.get("reason", "") for e in anomaly_items]
    n_anomalies          = len(anomaly_items)

    case_type  = case_context.get("case_type", "unknown")
    confidence = case_context.get("classifier_confidence", 0.0)
    case_id    = case_context.get("case_id", "N/A")
    summary    = case_context.get("raw_incident_summary", "No summary available.")
    hypotheses = case_context.get("hypotheses", [])

    tools_ran   = unified_evidence.get("tools_aggregated", [])
    total       = unified_evidence.get("total_items", 0)
    generated   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    overall_sev = _derive_severity(anomaly_items)

    all_items = [e for e in unified_evidence.get("evidence_items", []) if isinstance(e, dict)]
    priority_items = [e for e in all_items if e.get("severity") in ("critical", "high")][:15] or all_items[:10]
    for item in priority_items:
        aid = item.get("artifact_id", "")
        if aid in anomaly_lookup:
            item["_shap_reason"] = anomaly_lookup[aid]

    # Cover page
    cover = (
        f"# AutoForensiq — Forensic Investigation Report\n\n"
        f"| Field | Value |\n|-------|-------|\n"
        f"| **Case ID** | {case_id} |\n"
        f"| **Classification** | CONFIDENTIAL |\n"
        f"| **Date Generated** | {generated} |\n"
        f"| **Pipeline** | AutoForensiq v1.0 — PES University |\n"
        f"| **Case Type** | {case_type.replace('_', ' ').title()} |\n"
        f"| **Overall Severity** | **{overall_sev.upper()}** |"
    )

    # Executive summary
    exec_summary = (
        f"## Executive Summary\n\n{summary}\n\n"
        f"Automated analysis identified **{n_anomalies}** anomalous artifact(s) from {total} "
        f"total evidence items across {len(tools_ran)} forensic tool(s). "
        f"Overall case severity: **{overall_sev.upper()}**.\n\n"
        f"> Immediate analyst review is recommended."
    )

    # Case classification
    classification = (
        f"## Case Classification\n\n"
        f"| Field | Value |\n|-------|-------|\n"
        f"| **Case Type** | {case_type.replace('_', ' ').title()} |\n"
        f"| **Classifier Confidence** | {confidence:.0%} |\n"
        f"| **Case ID** | {case_id} |\n"
        f"| **Generated** | {generated} |"
    )

    # IOC table
    iocs = _extract_iocs(all_items)
    if iocs:
        ioc_rows = ["| Type | Indicator | Source Tool |", "|------|-----------|-------------|"]
        for ioc in iocs[:30]:
            ioc_rows.append(f"| {ioc['type']} | `{ioc['indicator']}` | {ioc['tool']} |")
        ioc_section = "## Indicators of Compromise\n\n" + "\n".join(ioc_rows)
    else:
        ioc_section = "## Indicators of Compromise\n\n_No discrete IOCs extracted from evidence._"

    # MITRE ATT&CK
    techniques = MITRE_BY_CASE.get(case_type, MITRE_BY_CASE["unknown"])
    basis      = "Anomaly detected" if n_anomalies > 0 else "Inferred from case type"
    mitre_rows = [
        "| Technique ID | Technique Name | Tactic | Evidence Basis |",
        "|--------------|----------------|--------|----------------|",
    ]
    for tid, tname, tactic in techniques:
        mitre_rows.append(f"| {tid} | {tname} | {tactic} | {basis} |")
    mitre_section = "## MITRE ATT&CK Mapping\n\n" + "\n".join(mitre_rows)

    # Process tree
    proc_tree = _build_process_tree(all_items, anomaly_ids)
    process_section = f"## Process Tree\n\n```\n{proc_tree}\n```\n_[!] = Critical/High   [ ] = Normal_"

    # Critical findings
    table_rows = [
        "| Severity | Artifact | Tool | Finding | XAI Explanation |",
        "|----------|----------|------|---------|-----------------|",
    ]
    for item in priority_items:
        if not isinstance(item, dict):
            continue
        aid      = item.get("artifact_id", "")
        xai_note = anomaly_lookup.get(aid, "-")[:80]
        table_rows.append(
            f"| {item.get('severity', '-').upper()} "
            f"| {item.get('evidence_type', '-')} "
            f"| {item.get('source_tool', '-')} "
            f"| {str(item.get('value', '-'))[:60]} "
            f"| {xai_note} |"
        )
    findings_section = "## Critical Findings\n\n" + "\n".join(table_rows)

    # Hypotheses
    hyp_lines = []
    for h in hypotheses:
        verdict = _evaluate_hypothesis(h, anomaly_reason_texts, n_anomalies)
        hyp_lines.append(f"**Hypothesis:** {h}  \n**Verdict:** {verdict}\n")
    hyp_section = (
        "## Hypotheses Evaluated\n\n" + "\n".join(hyp_lines)
        if hyp_lines else "## Hypotheses Evaluated\n\n_No hypotheses recorded._"
    )

    # Analyst verdict
    verdict_text = _build_analyst_verdict(case_type, overall_sev, n_anomalies, confidence)
    verdict_section = f"## Analyst Verdict\n\n{verdict_text}"

    # Recommendations
    recs = RECOMMENDATIONS_BY_CASE.get(case_type, RECOMMENDATIONS_BY_CASE["unknown"])
    rec_lines = "\n".join(f"{i+1}. {r}" for i, r in enumerate(recs))
    recs_section = f"## Recommendations\n\n{rec_lines}"

    # Evidence coverage
    coverage_section = "## Evidence Coverage\n\n" + _build_evidence_coverage(tools_ran)

    # Audit trail
    audit_section = (
        "## Audit Trail\n\n"
        "A SHA-256 audit log was generated at `output/audit_log.json` "
        "and can be used to verify evidence integrity for chain-of-custody compliance."
    )

    sections = [
        cover, exec_summary, classification, ioc_section,
        mitre_section, process_section, findings_section,
        hyp_section, verdict_section, recs_section,
        coverage_section, audit_section,
    ]
    return "\n\n---\n\n".join(sections)


# ─────────────────────────────────────────────────────────────
# MAIN PUBLIC FUNCTION
# ─────────────────────────────────────────────────────────────

def generate_report(
    unified_evidence,
    shap_explanations,
    case_context,
    output_path=None,
    config_override=None
):

    cfg = _load_config()

    if config_override:
        for k, v in config_override.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v

    mock_mode = cfg.get("llm", {}).get("mock_mode", False)
    provider  = cfg.get("llm", {}).get("provider", "openai")

    if mock_mode:
        print("  [MOCK] Building report from data.")
        report_text = _mock_report(unified_evidence, shap_explanations, case_context)
    else:
        user_prompt = _build_user_prompt(unified_evidence, shap_explanations, case_context)
        try:
            print(f"  [LIVE] Calling {provider}...")
            report_text = _call_openai(user_prompt, cfg)
        except Exception as exc:
            print(f"  [WARN] LLM failed ({exc})")
            print("  [FALLBACK] Using mock report.")
            report_text = _mock_report(unified_evidence, shap_explanations, case_context)

    if output_path is None:
        output_path = str(ROOT_DIR / "output" / "final_report.md")

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(f"  [DONE] Report written -> {output_path}")
    return report_text
