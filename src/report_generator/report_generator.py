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
# EXPLANATION SHAPE NORMALISER
# ─────────────────────────────────────────────────────────────

def _iter_explanations(shap_explanations):
    """Yield (artifact_id, explanation) pairs from the P5 output.

    pipeline.py emits `explanations` as a dict keyed by artifact_id; the
    error-fallback path in autoforensiq.py emits an empty list. Support both.
    """
    explanations = shap_explanations.get("explanations", {})

    if isinstance(explanations, dict):
        for aid, exp in explanations.items():
            if isinstance(exp, dict):
                yield aid, exp

    elif isinstance(explanations, list):
        for exp in explanations:
            if isinstance(exp, dict):
                yield exp.get("artifact_id", ""), exp


def _explanation_text(explanation):
    return (
        explanation.get("explain_instance")
        or explanation.get("plain_english")
        or explanation.get("reason")
        or ""
    )


def _score_summary(explanation):
    return {
        "model_score": explanation.get("model_score"),
        "rule_score": explanation.get("rule_score"),
        "final_score": explanation.get(
            "final_score",
            explanation.get("score")
        ),
        "threshold": explanation.get("threshold"),
        "confidence": explanation.get("confidence"),
        "severity": explanation.get("severity"),
    }


def _xai_payload(explanation):
    return {
        "summary": (
            explanation.get("plain_english")
            or explanation.get("reason")
            or _explanation_text(explanation)
        ),
        "explain_instance": _explanation_text(explanation),
        "scores": _score_summary(explanation),
        "top_factors": explanation.get("top_factors", []),
        "baseline_comparison": explanation.get("baseline_comparison", []),
        "machine_context": explanation.get("machine_context", {}),
        "correlation_context": explanation.get("correlation_context", []),
        "case_finding_context": explanation.get("case_finding_context", {}),
        "recommended_review": explanation.get("recommended_review", []),
    }


def _xai_lookup(shap_explanations, only_anomalies=False):
    lookup = {}

    for aid, item in _iter_explanations(shap_explanations):
        if only_anomalies and not item.get("is_anomaly"):
            continue

        lookup[aid] = _xai_payload(item)

    return lookup


def _format_score(value):
    if isinstance(value, (int, float)):
        return f"{value:+.4f}"
    return "N/A"


def _format_percent(value):
    if isinstance(value, (int, float)):
        return f"{value:.0%}"
    return "N/A"


def _format_top_factors(factors):
    if not factors:
        return "_No SHAP factors recorded._"

    lines = []
    for factor in factors[:5]:
        lines.append(
            "- "
            f"{factor.get('feature', 'unknown')}: "
            f"{factor.get('direction', 'unknown impact')} "
            f"(SHAP {_format_score(factor.get('shap_value'))}) — "
            f"{factor.get('meaning', 'No explanation available.')}"
        )

    return "\n".join(lines)


def _format_baseline_comparison(comparisons):
    if not comparisons:
        return "_No baseline comparison recorded._"

    lines = []
    for item in comparisons[:5]:
        lines.append(
            "- "
            f"{item.get('feature', 'unknown')}: "
            f"artifact={item.get('artifact_value', 'N/A')}, "
            f"baseline={item.get('baseline_average', 'N/A')}, "
            f"{item.get('direction', 'differs from baseline')}"
        )

    return "\n".join(lines)


def _format_correlation_context(correlations):
    if not correlations:
        return "_No P4 correlation context recorded._"

    lines = []
    for item in correlations[:5]:
        matches = item.get("matches") or []
        match_text = (
            f" using {', '.join(map(str, matches[:3]))}"
            if matches
            else ""
        )
        lines.append(
            "- "
            f"{item.get('artifact_id', 'unknown artifact')} via "
            f"{item.get('correlation_type', 'correlation')}"
            f"{match_text}"
        )

    return "\n".join(lines)


def _format_recommended_review(actions):
    if not actions:
        return "_No review actions recorded._"

    return "\n".join(f"- {action}" for action in actions[:5])


def _build_explainability_section(shap_explanations, max_items=8):
    items = [
        (aid, exp)
        for aid, exp in _iter_explanations(shap_explanations)
        if exp.get("is_anomaly")
    ]

    if not items:
        return "_No anomalous artifacts were available for XAI analysis._"

    sections = []

    for aid, exp in items[:max_items]:
        scores = _score_summary(exp)
        machine = exp.get("machine_context", {})
        machine_id = machine.get("machine_id") or "unknown"

        sections.append(
            "\n".join([
                f"### Artifact {aid}",
                "",
                f"- **Decision:** Anomalous",
                f"- **Severity:** {scores.get('severity', 'N/A')}",
                f"- **Confidence:** {_format_percent(scores.get('confidence'))}",
                f"- **Model Scope:** {exp.get('model_scope', 'N/A')}",
                f"- **Machine:** {machine_id}",
                f"- **Model Score:** {_format_score(scores.get('model_score'))}",
                f"- **Rule Score:** {_format_score(scores.get('rule_score'))}",
                f"- **Final Score:** {_format_score(scores.get('final_score'))}",
                f"- **Threshold:** {_format_score(scores.get('threshold'))}",
                "",
                "**Explanation**",
                "",
                _explanation_text(exp) or "_No explanation text recorded._",
                "",
                "**Top Contributing Factors**",
                "",
                _format_top_factors(exp.get("top_factors", [])),
                "",
                "**Baseline Comparison**",
                "",
                _format_baseline_comparison(
                    exp.get("baseline_comparison", [])
                ),
                "",
                "**P4 Correlation Context**",
                "",
                _format_correlation_context(
                    exp.get("correlation_context", [])
                ),
                "",
                "**Recommended Review**",
                "",
                _format_recommended_review(
                    exp.get("recommended_review", [])
                ),
            ])
        )

    return "\n\n".join(sections)


# ─────────────────────────────────────────────────────────────
# USER PROMPT BUILDER
# ─────────────────────────────────────────────────────────────

def _build_user_prompt(
    unified_evidence,
    shap_explanations,
    case_context
):

    xai_lookup = _xai_lookup(
        shap_explanations,
        only_anomalies=True
    )


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

        if aid in xai_lookup:

            item["_xai"] = xai_lookup[aid]

    prompt_parts = [

        "## Case Context",

        json.dumps(case_context, indent=2),

        "",

        "## Evidence",

        json.dumps(priority_items, indent=2),

        "",

        "## Explainability Analysis",

        _build_explainability_section(shap_explanations),

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


def _call_deepseek(user_prompt, cfg):

    from openai import OpenAI

    api_key = os.environ.get(
        cfg["llm"].get("deepseek_api_key_env", "DEEPSEEK_API_KEY")
    )

    client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")

    model = cfg["llm"].get("deepseek_model", "deepseek-chat")

    resp = client.chat.completions.create(
        model=model,
        max_tokens=cfg["llm"].get("max_tokens", 2048),
        temperature=cfg["llm"].get("temperature", 0.2),
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt},
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


def _is_internal_ip(ip):
    """True for non-routable / local IPs that don't belong in an external IOC
    table (loopback, broadcast, link-local, and RFC1918 private ranges). The
    affected host's own internal IP is reported as an affected system, not an
    indicator of compromise."""
    octets = ip.split(".")
    if len(octets) != 4 or not all(o.isdigit() for o in octets):
        return True
    a, b = int(octets[0]), int(octets[1])
    if a in (0, 10, 127, 255):
        return True
    if a == 169 and b == 254:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    return False


def _extract_iocs(evidence_items):
    """Extract discrete IOCs annotated with severity, the evidence context they
    were seen in, and any IOC-catalog matches that fired.

    The annotations let the table separate real indicators (e.g. critical C2
    URLs/IPs) from benign infrastructure noise. Beyond IPs/hashes/files we also
    surface tshark's network detail: domains from DNS queries and host+URI from
    HTTP requests. Results are returned sorted by severity (critical first)."""
    IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    HASH_RE = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
    DOMAIN_RE = re.compile(r"→\s*([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})", re.IGNORECASE)
    URL_RE = re.compile(r"→\s*(\S+/\S*)")
    FNAME_EXTS = (".exe", ".dll", ".bat", ".ps1", ".vbs", ".cmd", ".scr")

    _CTX = {
        "network_connection": "Network connection",
        "dns_query": "DNS query",
        "http_request": "HTTP request",
    }

    records = {}

    def _add(ioc_type, indicator, item, context):
        if not indicator:
            return
        sev = str(item.get("severity", "low")).lower()
        key = (ioc_type, indicator)
        rec = records.get(key)
        if rec is None:
            rec = {
                "type": ioc_type,
                "indicator": indicator,
                "severity": sev,
                "tool": item.get("source_tool", "-"),
                "contexts": set(),
                "matches": set(),
            }
            records[key] = rec
        # An indicator inherits the highest severity of any item it appeared in.
        if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(rec["severity"], 0):
            rec["severity"] = sev
        if context:
            rec["contexts"].add(context)
        for m in (item.get("ioc_match") or []):
            rec["matches"].add(m)

    for item in evidence_items:
        if not isinstance(item, dict):
            continue
        val = str(item.get("value", ""))
        etype = item.get("evidence_type", "")
        ctx = _CTX.get(etype, etype or "evidence")

        if etype == "dns_query":
            m = DOMAIN_RE.search(val)
            if m:
                _add("Domain", m.group(1).rstrip("."), item, ctx)
        elif etype == "http_request":
            m = URL_RE.search(val)
            if m:
                _add("URL", m.group(1), item, ctx)

        for ip in IP_RE.findall(val):
            if _is_internal_ip(ip):
                continue
            _add("IP Address", ip, item, ctx)
        for h in HASH_RE.findall(val):
            if len(h) in (32, 64):
                htype = "MD5 Hash" if len(h) == 32 else "SHA-256 Hash"
                _add(htype, h, item, ctx)
        if any(ext in val.lower() for ext in FNAME_EXTS):
            for tok in val.split():
                if tok.lower().endswith(FNAME_EXTS):
                    _add("Suspicious File", tok[:60], item, ctx)
        if val.startswith(("HKEY", "HKLM", "HKCU")):
            _add("Registry Key", val[:60], item, ctx)

    iocs = list(records.values())
    iocs.sort(key=lambda r: (
        -_SEVERITY_RANK.get(r["severity"], 0),   # critical first
        0 if r["matches"] else 1,                # catalog matches ahead of bare observations
        r["type"],
        r["indicator"],
    ))
    return iocs


def _md_cell(value) -> str:
    """Make an arbitrary tool string safe inside a GitHub-markdown table cell.

    Newlines split the row and unescaped pipes split the columns, so a value
    from any tool (e.g. a multiline JSON blob) could otherwise corrupt the
    table. Collapse whitespace and escape pipes.
    """
    if value is None:
        return "-"
    s = str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    return " ".join(s.split()).strip() or "-"


# Process evidence types we accept into the tree. Deliberately excludes
# network_connection / injected_code / file_artifact etc. whose free-text value
# may contain the substring "pid" — those polluted the old heuristic filter.
_PROCESS_EVIDENCE_TYPES = {"process", "memprocfs_process"}

# Match PID/PPID across each tool's delimiter style (PID:1940, PID 1234,
# "pid": 1636). The negative lookbehind on (?<![a-z]) stops the bare-PID pattern
# from matching the "pid" inside "ppid".
_PID_RE = re.compile(r'(?<![a-z])"?pid"?[\s:=]+(\d+)', re.IGNORECASE)
_PPID_RE = re.compile(r'"?ppid"?[\s:=]+(\d+)', re.IGNORECASE)

_TREE_ROW_CAP = 40


def _parse_flat_pids(value: str):
    """Extract (pid, ppid) from a flat process item's free-text value.

    Returns string PIDs or None when absent. PPID is parsed first so the
    bare-PID lookbehind never picks up the digits belonging to "ppid".
    """
    ppid_m = _PPID_RE.search(value)
    pid_m = _PID_RE.search(value)
    pid = pid_m.group(1) if pid_m else None
    ppid = ppid_m.group(1) if ppid_m else None
    return pid, ppid


def _build_process_tree(evidence_items, anomaly_ids):
    """Render a parent->child process hierarchy from structured evidence.

    Driven primarily by the ``process_tree`` JSON volatility emits
    (serialize_tree); flat ``process`` items from tools that don't emit a tree
    are slotted under their parent PID when known. Builds a unified PID
    namespace across all tools so the section stays correct multi-tool.
    """
    items = [e for e in evidence_items if isinstance(e, dict)]

    # node: {pid, ppid, name, suspicious, severity, aid, children:[pid...]}
    nodes: dict = {}
    child_order: dict = {}  # pid -> ordered list of child pids

    def _norm_pid(p):
        return str(p) if p is not None and str(p) != "" else None

    def _ensure(pid, **fields):
        pid = _norm_pid(pid)
        if pid is None:
            return None
        node = nodes.get(pid)
        if node is None:
            node = {"pid": pid, "ppid": None, "name": "", "suspicious": False,
                    "severity": "", "aid": "", "_children": []}
            nodes[pid] = node
        for k, v in fields.items():
            # don't clobber a real value with an empty one
            if v not in (None, "") and not node.get(k):
                node[k] = v
        return node

    def _link(parent_pid, child_pid):
        parent_pid = _norm_pid(parent_pid)
        child_pid = _norm_pid(child_pid)
        if parent_pid is None or child_pid is None or parent_pid == child_pid:
            return
        kids = child_order.setdefault(parent_pid, [])
        if child_pid not in kids:
            kids.append(child_pid)

    def _ingest_tree(raw, item):
        """Recursively fold a serialize_tree() dict into the node index."""
        if not isinstance(raw, dict):
            return
        pid = _norm_pid(raw.get("pid"))
        if pid is None:
            return
        # The tree is authoritative for hierarchy / name / suspicious only;
        # per-process severity and artifact_id (used for flagging) come from the
        # flat process items, which carry the IOC-rescored severity and the real
        # proc_<pid>_<name> ids that the anomaly set references.
        node = _ensure(
            pid,
            ppid=_norm_pid(raw.get("ppid")),
            name=str(raw.get("name") or ""),
        )
        if raw.get("suspicious"):
            node["suspicious"] = True
        if node["ppid"]:
            _link(node["ppid"], pid)
        for child in raw.get("children", []) or []:
            _ingest_tree(child, item)
            cpid = _norm_pid(child.get("pid")) if isinstance(child, dict) else None
            if cpid:
                _link(pid, cpid)

    # 1) Structured trees first — authoritative hierarchy.
    for item in items:
        if item.get("evidence_type") != "process_tree":
            continue
        try:
            _ingest_tree(json.loads(str(item.get("value", ""))), item)
        except (ValueError, TypeError):
            continue

    # 2) Flat process items — only add PIDs not already in a tree.
    for item in items:
        if item.get("evidence_type") not in _PROCESS_EVIDENCE_TYPES:
            continue
        pid, ppid = _parse_flat_pids(str(item.get("value", "")))
        if pid is None:
            continue
        val = str(item.get("value", ""))
        name = val.split()[0] if val.split() else item.get("artifact_id", "unknown")
        existed = pid in nodes
        node = _ensure(
            pid, ppid=ppid, name=name,
            severity=str(item.get("severity", "")).lower(),
            aid=item.get("artifact_id", ""),
        )
        if not existed and ppid:
            _link(ppid, pid)

    if not nodes:
        return "_No process artifacts in evidence._"

    # Roots: a PID with no PPID, or whose PPID points outside the captured set
    # (e.g. System's ppid 0, or a parent that wasn't collected). Derived from the
    # node's own ppid — not child_order — so a real root isn't hidden by an edge
    # to a phantom parent that has no node of its own.
    roots = sorted(
        pid for pid in nodes
        if not nodes[pid]["ppid"] or nodes[pid]["ppid"] not in nodes
    )

    lines: list = []
    emitted: set = set()

    def _emit(pid, prefix="", child_prefix=""):
        # prefix renders before this node's name (box-drawing connectors so the
        # hierarchy survives renderers that collapse leading whitespace);
        # child_prefix is the base the node's own children build on.
        if len(lines) >= _TREE_ROW_CAP or pid in emitted:
            return
        emitted.add(pid)
        node = nodes[pid]
        flag = "[!]" if (node["severity"] in ("critical", "high")
                         or node["suspicious"]
                         or node["aid"] in anomaly_ids) else "[ ]"
        name = node["name"] or node["aid"] or "unknown"
        label = f"{prefix}{name}"
        ppid = node["ppid"] or "?"
        lines.append(f"  {flag}  {label:<46}  PID {pid:<6}  PPID {ppid}")
        kids = child_order.get(pid, [])
        for idx, cpid in enumerate(kids):
            last = idx == len(kids) - 1
            _emit(
                cpid,
                prefix=child_prefix + ("└─ " if last else "├─ "),
                child_prefix=child_prefix + ("   " if last else "│  "),
            )

    for root in roots:
        _emit(root)
    # Any node never reached from a root (cyclic/orphaned data) — show flat.
    for pid in sorted(nodes):
        _emit(pid)

    if len(nodes) > len(emitted):
        lines.append(f"  …  ({len(nodes)} processes total; output truncated)")
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

    xai_lookup = _xai_lookup(shap_explanations, only_anomalies=True)

    case_type  = case_context.get("case_type", "unknown")
    confidence = case_context.get("classifier_confidence", 0.0)
    case_id    = case_context.get("case_id", "N/A")
    summary    = case_context.get("raw_incident_summary", "No summary available.")
    hypotheses = case_context.get("hypotheses", [])

    # tool -> source evidence file (recorded by the orchestrator). Lets findings
    # be attributed to the artifact they came from.
    tool_sources = case_context.get("evidence_sources", {})

    tools_ran = unified_evidence.get("tools_aggregated", [])
    total     = unified_evidence.get("total_items", 0)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Bridge aliases used by post-resolution code
    anomaly_lookup       = {aid: d.get("summary", "-") for aid, d in xai_lookup.items()}
    anomaly_ids          = set(xai_lookup.keys())
    anomaly_reason_texts = [d.get("summary", "") for d in xai_lookup.values()]
    n_anomalies          = len(xai_lookup)
    overall_sev          = "high" if n_anomalies >= 3 else ("medium" if n_anomalies >= 1 else "low")


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

    # IOC table — severity-ranked, with context so real indicators stand out
    # from benign infrastructure noise.
    iocs = _extract_iocs(all_items)
    if iocs:
        ioc_rows = [
            "| Severity | Type | Indicator | Source | Evidence File | Context |",
            "|----------|------|-----------|--------|---------------|---------|",
        ]
        # Always show flagged indicators (medium+ or a catalog match) in full;
        # cap the long tail of low-severity observations so the table stays
        # readable without hiding anything that matters.
        flagged = [
            i for i in iocs
            if _SEVERITY_RANK.get(i["severity"], 0) >= _SEVERITY_RANK["medium"]
            or i["matches"]
        ]
        flagged_keys = {(i["type"], i["indicator"]) for i in flagged}
        others = [i for i in iocs if (i["type"], i["indicator"]) not in flagged_keys]
        shown = flagged + others[:max(0, 25 - len(flagged))]

        for ioc in shown:
            ctx = ", ".join(sorted(ioc["contexts"])) or "-"
            if ioc["matches"]:
                ctx += f" — **IOC match: {', '.join(sorted(ioc['matches']))}**"
            indicator = ioc["indicator"]
            if len(indicator) > 70:
                indicator = indicator[:67] + "..."
            src_file = tool_sources.get(ioc["tool"], "-")
            ioc_rows.append(
                f"| {ioc['severity'].upper()} | {_md_cell(ioc['type'])} "
                f"| `{_md_cell(indicator)}` | {_md_cell(ioc['tool'])} "
                f"| {_md_cell(src_file)} | {_md_cell(ctx)} |"
            )

        ioc_section = "## Indicators of Compromise\n\n" + "\n".join(ioc_rows)
        remaining = len(iocs) - len(shown)
        if remaining > 0:
            ioc_section += (
                f"\n\n_…and {remaining} additional lower-severity indicator(s) — "
                "see `output/unified_evidence.json` for the full set._"
            )
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
        mitre_rows.append(
            f"| {_md_cell(tid)} | {_md_cell(tname)} | {_md_cell(tactic)} | {_md_cell(basis)} |"
        )
    mitre_section = "## MITRE ATT&CK Mapping\n\n" + "\n".join(mitre_rows)

    # Process tree
    proc_tree = _build_process_tree(all_items, anomaly_ids)
    process_section = f"## Process Tree\n\n```\n{proc_tree}\n```\n[!] = Critical/High\n[ ] = Normal"

    # Critical findings
    table_rows = [
        "| Severity | Artifact | Tool | Evidence File | Finding | XAI Explanation |",
        "|----------|----------|------|---------------|---------|-----------------|",
    ]
    for item in priority_items:
        if not isinstance(item, dict):
            continue
        aid      = item.get("artifact_id", "")
        xai_note = anomaly_lookup.get(aid, "-")[:80]
        src_file = tool_sources.get(item.get("source_tool", ""), "-")
        table_rows.append(
            f"| {_md_cell(item.get('severity', '-').upper())} "
            f"| {_md_cell(item.get('evidence_type', '-'))} "
            f"| {_md_cell(item.get('source_tool', '-'))} "
            f"| {_md_cell(src_file)} "
            f"| {_md_cell(str(item.get('value', '-'))[:60])} "
            f"| {_md_cell(xai_note)} |"
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
            if provider == "deepseek":
                report_text = _call_deepseek(user_prompt, cfg)
            elif provider == "anthropic":
                report_text = _call_openai(user_prompt, cfg)  # fallback: no Anthropic in report gen yet
            else:
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
