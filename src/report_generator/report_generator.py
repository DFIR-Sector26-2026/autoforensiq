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
    "memprocfs":   "memory_dump",
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
    indicator of compromise. Malformed or out-of-range dotted-quads (e.g.
    999.999.999.999) are also excluded — they aren't real external indicators."""
    octets = ip.split(".")
    if len(octets) != 4 or not all(o.isdigit() for o in octets):
        return True
    if not all(0 <= int(o) <= 255 for o in octets):
        return True            # impossible address — not a real external IOC
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


# ─── IOC extraction (shared) ──────────────────────────────────
# Module-scope so both the per-item Key Findings "Indicators" column and the
# deduped _extract_iocs rollup use identical patterns and gating.
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
_DOMAIN_RE = re.compile(r"→\s*([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})", re.IGNORECASE)
_URL_RE = re.compile(r"→\s*(\S+/\S*)")
# suspicious_domain / suspicious_crypto items carry the bare indicator as their
# value (no "→" arrow), so they need their own anchored patterns. The domain
# pattern also matches .onion hidden services (e.g. <16-56 base32>.onion).
_SUSP_DOMAIN_RE = re.compile(r"\b([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})\b", re.IGNORECASE)
_CRYPTO_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_FNAME_EXTS = (".exe", ".dll", ".bat", ".ps1", ".vbs", ".cmd", ".scr")
# Aggregate items re-list many process names (the whole tree, a parent->child
# pair); tokenizing them would stamp the aggregate's severity/ioc_match onto
# every benign name, so files come only from discrete items.
_AGG_PROC_TYPES = {"process_tree", "process_relation"}

_IOC_CTX = {
    "network_connection": "Network connection",
    "dns_query": "DNS query",
    "http_request": "HTTP request",
}


# Analyst-facing labels for the Key Findings "Type" column. The raw
# evidence_type values are pipeline-internal (e.g. memprocfs_process, ioc);
# this maps them to vocabulary a reader of the report expects. Unknown types
# fall back to a title-cased form of the raw value.
_FINDING_TYPE_LABEL = {
    "process":            "Process",
    "memprocfs_process":  "Process",
    "process_relation":   "Process Relationship",
    "process_tree":       "Process Tree",
    "injected_code":      "Code Injection",
    "malfind":            "Code Injection",
    "network_connection": "Network Connection",
    "dns_query":          "DNS Query",
    "http_request":       "HTTP Request",
    "file_artifact":      "File Artifact",
    "registry_key":       "Registry Key",
    "suspicious_domain":  "Suspicious Domain",
    "suspicious_crypto":  "Crypto Wallet",
    "ioc":                "IOC Match",
}


def _finding_type(etype):
    """Analyst-facing label for an evidence_type (Key Findings 'Type' column)."""
    if not etype:
        return "-"
    return _FINDING_TYPE_LABEL.get(etype, etype.replace("_", " ").title())


def _primary_name(val):
    """The single-token process/file name in a flagged item's value, e.g.
    "Suspicious process detected: @WanaDecryptor@" or "@WanaDecryptor@ (PID:740 …)"
    → "@WanaDecryptor@". Returns None when the value isn't a single bare name
    (e.g. "Process injection detected") so free-text doesn't become a fake IOC."""
    low = val.lower()
    if "detected:" in low:
        val = val[low.index("detected:") + len("detected:"):]
    name = val.split(" (")[0].strip()
    return name if name and " " not in name else None


def _item_indicators(item):
    """Atomic IOCs extracted from one evidence item as (type, indicator) tuples
    (order-stable, undeduped). Shared by the Key Findings inline Indicators
    column and _extract_iocs (which dedups these across all items)."""
    if not isinstance(item, dict):
        return []
    val = str(item.get("value", ""))
    etype = item.get("evidence_type", "")
    out = []

    if etype == "dns_query":
        m = _DOMAIN_RE.search(val)
        if m:
            out.append(("Domain", m.group(1).rstrip(".")))
    elif etype == "http_request":
        m = _URL_RE.search(val)
        if m:
            out.append(("URL", m.group(1)))
    elif etype == "suspicious_domain":
        # String-sweep C2 indicator: a bare domain or a .onion hidden service.
        m = _SUSP_DOMAIN_RE.search(val)
        if m:
            dom = m.group(1).rstrip(".")
            label = "Onion Address" if dom.lower().endswith(".onion") else "Domain"
            out.append((label, dom))
    elif etype == "suspicious_crypto":
        # String-sweep crypto indicator (e.g. a ransom BTC wallet). The value is
        # the bare address, so fall back to it when the regex (legacy BTC only)
        # doesn't match — otherwise a bech32/ETH wallet P3 may add later would be
        # silently dropped, the same failure mode the .onion fix removed.
        m = _CRYPTO_RE.search(val)
        indicator = m.group(0) if m else val.strip()[:80]
        if indicator:
            out.append(("Crypto Wallet", indicator))

    for ip in _IP_RE.findall(val):
        if not _is_internal_ip(ip):
            out.append(("IP Address", ip))
    for h in _HASH_RE.findall(val):
        if len(h) == 32:
            out.append(("MD5 Hash", h))
        elif len(h) == 64:
            out.append(("SHA-256 Hash", h))

    # Only surface a filename as an IOC when the item carries actual signal: an
    # elevated severity or an IOC-catalog match. A bare low-severity process/file
    # observation isn't an indicator and would just flood with benign binaries.
    file_signal = (
        _SEVERITY_RANK.get(str(item.get("severity", "low")).lower(), 0)
        >= _SEVERITY_RANK["high"]
        or bool(item.get("ioc_match"))
    )
    if etype not in _AGG_PROC_TYPES and file_signal:
        ext_tokens = [t for t in val.split() if t.lower().endswith(_FNAME_EXTS)]
        if ext_tokens:
            for tok in ext_tokens:
                out.append(("Suspicious File", tok[:60]))
        elif etype in ("process", "memprocfs_process", "ioc"):
            # Some flagged binaries have no extension (e.g. "@WanaDecryptor@").
            # Recover the bare process/file name so the IOC isn't dropped.
            name = _primary_name(val)
            if name:
                out.append(("Suspicious File", name[:60]))

    if val.startswith(("HKEY", "HKLM", "HKCU", "HKCR", "HKU", "\\Registry")):
        out.append(("Registry Key", val[:60]))

    return out


def _finding_sort_key(item):
    """Key Findings ordering: severity first, then — within a tier — items
    carrying a concrete IOC (a catalog ioc_match, or an extractable atomic
    indicator: domain/onion/wallet/IP/hash/file/registry) ahead of
    indicator-less ones. Without the tie-break, under KEY_FINDINGS_CAP the
    high-severity .onion C2 / ransom wallets lose their slots to the many
    indicator-less ransom-note language files (`*.wnry`) that become
    finding-eligible only via their XAI note (issue 3.3-I)."""
    sev = -_SEVERITY_RANK.get(str(item.get("severity", "low")).lower(), 0)
    has_ioc = 0 if (item.get("ioc_match") or _item_indicators(item)) else 1
    return (sev, has_ioc)


def _indicators_cell(item):
    """Render the Key Findings 'Indicators / IOC Match' column for one item:
    the atomic indicators it yielded plus any IOC-catalog match badge."""
    parts, seen = [], set()
    for ioc_type, ind in _item_indicators(item):
        key = (ioc_type, ind)
        if key in seen:
            continue
        seen.add(key)
        parts.append(f"`{ind}` ({ioc_type})")
    cell = " · ".join(parts)
    matches = sorted(set(item.get("ioc_match") or []))
    if matches:
        # Put the catalog-match badge on its own line within the same cell.
        # `<br>` survives _md_cell (no pipe/whitespace) and renders as a line
        # break in both the dev_report HTML and raw-markdown views. The trailing
        # &nbsp; indents the badge so it lines up under the indicator above it (a
        # plain space would be collapsed by the browser after a line break).
        cell = (cell + "<br>&nbsp;" if cell else "") + f"**IOC: {', '.join(matches)}**"
    return _md_cell(cell or "-")


def _extract_iocs(evidence_items, severity_lookup=None):
    """Deduped IOC rollup: every atomic indicator across all items, annotated
    with the highest severity it was seen at, the contexts it appeared in, and
    any IOC-catalog matches. Sorted critical-first. Retained as a reusable
    indicator export; the report itself now inlines indicators per finding.

    `severity_lookup` (artifact_id -> anomaly/P5 severity) lets an indicator
    inherit the EFFECTIVE severity the pipeline ultimately assigned, not the
    wrapper's first guess: a string-swept domain is emitted `low` but may be
    elevated to High/Critical by anomaly detection or reputation, and the report
    should rank and surface it on that verdict. `confidence` (max across the
    contributing items) carries the wrapper's URL-context tier so the folded
    low-severity list can be sampled anchored-first."""
    records = {}
    severity_lookup = severity_lookup or {}

    def _effective_sev(item):
        sev = str(item.get("severity", "low")).lower()
        elevated = severity_lookup.get(item.get("artifact_id"))
        if elevated and _SEVERITY_RANK.get(elevated, 0) > _SEVERITY_RANK.get(sev, 0):
            return elevated
        return sev

    def _add(ioc_type, indicator, item, context):
        if not indicator:
            return
        sev = _effective_sev(item)
        try:
            conf = float(item.get("confidence", 0) or 0)
        except (TypeError, ValueError):
            conf = 0.0
        key = (ioc_type, indicator)
        rec = records.get(key)
        if rec is None:
            rec = {
                "type": ioc_type,
                "indicator": indicator,
                "severity": sev,
                "confidence": conf,
                "tool": item.get("source_tool", "-"),
                "contexts": set(),
                "matches": set(),
                "tools": set(),
                "artifact_ids": set(),
            }
            records[key] = rec
        # An indicator inherits the highest severity of any item it appeared in.
        if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(rec["severity"], 0):
            rec["severity"] = sev
        if conf > rec["confidence"]:
            rec["confidence"] = conf
        if context:
            rec["contexts"].add(context)
        for m in (item.get("ioc_match") or []):
            rec["matches"].add(m)
        # Track every contributing tool + artifact so the detailed IOC report can
        # resolve source files and the per-indicator XAI explanation.
        if item.get("source_tool"):
            rec["tools"].add(item["source_tool"])
        if item.get("artifact_id"):
            rec["artifact_ids"].add(item["artifact_id"])

    for item in evidence_items:
        if not isinstance(item, dict):
            continue
        etype = item.get("evidence_type", "")
        ctx = _IOC_CTX.get(etype, etype or "evidence")
        for ioc_type, indicator in _item_indicators(item):
            _add(ioc_type, indicator, item, ctx)

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


def _truncate(text, limit=100):
    """Shorten to <= limit chars on a word boundary, adding an ellipsis, so the
    text isn't cut mid-word (e.g. '...anomaly d'). Short text is returned as-is."""
    s = str(text)
    if len(s) <= limit:
        return s
    cut = s[:limit].rsplit(" ", 1)[0].rstrip()
    return (cut or s[:limit].rstrip()) + "…"


def _ioc_xai_note(rec, anomaly_lookup, limit=100):
    """First XAI summary among the indicator's contributing artifacts, if any."""
    for aid in sorted(rec.get("artifact_ids") or []):
        note = anomaly_lookup.get(aid)
        if note and note != "-":
            return _truncate(note, limit)
    return "-"


# An indicator earns a full row in the main IOC table when the pipeline actually
# prioritised it — effective severity medium-or-higher, or a fired IOC-catalog /
# reputation match. Everything below that (the low-severity string-sweep mass,
# e.g. ~16k bare domains on a Windows memory image) is folded into a collapsed
# sample so it can't drown the document — but it is never dropped: counts, a
# confidence-tiered sample, and a pointer to the full evidence JSON are kept.
_IOC_SURFACE_RANK = _SEVERITY_RANK["medium"]  # medium-or-higher earns a main-table row
# A domain whose wrapper confidence reached the URL-context (anchored) tier.
_ANCHORED_CONF = 0.45
_FOLDED_SAMPLE_CAP = 50


def _ioc_is_surfaced(rec):
    return (_SEVERITY_RANK.get(rec["severity"], 0) >= _IOC_SURFACE_RANK
            or bool(rec["matches"]))


def _build_ioc_report(all_items, tool_sources=None, anomaly_lookup=None,
                      severity_lookup=None):
    """Standalone, human-readable Indicators-of-Compromise document.

    The main table lists indicators the pipeline prioritised (effective severity
    medium+ or an IOC/reputation match) with provenance and the XAI explanation.
    The low-severity string-sweep remainder is folded into a collapsed,
    confidence-tiered sample so it never drowns the report; nothing is discarded
    — the full set stays in unified_evidence.json. `severity_lookup` supplies the
    effective (post-anomaly) severity so elevated domains surface here.
    """
    tool_sources = tool_sources or {}
    anomaly_lookup = anomaly_lookup or {}
    iocs = _extract_iocs(all_items, severity_lookup)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    header = (
        "# AutoForensiq — Indicators of Compromise\n\n"
        f"_Generated {generated}_\n\n"
    )
    if not iocs:
        return header + "_No indicators of compromise extracted from evidence._\n"

    surfaced = [r for r in iocs if _ioc_is_surfaced(r)]
    folded = [r for r in iocs if not _ioc_is_surfaced(r)]

    by_type, by_sev = {}, {}
    for r in surfaced:
        by_type[r["type"]] = by_type.get(r["type"], 0) + 1
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
    type_breakdown = ", ".join(f"{n} {t}" for t, n in sorted(by_type.items())) or "none"
    sev_breakdown = ", ".join(
        f"{by_sev[s]} {s}" for s in ("critical", "high", "medium", "low")
        if by_sev.get(s)
    ) or "none"
    summary = (
        f"**{len(surfaced)}** prioritised indicator(s) — {type_breakdown}.\n\n"
        f"By severity: {sev_breakdown}.\n\n"
    )
    if folded:
        summary += (
            f"_{len(folded)} additional low-severity indicator(s) folded below "
            f"(not elevated by anomaly detection or reputation)._\n\n"
        )

    parts = [header, summary]

    if surfaced:
        rows = [
            "| Indicator | Type | Severity | IOC Match | Context(s) | Source (tool · file) | Why (XAI) |",
            "|-----------|------|----------|-----------|------------|----------------------|-----------|",
        ]
        for r in surfaced:
            matches = ", ".join(sorted(r["matches"])) if r["matches"] else "-"
            contexts = ", ".join(sorted(r["contexts"])) if r["contexts"] else "-"
            srcs = []
            for tool in sorted(r.get("tools") or ([r["tool"]] if r.get("tool") else [])):
                src_file = tool_sources.get(tool, "-")
                srcs.append(tool if src_file in ("-", "", None) else f"{tool} · {src_file}")
            src_cell = "; ".join(srcs) if srcs else "-"
            xai = _ioc_xai_note(r, anomaly_lookup)
            rows.append(
                f"| `{_md_cell(r['indicator'])}` "
                f"| {_md_cell(r['type'])} "
                f"| {_md_cell(r['severity'].upper())} "
                f"| {_md_cell(matches)} "
                f"| {_md_cell(contexts)} "
                f"| {_md_cell(src_cell)} "
                f"| {_md_cell(xai)} |"
            )
        parts.append("\n".join(rows) + "\n")
    else:
        parts.append("_No prioritised indicators; see the folded list below._\n")

    if folded:
        parts.append(_render_folded_iocs(folded))

    return "".join(parts)


def _render_folded_iocs(folded):
    """Collapsed <details> block summarising the low-severity indicator mass:
    per-type counts, a domain anchored/bare tier split, and a capped sample
    ordered by confidence (anchored first). Non-destructive — the full set is in
    unified_evidence.json."""
    by_type = {}
    for r in folded:
        by_type[r["type"]] = by_type.get(r["type"], 0) + 1
    type_breakdown = ", ".join(f"{n} {t}" for t, n in sorted(by_type.items()))

    domains = [r for r in folded if r["type"] in ("Domain", "Onion Address")]
    tier_note = ""
    if domains:
        anchored = sum(1 for r in domains if r.get("confidence", 0) >= _ANCHORED_CONF)
        tier_note = (
            f" Of {len(domains)} domain(s): {anchored} anchored (URL/Host context), "
            f"{len(domains) - anchored} bare."
        )

    sample = sorted(
        folded,
        key=lambda r: (-r.get("confidence", 0.0), r["type"], r["indicator"]),
    )[:_FOLDED_SAMPLE_CAP]
    sample_rows = ["| Indicator | Type | Confidence tier |", "|---|---|---|"]
    for r in sample:
        tier = "anchored" if r.get("confidence", 0) >= _ANCHORED_CONF else "bare"
        sample_rows.append(
            f"| `{_md_cell(r['indicator'])}` | {_md_cell(r['type'])} | {tier} |"
        )

    return (
        "\n<details>\n"
        f"<summary><b>{len(folded)}</b> low-severity / un-elevated indicator(s) "
        "folded — not flagged by anomaly detection or reputation. "
        "Expand for a sample.</summary>\n\n"
        f"By type: {type_breakdown}.{tier_note}\n\n"
        f"Showing top {len(sample)} by confidence (anchored first):\n\n"
        + "\n".join(sample_rows)
        + "\n\n_Full set in `output/unified_evidence.json`._\n"
        "</details>\n"
    )


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


def _build_process_tree(evidence_items, anomaly_ids, tool_sources=None):
    """Render a parent->child process hierarchy from flat process evidence.

    Volatility's ``process_tree`` value is now a human-readable text summary (not
    JSON), so the hierarchy is rebuilt from the flat ``process`` /
    ``memprocfs_process`` items — each carries PID/PPID and the IOC-rescored
    severity — linked child->parent by PPID. ``process_relation`` items mark
    suspicious lineage. Only flagged processes and the parent chain that anchors
    them are shown, with a severity word and the source evidence file per row.
    """
    tool_sources = tool_sources or {}
    items = [e for e in evidence_items if isinstance(e, dict)]

    # node: {pid, ppid, name, suspicious, severity, aid, source_tool, ioc_match}
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
                    "severity": "", "aid": "", "source_tool": "", "ioc_match": []}
            nodes[pid] = node
        for k, v in fields.items():
            if k == "severity":
                # keep the highest severity ever seen for this PID
                if _SEVERITY_RANK.get(str(v).lower(), 0) > \
                   _SEVERITY_RANK.get(str(node.get(k, "")).lower(), 0):
                    node[k] = v
            elif k == "ioc_match":
                # union the catalog matches across observations
                if v:
                    merged = list(node.get(k) or [])
                    for m in v:
                        if m not in merged:
                            merged.append(m)
                    node[k] = merged
            # don't clobber a populated value with an empty one
            elif v not in (None, "", []) and not node.get(k):
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

    # 1) Flat process items build the node index + PPID hierarchy.
    for item in items:
        if item.get("evidence_type") not in _PROCESS_EVIDENCE_TYPES:
            continue
        pid, ppid = _parse_flat_pids(str(item.get("value", "")))
        if pid is None:
            continue
        val = str(item.get("value", ""))
        name = val.split()[0] if val.split() else item.get("artifact_id", "unknown")
        _ensure(
            pid, ppid=ppid, name=name,
            severity=str(item.get("severity", "")).lower(),
            aid=item.get("artifact_id", ""),
            source_tool=item.get("source_tool", ""),
            ioc_match=item.get("ioc_match", []),
        )
        if ppid:
            _link(ppid, pid)

    if not nodes:
        return "_No process artifacts in evidence._"

    # 2) process_relation items flag a suspicious parent->child lineage. The child
    #    PID is the last linked artifact (proc_<child>) or the trailing id segment
    #    (relation_<parent>_<child>); mark it so the lineage survives the prune.
    for item in items:
        if item.get("evidence_type") != "process_relation":
            continue
        child_pid = None
        linked = item.get("linked_artifacts") or []
        if linked:
            m = re.search(r"(\d+)", str(linked[-1]))
            child_pid = m.group(1) if m else None
        if child_pid is None:
            m = re.search(r"relation_\d+_(\d+)", str(item.get("artifact_id", "")))
            child_pid = m.group(1) if m else None
        if child_pid in nodes:
            nodes[child_pid]["suspicious"] = True

    # Roots: a PID with no PPID, or whose PPID points outside the captured set
    # (e.g. System's ppid 0, or a parent that wasn't collected). Derived from the
    # node's own ppid so a real root isn't hidden behind a phantom parent.
    roots = sorted(
        pid for pid in nodes
        if not nodes[pid]["ppid"] or nodes[pid]["ppid"] not in nodes
    )

    # 3) Keep only flagged processes and the ancestor chain that anchors them, so
    #    benign noise drops out while the lineage to a malicious process stays.
    def _is_flagged(node):
        return (node["severity"] in ("critical", "high")
                or node["suspicious"]
                or node["aid"] in anomaly_ids
                or bool(node["ioc_match"]))

    keep: set = set()
    for pid, node in nodes.items():
        if not _is_flagged(node):
            continue
        keep.add(pid)
        cur = node["ppid"]            # walk ancestors (bounded to guard cycles)
        seen = 0
        while cur in nodes and cur not in keep and seen < len(nodes):
            keep.add(cur)
            cur = nodes[cur]["ppid"]
            seen += 1

    if not keep:
        return (f"_No flagged processes — {len(nodes)} process(es) captured "
                "(see output/unified_evidence.json)._")

    lines: list = []
    emitted: set = set()

    def _emit(pid, prefix="", child_prefix=""):
        # prefix renders before this node's name (box-drawing connectors so the
        # hierarchy survives renderers that collapse leading whitespace).
        if pid not in keep or len(lines) >= _TREE_ROW_CAP or pid in emitted:
            return
        emitted.add(pid)
        node = nodes[pid]
        sev = (node["severity"] or "-").upper()
        name = node["name"] or node["aid"] or "unknown"
        label = f"{prefix}{name}"
        ppid = node["ppid"] or "?"
        src = tool_sources.get(node["source_tool"], "-")
        lines.append(
            f"  {sev:<8}  {label:<44}  PID {pid:<6}  PPID {ppid:<6}  {src}"
        )
        kids = [c for c in child_order.get(pid, []) if c in keep]
        for idx, cpid in enumerate(kids):
            last = idx == len(kids) - 1
            _emit(
                cpid,
                prefix=child_prefix + ("└─ " if last else "├─ "),
                child_prefix=child_prefix + ("   " if last else "│  "),
            )

    for root in roots:
        _emit(root)
    # Any kept node never reached from a root (cyclic/orphaned data) — show flat.
    for pid in sorted(nodes):
        _emit(pid)

    if len(keep) > len(emitted):
        lines.append(f"  …  ({len(keep)} flagged/anchor processes; output truncated)")
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


# Evidence types that are status/diagnostic markers, not real analysis output.
# A tool whose only items are of these types ran but produced nothing usable
# (e.g. MemProcFS emits a single `memory_analysis_status` item when it cannot
# parse the image), so it must not be credited as having "Analysed" the dump.
_STATUS_EVIDENCE_TYPES = {"memory_analysis_status"}


def _build_evidence_coverage(tools_ran, evidence_items=None):
    # Map each covered evidence type to the tool(s) that actually analysed it,
    # so a type backed by more than one tool (e.g. memory_dump via volatility3
    # and memprocfs) is attributed accurately rather than to a single winner.
    #
    # A tool is only credited as "Analysed" when it produced at least one
    # substantive evidence item. If it emitted only a status/failure marker
    # (e.g. MemProcFS "unavailable" / "mount failure"), it's reported as
    # "ran but produced no artifacts" instead of being listed as a successful
    # analyser — otherwise the report contradicts itself (claims MemProcFS
    # analysed the dump while the evidence shows it was unavailable).
    produced = {}  # tool -> produced at least one non-status item
    for e in (evidence_items or []):
        if not isinstance(e, dict):
            continue
        tool = e.get("source_tool")
        if not tool:
            continue
        substantive = e.get("evidence_type") not in _STATUS_EVIDENCE_TYPES
        produced[tool] = produced.get(tool, False) or substantive

    covered = {}
    for t in tools_ran:
        ev = _TOOL_TO_EVIDENCE.get(t)
        if ev:
            covered.setdefault(ev, []).append(t)
    rows = [
        "| Evidence Type | Status | Forensic Tool | Notes |",
        "|---------------|--------|---------------|-------|",
    ]
    for ev in _ALL_EVIDENCE_TYPES:
        ev_label = ev.replace("_", " ").title()
        tools_for_ev = sorted(set(covered.get(ev, [])))
        # Default True keeps backward-compatible behaviour when evidence_items
        # isn't supplied (every covered tool counts as an analyser).
        analysed  = [t for t in tools_for_ev if produced.get(t, True)]
        attempted = [t for t in tools_for_ev if not produced.get(t, True)]
        if analysed:
            tool_str = ", ".join(analysed)
            note = (
                "-" if not attempted
                else f"{', '.join(attempted)} ran but produced no analysable artifacts."
            )
            rows.append(f"| {ev_label} | Analysed | {tool_str} | {note} |")
        elif attempted:
            tool_str = ", ".join(attempted)
            rows.append(
                f"| {ev_label} | Not analysed | {tool_str} | "
                "Tool ran but could not parse the evidence; no artifacts extracted. |"
            )
        else:
            note = _ACQUIRE_NOTES.get(ev, "Collect evidence to enable analysis.")
            rows.append(
                f"| {ev_label} | Not provided | - | {note} |"
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

    # Evidence↔narrative reconciliation (issue 1.1), attached post-aggregation.
    reconciliation = case_context.get("evidence_reconciliation") or {}

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
    # A "finding" worth its own Key Findings row: elevated severity or a fired
    # IOC match (e.g. a medium ransom-note binary). Bare low-severity anomalies
    # are left to the full evidence file so they don't flood the table. The
    # process_tree aggregate is excluded — it has its own Process Tree section.
    def _is_finding(e):
        if e.get("evidence_type") == "process_tree":
            return False
        if not (e.get("severity") in ("critical", "high")
                or bool(e.get("ioc_match"))):
            return False
        # Drop rows that would render all-dashes: no extractable indicator, no
        # catalog match, and no XAI explanation. These are low-information echoes
        # (e.g. ioc_engine's "Process injection detected") of evidence already
        # shown richer elsewhere; the full set remains in unified_evidence.json.
        has_indicator = bool(_item_indicators(e))
        has_match     = bool(e.get("ioc_match"))
        has_xai       = anomaly_lookup.get(e.get("artifact_id", "")) not in (None, "-")
        return has_indicator or has_match or has_xai
    _seen_findings = set()
    priority_items = []
    for e in sorted(
        (e for e in all_items if _is_finding(e)),
        key=_finding_sort_key,
    ):
        # Collapse exact-duplicate rows (same type + value + severity).
        dk = (e.get("evidence_type"), e.get("value"), e.get("severity"))
        if dk in _seen_findings:
            continue
        _seen_findings.add(dk)
        priority_items.append(e)
    priority_items = priority_items or all_items[:10]
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
    )
    # Surface the evidence-reconciled confidence (issue 1.1) when available.
    if "reconciled_confidence" in reconciliation:
        rc = reconciliation["reconciled_confidence"]
        diverged = reconciliation.get("narrative_evidence_divergence")
        flag = " ⚠ narrative <-> evidence divergence" if diverged else ""
        classification += f"| **Evidence-Reconciled Confidence** | {rc:.0%}{flag} |\n"
    classification += (
        f"| **Case ID** | {case_id} |\n"
        f"| **Generated** | {generated} |"
    )
    # Reconciliation detail (notes) as a short follow-on, when present.
    recon_notes = reconciliation.get("notes") or []
    if recon_notes:
        classification += "\n\n" + "\n".join(f"> {note}" for note in recon_notes)

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
    proc_tree = _build_process_tree(all_items, anomaly_ids, tool_sources)
    process_section = (
        f"## Process Tree\n\n```\n{proc_tree}\n```\n"
        "_Severity shown per process; only flagged processes and the parent chain "
        "that anchors them are listed._"
    )

    # Key Findings — one row per notable evidence item, with its extracted
    # indicators inline (replacing the former separate IOC table) and the XAI
    # explanation. Capped; overflow points to the full evidence file.
    KEY_FINDINGS_CAP = 30
    shown_findings = priority_items[:KEY_FINDINGS_CAP]
    if shown_findings:
        kf_rows = [
            "| Severity | Host | Timestamp | Type | Finding | Indicators / IOC Match | Source · File | Why (XAI) |",
            "|----------|------|-----------|------|---------|------------------------|---------------|-----------|",
        ]
        for item in shown_findings:
            if not isinstance(item, dict):
                continue
            aid      = item.get("artifact_id", "")
            xai_note = _truncate(anomaly_lookup.get(aid, "-"), 80)
            tool     = item.get("source_tool", "-")
            src_file = tool_sources.get(item.get("source_tool", ""), "-")
            src_cell = tool if src_file in ("-", "", None) else f"{tool} · {src_file}"
            kf_rows.append(
                f"| {_md_cell(str(item.get('severity', '-')).upper())} "
                f"| {_md_cell(item.get('machine_id', '-'))} "
                f"| {_md_cell(item.get('timestamp', '-'))} "
                f"| {_md_cell(_finding_type(item.get('evidence_type', '')))} "
                f"| {_md_cell(str(item.get('value', '-'))[:70])} "
                f"| {_indicators_cell(item)} "
                f"| {_md_cell(src_cell)} "
                f"| {_md_cell(xai_note)} |"
            )
        findings_section = "## Key Findings\n\n" + "\n".join(kf_rows)
        overflow = len(priority_items) - len(shown_findings)
        if overflow > 0:
            findings_section += (
                f"\n\n_…and {overflow} additional finding(s) — "
                "see `output/unified_evidence.json` for the full set._"
            )
    else:
        findings_section = (
            "## Key Findings\n\n"
            "_No critical or high-severity findings extracted from evidence._"
        )

    # Indicators of Compromise — brief overview only. The full per-indicator
    # list (with provenance + XAI) is written to output/ioc_report.md.
    iocs = _extract_iocs(all_items)
    if iocs:
        by_type = {}
        for r in iocs:
            by_type[r["type"]] = by_type.get(r["type"], 0) + 1
        type_breakdown = ", ".join(f"{n} {t}" for t, n in sorted(by_type.items()))
        n_critical = sum(1 for r in iocs if r["severity"] == "critical")
        crit_note = f" ({n_critical} critical)" if n_critical else ""
        ioc_section = (
            "## Indicators of Compromise\n\n"
            f"**{len(iocs)}** unique indicator(s) extracted{crit_note} — "
            f"{type_breakdown}.\n\n"
            "_Full indicator detail (severity, context, source file, and "
            "explanation) in `output/ioc_report.md`._"
        )
    else:
        ioc_section = (
            "## Indicators of Compromise\n\n"
            "_No indicators of compromise extracted from evidence._"
        )

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
    coverage_section = "## Evidence Coverage\n\n" + _build_evidence_coverage(tools_ran, all_items)

    # Audit trail
    audit_section = (
        "## Audit Trail\n\n"
        "A SHA-256 audit log was generated at `output/audit_log.json` "
        "and can be used to verify evidence integrity for chain-of-custody compliance."
    )

    sections = [
        cover, exec_summary, classification, findings_section,
        ioc_section, mitre_section, process_section,
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

    # Detailed IOC list (data-derived; written in both mock and live modes).
    try:
        all_items = [e for e in unified_evidence.get("evidence_items", [])
                     if isinstance(e, dict)]
        tool_sources = case_context.get("evidence_sources", {})
        xai = _xai_lookup(shap_explanations, only_anomalies=True)
        anomaly_lookup = {aid: d.get("summary", "-") for aid, d in xai.items()}
        # Effective severity the pipeline assigned per artifact (P5 anomaly /
        # reputation), so a string-swept domain emitted `low` but elevated to
        # High/Critical surfaces in the main IOC table instead of being folded.
        severity_lookup = {}
        for aid, exp in _iter_explanations(shap_explanations):
            sev = str(exp.get("severity", "")).lower()
            if sev in _SEVERITY_RANK:
                severity_lookup[aid] = sev
        ioc_text = _build_ioc_report(all_items, tool_sources, anomaly_lookup,
                                     severity_lookup)
        ioc_path = Path(output_path).parent / "ioc_report.md"
        with open(ioc_path, "w", encoding="utf-8") as f:
            f.write(ioc_text)
        print(f"  [DONE] IOC report written -> {ioc_path}")
    except Exception as exc:
        print(f"  [WARN] IOC report generation failed ({exc})")

    return report_text
