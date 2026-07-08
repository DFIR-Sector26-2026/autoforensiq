"""Converts both baseline_normal.json and unified_evidence.json records into a
COMMON, fixed-width numeric feature vector.

Feature vector layout (14 dimensions):
  [0]  is_system_process      – known Windows system binary
  [1]  is_suspicious_process  – known malware/LOLBin name
  [2]  suspicious_parent      – parent is cmd/powershell/wscript etc.
  [3]  port_is_nonstandard    – port not in {80,443,0}
  [4]  port_is_known_c2       – port in common C2 list {4444,1337,8888,9999,...}
  [5]  has_network            – boolean
  [6]  evidence_is_file       – evidence_type == "file"
  [7]  evidence_is_network    – evidence_type == "network"
  [8]  evidence_is_email      – evidence_type == "email"
  [9]  path_in_temp           – value contains Temp/AppData/Roaming path
  [10] path_has_exe_in_temp   – .exe dropped in Temp/Downloads
  [11] keyword_c2_indicator   – value has C2/shell/beacon/reverse keywords
  [12] keyword_exfil          – value has exfil/upload/POST/data keywords
  [13] severity_score         – critical=1.0, high=0.75, medium=0.5, low=0.25, none=0.0
"""

import re
from typing import Dict, Any, List

# Known C2 ports come from the shared catalog (issue D1) so the ML "known C2 port" feature can never
# drift from what the wrappers/rescorer flag.
from src.data.threat_intel import C2_PORTS_ALL as KNOWN_C2_PORTS

# ── Threat intelligence lists ─────────────────────────────────────────────────

SUSPICIOUS_PROCESSES = {
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe", "psexec.exe", "nc.exe", "ncat.exe",
    "mimikatz.exe", "procdump.exe", "meterpreter", "beacon.exe",
    "malware.exe", "payload.exe", "shell.exe", "rat.exe",
}

SYSTEM_PROCESSES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe",
    "services.exe", "winlogon.exe", "explorer.exe", "taskhostw.exe",
    "spoolsv.exe", "dwm.exe", "system", "registry",
}

SUSPICIOUS_PARENTS = {
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "python.exe", "python3", "bash", "sh",
}

STANDARD_PORTS = {80, 443, 0, 8080, 8443, 53, 22, 21, 25}

SEVERITY_MAP = {
    "critical": 1.0,
    "high":     0.75,
    "medium":   0.50,
    "low":      0.25,
    "none":     0.0,
    "":         0.0,
}

C2_KEYWORDS = re.compile(
    r"\b(c2|command.and.control|beacon|reverse.shell|meterpreter|"
    r"connect.back|bind.shell|netcat|nc\.exe|4444|1337|8888|"
    r"payload|dropper|implant|rat\b|exeshell)", re.I
)

EXFIL_KEYWORDS = re.compile(
    r"\b(exfil|upload|exfiltrat|data.sent|POST|curl|wget|"
    r"ftp|sftp|transfer|smuggl|tunnel|dns.query)", re.I
)

TEMP_PATH = re.compile(
    r"(AppData[\\\/](?:Roaming|Local|Temp)|"
    r"[\\\/]Temp[\\\/]|[\\\/]tmp[\\\/]|"
    r"Downloads[\\\/]|ProgramData[\\\/])", re.I
)

EXE_IN_TEMP = re.compile(
    r"(Temp|AppData|Downloads|tmp)[\\\/\w]*\.exe", re.I
)


def _canonical_evidence_type(evidence_type: str) -> str:
    evidence_type = evidence_type.lower()

    if (
        "network" in evidence_type
        or "connection" in evidence_type
        or "pcap" in evidence_type
    ):
        return "network"

    if (
        "email" in evidence_type
        or "phishing" in evidence_type
    ):
        return "email"

    if (
        "file" in evidence_type
        or "disk" in evidence_type
    ):
        return "file"

    return evidence_type


def _record_value(record: Dict[str, Any]) -> str:
    """Prefer P4's normalized text for ML features, then fall back to display/raw values for
    older evidence items."""
    return str(
        record.get("normalized_value")
        or record.get("value")
        or record.get("raw_value")
        or ""
    )


# ── Core extractor ────────────────────────────────────────────────────────────

def extract_features(record: Dict[str, Any]) -> List[float]:
    """Accept either a baseline record or a unified-evidence record. Always returns a 14-element
    list of floats in [0, 1]."""

    # ── Pull raw fields, tolerating missing keys ──────────────────────────────
    evidence_type = _canonical_evidence_type(
        str(record.get("evidence_type", ""))
    )
    value         = _record_value(record)
    severity_raw  = str(record.get("severity", "")).lower()

    # Baseline fields
    process_name   = str(record.get("process_name", "")).lower()
    parent_process = str(record.get("parent_process", "")).lower()
    port           = int(record.get("port", 0))
    has_network    = bool(record.get("has_network", False))

    # ── Derive process / parent from value text when evidence record ──────────
    # e.g. "svchost.exe spawned by cmd.exe" → process=svchost, parent=cmd
    if not process_name and value:
        spawned_match = re.search(
            r"([\w\-]+\.exe)\s+(?:spawned|launched|executed)\s+by\s+([\w\-]+\.exe)",
            value, re.I
        )
        if spawned_match:
            process_name   = spawned_match.group(1).lower()
            parent_process = spawned_match.group(2).lower()
        else:
            # fallback: first .exe mentioned
            exe_match = re.findall(r"[\w\-]+\.exe", value, re.I)
            if exe_match:
                process_name = exe_match[0].lower()

    # ── Derive port only from network evidence with an IP:PORT pattern ───────
    # Avoid treating non-network fields like "(PID:596)" as port observations.
    if port == 0 and value and evidence_type == "network":
        port_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}:(\d{2,5})\b", value)
        if port_match:
            port = int(port_match.group(1))

    # ── Compute individual features ───────────────────────────────────────────
    f0  = 1.0 if process_name in SYSTEM_PROCESSES else 0.0
    f1  = 1.0 if process_name in SUSPICIOUS_PROCESSES else 0.0
    f2  = 1.0 if parent_process in SUSPICIOUS_PARENTS else 0.0
    f3  = 0.0 if port in STANDARD_PORTS else (1.0 if port > 0 else 0.0)
    f4  = 1.0 if port in KNOWN_C2_PORTS else 0.0
    f5  = 1.0 if has_network or evidence_type == "network" else 0.0
    f6  = 1.0 if evidence_type == "file" else 0.0
    f7  = 1.0 if evidence_type == "network" else 0.0
    f8  = 1.0 if evidence_type == "email" else 0.0
    f9  = 1.0 if TEMP_PATH.search(value) else 0.0
    f10 = 1.0 if EXE_IN_TEMP.search(value) else 0.0
    f11 = 1.0 if C2_KEYWORDS.search(value) else 0.0
    f12 = 1.0 if EXFIL_KEYWORDS.search(value) else 0.0
    f13 = SEVERITY_MAP.get(severity_raw, 0.0)

    return [f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13]


FEATURE_NAMES = [
    "is_system_process",
    "is_suspicious_process",
    "suspicious_parent",
    "port_is_nonstandard",
    "port_is_known_c2",
    "has_network",
    "evidence_is_file",
    "evidence_is_network",
    "evidence_is_email",
    "path_in_temp",
    "path_has_exe_in_temp",
    "keyword_c2_indicator",
    "keyword_exfil",
    "severity_score",
]


def extract_feature_matrix(records: List[Dict[str, Any]]):
    """Return (matrix, feature_names) ready for sklearn."""
    import numpy as np
    matrix = np.array([extract_features(r) for r in records], dtype=float)
    return matrix, FEATURE_NAMES
