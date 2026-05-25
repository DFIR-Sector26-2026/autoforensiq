SUSPICIOUS_PROCESSES = [
    "powershell.exe",
    "cmd.exe",
    "rundll32.exe",
    "wscript.exe",
    "cscript.exe",
    "tasksche.exe",
    "@WanaDecryptor@"
]

SUSPICIOUS_KEYWORDS = [
    "mimikatz",
    "meterpreter",
    "wannacry",
    "cobaltstrike",
    "powershell -enc",
    "vssadmin delete shadows",
    "wmic",
]

SUSPICIOUS_DLL_PATHS = [
    "temp",
    "appdata",
]

SUSPICIOUS_RELATIONS = [
    ("explorer.exe", "powershell.exe"),
    ("tasksche.exe", "@WanaDecryptor@"),
]


def extract_iocs(evidence_items):

    iocs = []

    for item in evidence_items:

        value = str(item.get("value", "")).lower()

        evidence_type = item.get("evidence_type", "")

        artifact_id = item.get("artifact_id", "")

        severity = "medium"

        confidence = 0.75

        # ---------------------------------------------------
        # Suspicious Processes
        # ---------------------------------------------------

        for proc in SUSPICIOUS_PROCESSES:

            if proc.lower() in value:

                iocs.append({
                    "artifact_id": f"ioc_proc_{artifact_id}",
                    "source_tool": "ioc_engine",
                    "evidence_type": "ioc",
                    "timestamp": "",
                    "value": f"Suspicious process detected: {proc}",
                    "severity": "high",
                    "confidence": 0.90,
                    "linked_artifacts": [artifact_id]
                })

        # ---------------------------------------------------
        # Malware Keywords
        # ---------------------------------------------------

        for keyword in SUSPICIOUS_KEYWORDS:

            if keyword.lower() in value:

                iocs.append({
                    "artifact_id": f"ioc_keyword_{artifact_id}",
                    "source_tool": "ioc_engine",
                    "evidence_type": "ioc",
                    "timestamp": "",
                    "value": f"Malware indicator detected: {keyword}",
                    "severity": "critical",
                    "confidence": 0.95,
                    "linked_artifacts": [artifact_id]
                })

        # ---------------------------------------------------
        # Injected Code
        # ---------------------------------------------------

        if evidence_type == "injected_code":

            iocs.append({
                "artifact_id": f"ioc_injection_{artifact_id}",
                "source_tool": "ioc_engine",
                "evidence_type": "ioc",
                "timestamp": "",
                "value": "Process injection detected",
                "severity": "critical",
                "confidence": 0.97,
                "linked_artifacts": [artifact_id]
            })

        # ---------------------------------------------------
        # Suspicious DLL Paths
        # ---------------------------------------------------

        for dll_path in SUSPICIOUS_DLL_PATHS:

            if dll_path in value:

                iocs.append({
                    "artifact_id": f"ioc_dll_{artifact_id}",
                    "source_tool": "ioc_engine",
                    "evidence_type": "ioc",
                    "timestamp": "",
                    "value": f"Suspicious DLL path detected: {dll_path}",
                    "severity": "high",
                    "confidence": 0.85,
                    "linked_artifacts": [artifact_id]
                })

        # ---------------------------------------------------
        # Suspicious Parent-Child Relationships
        # ---------------------------------------------------

        for parent, child in SUSPICIOUS_RELATIONS:

            relation_string = f"{parent.lower()} -> {child.lower()}"

            if relation_string in value:

                iocs.append({
                    "artifact_id": f"ioc_relation_{artifact_id}",
                    "source_tool": "ioc_engine",
                    "evidence_type": "ioc",
                    "timestamp": "",
                    "value": f"Suspicious lineage detected: {parent} -> {child}",
                    "severity": "critical",
                    "confidence": 0.96,
                    "linked_artifacts": [artifact_id]
                })

    return iocs
