import re


def _slug(text):
    """Stable, filename-safe token from a matched indicator, used to keep
    emitted IOC artifact_ids unique. A single source item (e.g. a process_tree
    text) can match several indicators; without the token suffix every match
    would collapse onto the same `ioc_<kind>_<artifact_id>` id."""
    s = re.sub(r"[^a-z0-9]+", "_", str(text).lower()).strip("_")
    return s or "x"


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


def _dedupe_iocs(iocs):
    """Collapse IOC items reporting the same indicator at the same severity into
    a single item, unioning their `linked_artifacts` (IOC-redundancy).

    The engine emits one item per (source item, matched indicator), so an
    indicator seen in N source items (e.g. `tasksche.exe` ×5, `@WanaDecryptor@`
    ×5) produced N near-identical items differing only by `linked_artifacts`.
    Downstream consumers want one indicator carrying all its source links, so we
    keep the first item per (value, severity) and merge the rest's links into it.
    """
    merged = {}
    order = []
    for ioc in iocs:
        key = (ioc.get("value", ""), ioc.get("severity", ""))
        if key not in merged:
            canonical = dict(ioc)
            canonical["linked_artifacts"] = list(ioc.get("linked_artifacts", []))
            merged[key] = canonical
            order.append(key)
        else:
            existing = merged[key]["linked_artifacts"]
            for link in ioc.get("linked_artifacts", []):
                if link not in existing:
                    existing.append(link)
    return [merged[key] for key in order]


def extract_iocs(evidence_items):

    iocs = []

    for item in evidence_items:

        evidence_type = item.get("evidence_type", "")

        # Skip the process_tree aggregate: it's a summary blob of processes that
        # are already scored individually (per-PID `process` items) and as
        # lineage (`process_relation` items). Scanning it re-derives the same
        # IOCs from one item, producing duplicate / colliding artifact_ids
        # (cf. issue 4.4 — process vs process_tree double-scoring).
        if evidence_type == "process_tree":
            continue

        value = str(item.get("value", "")).lower()

        artifact_id = item.get("artifact_id", "")

        severity = "medium"

        confidence = 0.75

        # ---------------------------------------------------
        # Suspicious Processes
        # ---------------------------------------------------

        for proc in SUSPICIOUS_PROCESSES:

            if proc.lower() in value:

                iocs.append({
                    "artifact_id": f"ioc_proc_{artifact_id}_{_slug(proc)}",
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
                    "artifact_id": f"ioc_keyword_{artifact_id}_{_slug(keyword)}",
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
                    "artifact_id": f"ioc_dll_{artifact_id}_{_slug(dll_path)}",
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
                    "artifact_id": f"ioc_relation_{artifact_id}_{_slug(parent)}_{_slug(child)}",
                    "source_tool": "ioc_engine",
                    "evidence_type": "ioc",
                    "timestamp": "",
                    "value": f"Suspicious lineage detected: {parent} -> {child}",
                    "severity": "critical",
                    "confidence": 0.96,
                    "linked_artifacts": [artifact_id]
                })

    return _dedupe_iocs(iocs)
