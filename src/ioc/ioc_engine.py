import re


def _slug(text):
    """Stable, filename-safe token from a matched indicator, used to keep
    emitted IOC artifact_ids unique. A single source item (e.g. a process_tree
    text) can match several indicators; without the token suffix every match
    would collapse onto the same `ioc_<kind>_<artifact_id>` id."""
    s = re.sub(r"[^a-z0-9]+", "_", str(text).lower()).strip("_")
    return s or "x"


# Process names suspicious on their name alone. cmd.exe / powershell.exe are
# deliberately NOT here (B-5): they are living-off-the-land binaries that run
# constantly on a healthy host, so a bare-name match is a false positive (e.g.
# the Kibana launcher cmd.exe). Their malicious use carries context this engine
# already scores separately — the `powershell -enc` keyword and the
# `explorer.exe -> powershell.exe` relation rule — so no detection is lost.
SUSPICIOUS_PROCESSES = [
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


def _emit(artifact_id, value, severity, confidence, source_id):
    """Build one evidence-schema IOC item linked back to its source artifact."""
    return {
        "artifact_id": artifact_id,
        "source_tool": "ioc_engine",
        "evidence_type": "ioc",
        "timestamp": "",
        "value": value,
        "severity": severity,
        "confidence": confidence,
        "linked_artifacts": [source_id],
    }


# Substring-match indicator rules: scan an item's (lowercased) value for any
# catalog term, emitting one IOC per match. Adding an indicator class is a
# one-line table edit. (id_prefix, terms, message_template, severity, confidence)
_SUBSTRING_RULES = [
    ("ioc_proc",    SUSPICIOUS_PROCESSES,  "Suspicious process detected: {term}", "high",     0.90),
    ("ioc_keyword", SUSPICIOUS_KEYWORDS,   "Malware indicator detected: {term}",  "critical", 0.95),
    ("ioc_dll",     SUSPICIOUS_DLL_PATHS,  "Suspicious DLL path detected: {term}", "high",     0.85),
]


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

        # Substring catalogs (processes / keywords / dll paths).
        for prefix, terms, template, severity, confidence in _SUBSTRING_RULES:
            for term in terms:
                if term.lower() in value:
                    iocs.append(_emit(
                        f"{prefix}_{artifact_id}_{_slug(term)}",
                        template.format(term=term),
                        severity, confidence, artifact_id,
                    ))

        # Injected code is an evidence-type signal, not a substring match.
        if evidence_type == "injected_code":
            iocs.append(_emit(
                f"ioc_injection_{artifact_id}",
                "Process injection detected", "critical", 0.97, artifact_id,
            ))

        # Suspicious parent->child lineage (two-part term, two-slug id).
        for parent, child in SUSPICIOUS_RELATIONS:
            if f"{parent.lower()} -> {child.lower()}" in value:
                iocs.append(_emit(
                    f"ioc_relation_{artifact_id}_{_slug(parent)}_{_slug(child)}",
                    f"Suspicious lineage detected: {parent} -> {child}",
                    "critical", 0.96, artifact_id,
                ))

    return _dedupe_iocs(iocs)
