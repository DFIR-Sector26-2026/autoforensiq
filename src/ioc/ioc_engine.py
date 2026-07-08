import re


def _slug(text):
    """Filename-safe token from a matched indicator — one source item can match several
    indicators, and without the suffix their ids would collide."""
    s = re.sub(r"[^a-z0-9]+", "_", str(text).lower()).strip("_")
    return s or "x"


# Process names suspicious on their name alone. cmd.exe / powershell.exe are deliberately NOT here
# (B-5): bare LOLBin names FP on healthy hosts; their malicious use is covered by the `powershell
# -enc` keyword + relation rule.
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
    """Collapse items with the same (value, severity) into one, unioning their linked_artifacts —
    the engine emits one item per (source, indicator), so an indicator seen N times produced N
    near-identical items."""
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


# Substring-match indicator rules: scan an item's (lowercased) value for any catalog term, emitting
# one IOC per match. Adding an indicator class is a one-line table edit. (id_prefix, terms,
# message_template, severity, confidence)
_SUBSTRING_RULES = [
    ("ioc_proc",    SUSPICIOUS_PROCESSES,  "Suspicious process detected: {term}", "high",     0.90),
    ("ioc_keyword", SUSPICIOUS_KEYWORDS,   "Malware indicator detected: {term}",  "critical", 0.95),
    # medium, not high (B-9c): a DLL under temp/appdata is a lead, not a finding — browsers and
    # updaters legitimately keep DLLs there (Edge components under AppData\Local). Catalog-named
    # malware still escalates via the rescorer.
    ("ioc_dll",     SUSPICIOUS_DLL_PATHS,  "Suspicious DLL path detected: {term}", "medium",   0.85),
]


def extract_iocs(evidence_items):

    iocs = []

    for item in evidence_items:

        evidence_type = item.get("evidence_type", "")

        # Skip process_tree (its processes are already scored per-PID and as relations — rescanning
        # duplicates ids, 4.4) and suspicious_domain (the catalogs FP inside memory-scraped domain
        # blobs, e.g. "mimikatz" in "invoke-mimikatz.ps1tinyurl.com"; domains are scored by the
        # rescorer).
        if evidence_type in ("process_tree", "suspicious_domain"):
            continue

        value = str(item.get("value", "")).lower()
        artifact_id = item.get("artifact_id", "")

        # Substring catalogs (processes / keywords / dll paths).
        for prefix, terms, template, severity, confidence in _SUBSTRING_RULES:
            # The DLL rule needs an actual .dll — without it, "temp"/"appdata" matched hundreds of
            # benign caches/logs/configs.
            if prefix == "ioc_dll" and ".dll" not in value:
                continue
            for term in terms:
                if term.lower() in value:
                    iocs.append(_emit(
                        f"{prefix}_{artifact_id}_{_slug(term)}",
                        template.format(term=term),
                        severity, confidence, artifact_id,
                    ))

        # Injected code inherits the wrapper's graded severity — malfind already distinguishes
        # RWX+PE from bare RWX and down-ranks JIT/AV hosts; a blanket critical re-escalated
        # Defender's benign RWX region.
        if evidence_type == "injected_code":
            iocs.append(_emit(
                f"ioc_injection_{artifact_id}",
                "Process injection detected",
                str(item.get("severity", "high")).lower(),
                float(item.get("confidence") or 0.9), artifact_id,
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
