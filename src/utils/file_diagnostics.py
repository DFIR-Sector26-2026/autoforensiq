"""Pre-flight sanity checks run on each evidence file just before its wrapper is invoked.

A wrapper that gets nothing back from a bad file (empty, wrong format, truncated) currently just
returns [] silently - the orchestrator moves on with no record of *why*. This gives every evidence
type a cheap, tool-independent check (file size, format magic bytes) so a bad file is diagnosed up
front instead of just vanishing into "0 items" with no explanation.
"""

import os

# (magic bytes, offset) alternatives that identify a valid file of this format. A format with no
# reliable universal magic (raw memory dumps, raw .img/.dd disk images) is size-checked only.
_MAGIC_SIGNATURES = {
    "pcap": [
        (b"\xd4\xc3\xb2\xa1", 0),  # classic pcap, little-endian
        (b"\xa1\xb2\xc3\xd4", 0),  # classic pcap, big-endian
        (b"\x0a\x0d\x0d\x0a", 0),  # pcapng block type
    ],
    "registry_hive": [
        (b"regf", 0),
    ],
    "disk_image": [
        (b"EVF\x09\x0d\x0a\xff\x00", 0),  # EWF/E01 - only signature-checked format among disk images
    ],
}

# Minimum plausible size per evidence type for formats with no reliable magic bytes to check
# instead (raw memory/disk acquisitions have no fixed header). Real captures of these types run
# from tens of MB up; anything under this is almost certainly a placeholder or truncated transfer.
_MIN_PLAUSIBLE_SIZE = {
    "memory_dump": 1_000_000,
    "disk_image": 1_000_000,
}


def diagnose_evidence_file(path: str, evidence_key: str) -> str | None:
    """Returns a human-readable diagnosis if `path` looks unusable for `evidence_key`, else None.
    Assumes the caller has already confirmed the file exists."""
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return f"Could not read this file to check it: {e}"

    if size == 0:
        return "This file is empty (0 bytes) — it contains no data to analyse."

    signatures = _MAGIC_SIGNATURES.get(evidence_key)
    if signatures:
        try:
            with open(path, "rb") as f:
                header = f.read(16)
        except OSError as e:
            return f"Could not read this file to check it: {e}"
        if not any(header[offset:offset + len(magic)] == magic
                   for magic, offset in signatures):
            label = evidence_key.replace("_", " ")
            return (f"This file does not have a valid {label} header — it may be the "
                    "wrong file, renamed, or corrupted.")

    min_size = _MIN_PLAUSIBLE_SIZE.get(evidence_key)
    if min_size and size < min_size:
        label = evidence_key.replace("_", " ")
        return (f"This file is only {size:,} bytes — too small to be a real {label} "
                f"(expected at least ~{min_size // 1_000_000}MB). Likely a placeholder "
                "or an incomplete transfer.")

    return None
