import hashlib
import json
import os
from datetime import datetime, timezone

AUDIT_LOG_PATH = "output/audit_log.jsonl"

# Hash cache keyed by (path, size, mtime) — the evidence image was re-hashed for every plugin
# subprocess (review 4.1). Chain-of-custody holds: each distinct file state is hashed once.
_HASH_CACHE: dict = {}

def sha256_file(filepath: str) -> str:
    if not os.path.exists(filepath):
        return "file_not_found"
    st = os.stat(filepath)
    key = (os.path.abspath(filepath), st.st_size, st.st_mtime_ns)
    if key not in _HASH_CACHE:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        _HASH_CACHE[key] = h.hexdigest()
    return _HASH_CACHE[key]

def log_action(tool_name: str, command: list, input_files: list,
               output_files: list, status: str, error: str = ""):
    os.makedirs("output", exist_ok=True)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tool": tool_name,
        "command": " ".join(command),
        "status": status,
        "error": error,
        "input_hashes": {f: sha256_file(f) for f in input_files},
        "output_hashes": {f: sha256_file(f) for f in output_files}
    }

    # JSONL append: the old read-whole-array-and-rewrite made every log O(file) and could lose the
    # chain-of-custody file on a mid-write crash (review-2 F6).
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")

    print(f"  [AUDIT] {tool_name} → {status}")
