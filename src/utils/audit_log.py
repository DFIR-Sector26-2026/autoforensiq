import hashlib
import json
import os
from datetime import datetime, timezone

AUDIT_LOG_PATH = "output/audit_log.json"

def sha256_file(filepath: str) -> str:
    if not os.path.exists(filepath):
        return "file_not_found"
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

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

    existing = []
    if os.path.exists(AUDIT_LOG_PATH):
        with open(AUDIT_LOG_PATH, "r") as f:
            try:
                existing = json.load(f)
            except json.JSONDecodeError:
                existing = []

    existing.append(entry)

    with open(AUDIT_LOG_PATH, "w") as f:
        json.dump(existing, f, indent=2)

    print(f"  [AUDIT] {tool_name} → {status}")
