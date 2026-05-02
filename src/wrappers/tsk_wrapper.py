import os
import json
import tempfile
from src.wrappers.base_wrapper import BaseWrapper

SUSPICIOUS_EXTENSIONS = [".exe", ".dll", ".bat", ".ps1", ".vbs",
                          ".js", ".jar", ".scr", ".locked", ".encrypted"]
SUSPICIOUS_DIRS = ["temp", "tmp", "appdata\\roaming", "recycle",
                   "programdata", "windows\\temp"]

class TSKWrapper(BaseWrapper):
    def __init__(self):
        super().__init__("tsk_fls")

    def run(self, image_path: str) -> list:
        if not os.path.exists(image_path):
            print(f"  [ERROR] Disk image not found: {image_path}")
            return []

        all_items = []
        all_items.extend(self._run_fls(image_path))
        all_items.extend(self._run_mactime(image_path))
        return all_items

    def _run_fls(self, image_path: str) -> list:
        print("  [TSK] Running fls (file listing)...")
        stdout, _, code = self.run_command(
            ["fls", "-r", "-m", "/", image_path],
            input_files=[image_path],
            timeout=180
        )

        items = []
        if code != 0 or not stdout.strip():
            print("  [TSK] fls produced no output")
            return items

        for line in stdout.strip().splitlines():
            parts = line.split("|")
            if len(parts) < 2:
                continue
            try:
                filepath = parts[1].strip() if len(parts) > 1 else line
                is_deleted = line.startswith("r/r *") or "* " in parts[0]
                lower_path = filepath.lower()

                suspicious = (
                    any(filepath.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS) or
                    any(d in lower_path for d in SUSPICIOUS_DIRS) or
                    is_deleted
                )

                if suspicious:
                    severity = "high" if is_deleted else "medium"
                    label = "DELETED file" if is_deleted else "Suspicious file"
                    items.append(self.make_evidence_item(
                        artifact_id=f"file_{abs(hash(filepath)) % 99999}",
                        evidence_type="file_artifact",
                        value=f"{label}: {filepath}",
                        severity=severity,
                        confidence=0.75
                    ))
            except Exception:
                continue

        print(f"  [TSK] fls → {len(items)} suspicious file items")
        return items

    def _run_mactime(self, image_path: str) -> list:
        print("  [TSK] Running mactime (timeline)...")

        # step 1: fls output to temp file for mactime
        fls_stdout, _, code = self.run_command(
            ["fls", "-r", "-m", "/", image_path],
            input_files=[image_path],
            timeout=180
        )

        if code != 0 or not fls_stdout.strip():
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".fls",
                                         delete=False) as tmp:
            tmp.write(fls_stdout)
            tmp_path = tmp.name

        # step 2: run mactime on the fls output
        stdout, _, code = self.run_command(
            ["mactime", "-b", tmp_path, "-d"],
            input_files=[tmp_path],
            timeout=60
        )
        os.unlink(tmp_path)

        items = []
        if code != 0 or not stdout.strip():
            return items

        for line in stdout.strip().splitlines()[1:]:  # skip header
            parts = line.split(",")
            if len(parts) < 6:
                continue
            try:
                timestamp = parts[0].strip()
                filepath  = parts[3].strip() if len(parts) > 3 else ""
                activity  = parts[2].strip() if len(parts) > 2 else ""
                lower = filepath.lower()

                if any(filepath.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS) or \
                   any(d in lower for d in SUSPICIOUS_DIRS):
                    items.append(self.make_evidence_item(
                        artifact_id=f"timeline_{abs(hash(filepath+timestamp)) % 99999}",
                        evidence_type="timeline_event",
                        value=f"[{timestamp}] {activity} → {filepath}",
                        severity="medium",
                        confidence=0.70,
                        timestamp=timestamp
                    ))
            except Exception:
                continue

        print(f"  [TSK] mactime → {len(items)} timeline items")
        return items


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 2:
        print("Usage: python -m src.wrappers.tsk_wrapper <disk.img>")
        sys.exit(1)
    wrapper = TSKWrapper()
    items = wrapper.run(sys.argv[1])
    output = {"tool": "tsk", "items": items}
    os.makedirs("output/raw", exist_ok=True)
    with open("output/raw/tsk_output.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n[DONE] {len(items)} evidence items saved to output/raw/tsk_output.json")
