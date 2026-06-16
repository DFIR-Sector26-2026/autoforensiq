import os
import re
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

        fls_output, fls_items = self._run_fls(image_path)
        all_items = list(fls_items)
        all_items.extend(self._run_mactime(fls_output))
        return all_items

    def _enumerate_fs_offsets(self, image_path: str) -> list:
        """Return the sector offsets of candidate filesystems in a partitioned
        image, via `mmls`. An empty list means there is no partition table
        (a bare filesystem) — the caller then runs `fls` with no `-o`.

        Without this, `fls -r -m /` is given a partitioned disk and reports
        "Cannot determine file system type", yielding 0 items (issue D2). The
        Windows Server E01 keeps its NTFS at sector 2048; only the Ubuntu casper
        image is a bare filesystem at offset 0.
        """
        stdout, _, code = self.run_command(
            ["mmls", image_path],
            input_files=[image_path],
            timeout=60
        )

        # mmls exits non-zero / empty when there is no partition table.
        if code != 0 or not stdout.strip():
            return []

        offsets = []
        for line in stdout.splitlines():
            # Data rows look like:
            #   002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)
            m = re.match(
                r"^\d{3}:\s+(\S+)\s+(\d+)\s+\d+\s+\d+\s+(.*)$",
                line.strip()
            )
            if not m:
                continue

            slot, start, desc = m.group(1), m.group(2), m.group(3).strip().lower()

            # Skip the partition-table meta row and unallocated gaps; everything
            # else is a candidate (fls is tolerant — unreadable/foreign slots
            # simply produce no output and are skipped below).
            if slot == "Meta" or "unallocated" in desc:
                continue

            offsets.append(int(start))

        return offsets

    def _parse_fls_lines(self, fls_output: str) -> list:
        """Parse mactime-body output from a single `fls` run into evidence."""
        items = []
        for line in fls_output.strip().splitlines():
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
        return items

    def _run_fls(self, image_path: str) -> tuple:
        print("  [TSK] Running fls (file listing)...")

        offsets = self._enumerate_fs_offsets(image_path)
        combined_output = ""
        items = []

        if offsets:
            print(
                f"  [TSK] mmls found {len(offsets)} filesystem(s) at "
                f"sector offset(s): {offsets}"
            )
            for off in offsets:
                stdout, _, code = self.run_command(
                    ["fls", "-o", str(off), "-r", "-m", "/", image_path],
                    input_files=[image_path],
                    timeout=180
                )
                if code != 0 or not stdout.strip():
                    print(f"  [TSK] fls @offset {off} → no output (skipped)")
                    continue
                combined_output += ("\n" if combined_output else "") + stdout
                part_items = self._parse_fls_lines(stdout)
                items.extend(part_items)
                print(
                    f"  [TSK] fls @offset {off} → "
                    f"{len(part_items)} suspicious file items"
                )
        else:
            # No partition table — bare filesystem; run fls at offset 0.
            print("  [TSK] No partition table; running fls on bare filesystem")
            stdout, _, code = self.run_command(
                ["fls", "-r", "-m", "/", image_path],
                input_files=[image_path],
                timeout=180
            )
            if code == 0 and stdout.strip():
                combined_output = stdout
                items = self._parse_fls_lines(stdout)

        if not combined_output.strip():
            print("  [TSK] fls produced no output")
            return "", items

        print(f"  [TSK] fls → {len(items)} suspicious file items")
        return combined_output, items

    def _run_mactime(self, fls_output: str) -> list:
        print("  [TSK] Running mactime (timeline)...")

        if not fls_output:
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".fls",
                                         delete=False) as tmp:
            tmp.write(fls_output)
            tmp_path = tmp.name

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
    import sys
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
