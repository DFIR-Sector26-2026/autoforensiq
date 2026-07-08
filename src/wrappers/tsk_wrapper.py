import os
import re
import json
import hashlib
import tempfile
from src.wrappers.base_wrapper import BaseWrapper
from src.data.threat_intel import RANSOM_EXTENSIONS, EXECUTABLE_EXTENSIONS


def _path_id(prefix: str, *parts: str) -> str:
    """Stable artifact_id from the file path (+ optional timestamp), md5 slice. The old
    abs(hash())%99999 collided distinct files (silently dropped by the aggregator's dedup: 68,690
    -> 49,738 on dev01) and changed every run."""
    digest = hashlib.md5("|".join(parts).encode("utf-8", "replace")).hexdigest()
    return f"{prefix}_{digest[:16]}"


# EXECUTABLE_EXTENSIONS are notable only inside a staging dir (or deleted) — extension alone flooded
# a real disk with ~65k benign binaries. RANSOM_EXTENSIONS flag anywhere. Both centralised in
# threat_intel.

# User-writable staging dirs, matched as /-delimited path segments (TSK emits '/' even for NTFS) so
# a file merely *named* like a temp file isn't flagged (B6).
STAGING_DIRS = (
    "/temp/", "/tmp/", "/appdata/", "/downloads/", "/users/public/",
    "/programdata/", "/$recycle", "/perflogs/",
)


# OS-managed servicing dirs whose "/temp/" segments are NOT user-writable staging (GAC ngen cache +
# WinSxS servicing — 140 of 141 dev01 staging flags, B-9c).
_OS_SERVICING_DIRS = ("/windows/assembly/", "/windows/winsxs/")


def _in_staging_dir(lower_path: str) -> bool:
    if any(seg in lower_path for seg in _OS_SERVICING_DIRS):
        return False
    return any(seg in lower_path for seg in STAGING_DIRS)


def _file_signal(filepath: str):
    """Return (severity, label) if the path is a notable file artifact by extension + location,
    else None. Payload/encrypted extensions count anywhere; executable/script extensions count
    only inside a staging directory. Deleted- file handling stays in the caller (it needs the fls
    deletion flag)."""
    lower = filepath.lower()
    base = lower.rsplit("/", 1)[-1]
    if base.endswith(RANSOM_EXTENSIONS):
        return "high", "Payload/encrypted file"
    if base.endswith(EXECUTABLE_EXTENSIONS) and _in_staging_dir(lower):
        return "medium", "Executable in staging directory"
    # PowerShell transcripts: deliberately LOW — GPO transcription is often fleet-wide, so existence
    # alone is weak; correlation is the lift. Scoring by filename/location would flood or overfit to
    # one image (B-6/B-7, N5).
    if base.startswith("powershell_transcript.") and base.endswith(".txt"):
        return "low", "PowerShell transcript"
    return None


class TSKWrapper(BaseWrapper):
    consumes = "disk_image"

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
        """Sector offsets of candidate filesystems via `mmls`; [] = no partition table, caller
        runs fls with no -o. Without offsets, fls on a partitioned disk yields 0 items ("Cannot
        determine file system type", D2)."""
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

            # Skip the partition-table meta row and unallocated gaps; everything else is a candidate
            # (fls is tolerant — unreadable/foreign slots simply produce no output and are skipped
            # below).
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
                # Field 3 is the type/mode string; skip directory nodes ("d/...") — the signal is
                # the files inside, on their own rows (B3).
                mode = parts[3].strip() if len(parts) > 3 else ""
                if mode.startswith("d/"):
                    continue
                is_deleted = line.startswith("r/r *") or "* " in parts[0]

                if is_deleted:
                    severity, label = "high", "DELETED file"
                else:
                    signal = _file_signal(filepath)
                    if not signal:
                        continue
                    severity, label = signal

                items.append(self.make_evidence_item(
                    artifact_id=_path_id("file", filepath),
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

                signal = _file_signal(filepath)
                if signal:
                    # Timeline events for high/medium file signals stay medium (historical
                    # behavior); a low signal (transcripts) must not be elevated by appearing in the
                    # timeline.
                    items.append(self.make_evidence_item(
                        artifact_id=_path_id("timeline", filepath, timestamp),
                        evidence_type="timeline_event",
                        value=f"[{timestamp}] {activity} → {filepath}",
                        severity="low" if signal[0] == "low" else "medium",
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
