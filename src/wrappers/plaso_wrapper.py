import os
import sys
import json
import shutil
import tempfile
import csv
from pathlib import Path
from src.wrappers.base_wrapper import BaseWrapper, stable_artifact_id


def _resolve_cmd(preferred: str, fallback: str) -> str:
    """Resolve a plaso console script (log2timeline.py / psort.py).

    venv/bin isn't on PATH under `venv/bin/python autoforensiq.py` (D1), so check
    the interpreter's own bin dir first, then PATH, then the bare name."""
    venv_bin = os.path.dirname(sys.executable)
    for name in (preferred, fallback):
        candidate = os.path.join(venv_bin, name)
        if os.path.exists(candidate):
            return candidate
    return shutil.which(preferred) or shutil.which(fallback) or fallback


LOG2TIMELINE = _resolve_cmd("log2timeline.py", "log2timeline")
PSORT        = _resolve_cmd("psort.py",        "psort")

SUSPICIOUS_SOURCES = [
    "run key",
    "startup",
    "scheduled task",
    "autorun",
    "powershell",
    "cmd.exe",
    "encoded",
    "download"
]

# Non-matching rows are sampled at low severity so benign-image runs give the baseline harvester timeline material
ROUTINE_SAMPLE_CAP = 150

class PlasoWrapper(BaseWrapper):
    # The orchestrator feeds plaso the disk image; display layers formerly mislabelled it log_files
    # (D2).
    consumes = "disk_image"

    def __init__(self):
        super().__init__("plaso")

    def run(self, source_path: str) -> list:
        if not os.path.exists(source_path):
            print(f"  [ERROR] Source path not found: {source_path}")
            return []

        # NOT /tmp: it's tmpfs (RAM) on most systemd distros and the dump alone measured 1.9 GB —
        # staging it in RAM starves the plaso workers (B-4).
        temp_dir = Path("/var/tmp") if os.path.isdir("/var/tmp") else Path(tempfile.gettempdir())
        plaso_dump = temp_dir / "autoforensiq_plaso.dump"
        csv_output = temp_dir / "autoforensiq_timeline.csv"

        # A timeout-killed run leaves a partial dump; log2timeline RESUMES into it and crashes
        # ("database disk image is malformed"), and psort refuses to overwrite an existing CSV
        # (B-4). Always start clean.
        for stale in (plaso_dump, csv_output):
            stale.unlink(missing_ok=True)

        # STEP 1 — log2timeline
        print("  [PLASO] Running log2timeline (this may take a few minutes)...")

        stdout, stderr, code = self.run_command(
            [
                LOG2TIMELINE,
                "--status_view", "none",
                # Scoped to what _parse_csv's SUSPICIOUS_SOURCES filter keeps — a bare invocation
                # runs every parser + hashes every file and never finished in 600s. "win7" covers
                # Win7 AND later (verified on the dev01 Server 2022 E01); winxp adds pre-Win7
                # formats near-free; prefetch = execution evidence. !filestat (one event per file,
                # duplicates tsk_fls) and !pe (heavy, never matches the filter) dominate cost and
                # are excluded.
                "--parsers", "win7,winxp,prefetch,!filestat,!pe",
                # Nothing downstream uses plaso hashes; hashing was the biggest time sink.
                "--hashers", "none",
                # Non-interactive: multi-partition images prompt with no TTY.
                "--partitions", "all",
                # VSS images prompt "VSS identifier(s):" and block forever with no TTY; "none" =
                # current volume only.
                "--vss_stores", "none",
                # Default = one worker per core (15 here) → memory pressure and the 600s timeout
                # (B-4); the run is I/O-bound anyway.
                "--workers", "4",
                "--storage_file", str(plaso_dump),
                source_path
            ],
            input_files=[source_path],
            output_files=[str(plaso_dump)],
            # Deliberately 600s (accepted, B-4): the 11 GB E01 measured ~65 min total and mostly
            # re-corroborates the memory/disk wrappers, so GB-scale images time out; small images
            # complete fine.
            timeout=600
        )

        if code != 0:
            print("  [ERROR] log2timeline failed")
            print(stderr[:500])
            return []

        if not plaso_dump.exists():
            print("  [ERROR] Plaso dump file not created")
            return []

        # STEP 2 — psort export
        print("  [PLASO] Running psort (exporting timeline to CSV)...")

        stdout, stderr, code = self.run_command(
            [
                PSORT,
                "-o",
                "l2tcsv",
                "-w",
                str(csv_output),
                str(plaso_dump)
            ],
                input_files=[str(plaso_dump)],
                output_files=[str(csv_output)],
            timeout=300
        )

        if code != 0:
            print("  [ERROR] psort failed")
            print(stderr[:500])
            return []

        if not csv_output.exists():
            print("  [ERROR] CSV output not created")
            return []

        items = self._parse_csv(csv_output)

        # cleanup
        for f in (plaso_dump, csv_output):
            f.unlink(missing_ok=True)

        return items

    def _parse_csv(self, csv_path: str) -> list:
        print("  [PLASO] Parsing CSV timeline...")

        items = []
        routine_items = []
        routine_seen = set()

        # evtx "Strings" blobs exceed csv's 128 KB field limit; the csv.Error silently truncated the
        # dev01 CSV at ~row 360k of 633k.
        csv.field_size_limit(sys.maxsize)

        try:
            p = Path(csv_path)
            with p.open("r", encoding="utf-8", errors="replace") as f:

                reader = csv.DictReader(f)

                for row in reader:
                    try:
                        # l2tcsv has no datetime/description columns — the real keys are
                        # date,time,desc,sourcetype (B-12: wrong keys made even a successful run
                        # parse 0 items).
                        timestamp = f'{row.get("date", "")} {row.get("time", "")}'.strip()
                        source = row.get("sourcetype", "")
                        desc = row.get("desc", "")
                        filename = row.get("filename", "")

                        lower_desc = desc.lower()
                        lower_source = source.lower()

                        is_suspicious = any(
                            kw in lower_desc or kw in lower_source
                            for kw in SUSPICIOUS_SOURCES
                        )

                        if is_suspicious:
                            items.append(
                                self.make_evidence_item(
                                    artifact_id=stable_artifact_id("plaso", timestamp, desc),
                                    evidence_type="timeline_event",
                                    value=f"[{timestamp}] [{source}] {desc} | File: {filename}",
                                    # medium, not high: the substring filter is a lead generator
                                    # (~7.7k mostly-benign keeps on dev01); bad events escalate via
                                    # ioc_rescorer.
                                    severity="medium",
                                    confidence=0.72,
                                    timestamp=timestamp
                                )
                            )
                        elif len(routine_items) < ROUTINE_SAMPLE_CAP:
                            key = (source, desc)
                            if key not in routine_seen:
                                routine_seen.add(key)
                                routine_items.append(
                                    self.make_evidence_item(
                                        artifact_id=stable_artifact_id("plaso", timestamp, desc),
                                        evidence_type="timeline_event",
                                        value=f"[{timestamp}] [{source}] {desc} | File: {filename}",
                                        severity="low",
                                        confidence=0.5,
                                        timestamp=timestamp
                                    )
                                )

                    except Exception:
                        continue

        except Exception as e:
            print(f"  [ERROR] Failed to parse CSV: {e}")

        print(f"  [PLASO] Timeline → {len(items)} suspicious events "
              f"+ {len(routine_items)} routine sample")

        return items + routine_items


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python -m src.wrappers.plaso_wrapper <evidence_dir_or_image>")
        sys.exit(1)

    wrapper = PlasoWrapper()

    items = wrapper.run(sys.argv[1])

    output = {
        "tool": "plaso",
        "items": items
    }

    os.makedirs("output/raw", exist_ok=True)

    with open("output/raw/plaso_output.json", "w") as f:
        json.dump(output, f, indent=2)

    print(
        f"\n[DONE] {len(items)} evidence items saved to output/raw/plaso_output.json"
    )
