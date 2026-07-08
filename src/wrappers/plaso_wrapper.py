import os
import sys
import json
import shutil
import tempfile
import csv
from pathlib import Path
from src.wrappers.base_wrapper import BaseWrapper


def _resolve_cmd(preferred: str, fallback: str) -> str:
    """Resolve a plaso console script (log2timeline.py / psort.py).

    Under the documented `venv/bin/python autoforensiq.py` invocation, venv/bin
    is NOT on PATH, so shutil.which() misses a plaso installed via
    `venv/bin/pip install plaso` (its scripts land in venv/bin). This is the same
    root cause as the volatility D1 fix, so check the interpreter's own bin dir
    first, then PATH, then fall back to the bare name (which fails loudly if the
    binary genuinely isn't installed)."""
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

class PlasoWrapper(BaseWrapper):
    # The orchestrator feeds plaso the disk image (the ontology lists
    # disk_image/evidence_directory). The display layers previously called it
    # log_files, which contradicted what actually runs (issue D2).
    consumes = "disk_image"

    def __init__(self):
        super().__init__("plaso")

    def run(self, source_path: str) -> list:
        if not os.path.exists(source_path):
            print(f"  [ERROR] Source path not found: {source_path}")
            return []

        # NOT tempfile.gettempdir(): /tmp is tmpfs (RAM-backed) on Fedora/most
        # systemd distros, and the storage dump alone measured 1.9 GB on the 11 GB
        # dev01 E01 — staging it in RAM competes with the plaso workers for the
        # same memory budget (B-4's original OOM pressure). /var/tmp is the
        # disk-backed temp location.
        temp_dir = Path("/var/tmp") if os.path.isdir("/var/tmp") else Path(tempfile.gettempdir())
        plaso_dump = temp_dir / "autoforensiq_plaso.dump"
        csv_output = temp_dir / "autoforensiq_timeline.csv"

        # These fixed-path temp files are only cleaned up on the success path, so
        # a run killed mid-write (timeout/OOM) leaves a PARTIAL sqlite dump behind
        # — and log2timeline RESUMES into an existing storage file, crashing
        # instantly with "sqlite3.DatabaseError: database disk image is malformed"
        # (B-4: every dev01 run after the first timed-out one produced 0 items
        # this way). psort likewise refuses to overwrite an existing CSV. Always
        # start from a clean slate.
        for stale in (plaso_dump, csv_output):
            stale.unlink(missing_ok=True)

        # STEP 1 — log2timeline
        print("  [PLASO] Running log2timeline (this may take a few minutes)...")

        stdout, stderr, code = self.run_command(
            [
                LOG2TIMELINE,
                "--status_view", "none",
                # A bare `log2timeline <image>` runs EVERY parser and MD5-hashes
                # every file on the disk. On an 11 GB E01 that never finished
                # inside the 600s timeout below, so the stage was killed and
                # returned zero events. Restrict to the artifacts _parse_csv
                # actually keeps (SUSPICIOUS_SOURCES: run keys, scheduled tasks,
                # powershell/cmd, downloads) so it completes in minutes:
                #   win7      -> winreg (run keys/autorun), winjob + winevtx
                #                (scheduled tasks, powershell/cmd command lines),
                #                webhist (downloads), powershell transcripts.
                #                Despite the name, "win7" is plaso's preset for
                #                Windows 7 AND LATER — the same evtx/registry/
                #                prefetch/NTFS formats cover 8/10/11 and Server
                #                2008-2022 (verified on the dev01 Server 2022 E01).
                #   winxp     -> the pre-Win7 formats (.evt event logs, INFO2
                #                recyclers). Near-free on a modern image (its
                #                XP-only parsers just find nothing) but makes the
                #                stage version-agnostic across all Windows.
                #   prefetch  -> execution evidence (cmd.exe/powershell .pf)
                # These presets also drag in two parsers whose output the
                # SUSPICIOUS_SOURCES filter throws away but which dominate cost,
                # so exclude them (a full super-timeline is wasted here — the
                # pipeline only keeps events matching a handful of keywords):
                #   !filestat -> one event per file (millions on a full disk);
                #                ballooned the run to 300 MB+ and duplicates the
                #                tsk_fls wrapper's per-file timeline.
                #   !pe       -> parses every executable on disk (heavy I/O);
                #                its PE compile-time events never match the
                #                filter keywords.
                "--parsers", "win7,winxp,prefetch,!filestat,!pe",
                # Nothing downstream uses plaso hashes, and hashing every file
                # was the single biggest time sink.
                "--hashers", "none",
                # Process all partitions non-interactively; a multi-partition
                # image would otherwise prompt for a selection with no TTY.
                "--partitions", "all",
                # Same reason for shadow copies: an image with VSS snapshots
                # (like the dev01 E01) prompts "VSS identifier(s):" and blocks
                # forever with no TTY. "none" = current volume only, no prompt
                # (processing every snapshot would also multiply runtime).
                "--vss_stores", "none",
                # The default spawns one worker per core (15 on this box), which
                # under a 14 GB budget drove the machine into memory pressure and
                # the 600s timeout (B-4). Four workers is the sweet spot: bounded
                # memory, and the run is I/O-bound anyway.
                "--workers", "4",
                "--storage_file", str(plaso_dump),
                source_path
            ],
            input_files=[source_path],
            output_files=[str(plaso_dump)],
            # Deliberately kept at 600s (accepted limitation): a measured run on
            # an 11 GB E01 needed ~18 min here plus ~46 min in psort — raising
            # the timeouts would buy a ~65-minute stage whose keyword filter
            # mostly re-corroborates what the memory/disk wrappers already
            # surface. GB-scale images therefore time out and plaso contributes
            # nothing; small images complete fine.
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
        for f in [plaso_dump, csv_output]:
            try:
                if isinstance(f, Path):
                    f.unlink()
                else:
                    os.remove(f)
            except Exception:
                pass

        return items

    def _parse_csv(self, csv_path: str) -> list:
        print("  [PLASO] Parsing CSV timeline...")

        items = []

        # Real psort output contains fields beyond csv's 128 KB default limit
        # (evtx "Strings" blobs) — the resulting csv.Error escapes the row loop
        # and silently truncates the timeline (the dev01 CSV died at row ~360k
        # of 633k).
        csv.field_size_limit(sys.maxsize)

        try:
            p = Path(csv_path)
            with p.open("r", encoding="utf-8", errors="replace") as f:

                reader = csv.DictReader(f)

                for row in reader:
                    try:
                        # l2tcsv columns (B-12): the format has no "datetime" or
                        # "description" — the header is date,time,timezone,MACB,
                        # source,sourcetype,...,desc,...,filename,... Reading the
                        # wrong keys made every row look empty, so the keyword
                        # filter matched nothing and a *successful* plaso run
                        # still produced 0 items. "sourcetype" is the readable
                        # label ("Registry Key"); "source" is a short code (REG).
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
                                    artifact_id=f"plaso_{abs(hash(timestamp + desc)) % 99999}",
                                    evidence_type="timeline_event",
                                    value=f"[{timestamp}] [{source}] {desc} | File: {filename}",
                                    # medium, not high: the bare-substring filter
                                    # is a lead generator, not a detector — on the
                                    # dev01 CSV it kept 7,734 rows, almost all
                                    # benign (Start-Menu powershell .lnk files,
                                    # WinSxS "Deployments" keys matching
                                    # "startup"). Blanket high would flood Key
                                    # Findings; genuinely bad events still
                                    # escalate via the ioc_rescorer catalogs.
                                    severity="medium",
                                    confidence=0.72,
                                    timestamp=timestamp
                                )
                            )

                    except Exception:
                        continue

        except Exception as e:
            print(f"  [ERROR] Failed to parse CSV: {e}")

        print(f"  [PLASO] Timeline → {len(items)} suspicious events")

        return items


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
