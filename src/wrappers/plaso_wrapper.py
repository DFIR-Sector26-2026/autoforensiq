import os
import json
import shutil
import tempfile
import csv
from src.wrappers.base_wrapper import BaseWrapper


def _resolve_cmd(preferred: str, fallback: str) -> str:
    return preferred if shutil.which(preferred) else fallback


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
    def __init__(self):
        super().__init__("plaso")

    def run(self, source_path: str) -> list:
        if not os.path.exists(source_path):
            print(f"  [ERROR] Source path not found: {source_path}")
            return []

        plaso_dump = os.path.join(
            tempfile.gettempdir(),
            "autoforensiq_plaso.dump"
        )

        # STEP 1 — log2timeline
        print("  [PLASO] Running log2timeline (this may take a few minutes)...")

        stdout, stderr, code = self.run_command(
            [
                LOG2TIMELINE,
                "--status_view",
                "none",
                "--storage_file",
                plaso_dump,
                source_path
            ],
            input_files=[source_path],
            output_files=[plaso_dump],
            timeout=600
        )

        if code != 0:
            print("  [ERROR] log2timeline failed")
            print(stderr[:500])
            return []

        if not os.path.exists(plaso_dump):
            print("  [ERROR] Plaso dump file not created")
            return []

        # STEP 2 — psort export
        csv_output = os.path.join(
            tempfile.gettempdir(),
            "autoforensiq_timeline.csv"
        )

        print("  [PLASO] Running psort (exporting timeline to CSV)...")

        stdout, stderr, code = self.run_command(
            [
                PSORT,
                "-o",
                "l2tcsv",
                "-w",
                csv_output,
                plaso_dump
            ],
            input_files=[plaso_dump],
            output_files=[csv_output],
            timeout=300
        )

        if code != 0:
            print("  [ERROR] psort failed")
            print(stderr[:500])
            return []

        if not os.path.exists(csv_output):
            print("  [ERROR] CSV output not created")
            return []

        items = self._parse_csv(csv_output)

        # cleanup
        for f in [plaso_dump, csv_output]:
            try:
                os.remove(f)
            except Exception:
                pass

        return items

    def _parse_csv(self, csv_path: str) -> list:
        print("  [PLASO] Parsing CSV timeline...")

        items = []

        try:
            with open(
                csv_path,
                "r",
                encoding="utf-8",
                errors="replace"
            ) as f:

                reader = csv.DictReader(f)

                for row in reader:
                    try:
                        timestamp = row.get("datetime", "")
                        source = row.get("source", "")
                        desc = row.get("description", "")
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
                                    severity="high",
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
    import sys

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
