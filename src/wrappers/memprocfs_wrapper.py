import os
import json

from src.wrappers.base_wrapper import BaseWrapper


class MemProcFSWrapper(BaseWrapper):

    def __init__(self):

        super().__init__("memprocfs")

    def run(self, image_path):

        mount_dir = "/tmp/memprocfs_mount"

        os.makedirs(mount_dir, exist_ok=True)

        command = [
            "/home/yuti/Downloads/memprocfs",
            "-device",
            image_path,
            "-mount",
            mount_dir
        ]

        stdout, stderr, code = self.run_command(
            command,
            input_files=[image_path],
            timeout=300
        )

        if code != 0:

            print("[MemProcFS] mount failed")
            print(stderr)

            return [
                self.make_evidence_item(
                    artifact_id="memprocfs_mount_failure",
                    evidence_type="memory_analysis_status",
                    value=(
                        "MemProcFS could not parse the "
                        "memory image automatically. "
                        "Possible DTB/CR3 issue or "
                        "unsupported dump structure."
                    ),
                    severity="medium",
                    confidence=0.70
                )
            ]

        print("[MemProcFS] mounted successfully")

        items = []

        process_path = f"{mount_dir}/forensic/processes"

        if os.path.exists(process_path):

            for name in os.listdir(process_path):

                items.append(
                    self.make_evidence_item(
                        artifact_id=f"memprocfs_proc_{name}",
                        evidence_type="memprocfs_process",
                        value=f"Process artifact found: {name}",
                        severity="medium",
                        confidence=0.80
                    )
                )

        if not items:

            items.append(
                self.make_evidence_item(
                    artifact_id="memprocfs_no_artifacts",
                    evidence_type="memory_analysis_status",
                    value=(
                        "MemProcFS mounted successfully "
                        "but no process artifacts "
                        "were extracted."
                    ),
                    severity="low",
                    confidence=0.60
                )
            )

        return items


if __name__ == "__main__":

    import sys

    if len(sys.argv) < 2:

        print(
            "Usage: python -m "
            "src.wrappers.memprocfs_wrapper "
            "<memory_image>"
        )

        sys.exit(1)

    image_path = sys.argv[1]

    wrapper = MemProcFSWrapper()

    items = wrapper.run(image_path)

    output = {
        "tool": "memprocfs",
        "items": items
    }

    os.makedirs("output/raw", exist_ok=True)

    with open(
        "output/raw/memprocfs_output.json",
        "w"
    ) as f:

        json.dump(
            output,
            f,
            indent=2
        )

    print(
        f"[DONE] Saved "
        f"{len(items)} evidence items"
    )
