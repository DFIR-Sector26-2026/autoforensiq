import os
import json
import shutil

from src.wrappers.base_wrapper import BaseWrapper
from src.utils.audit_log import log_action


class MemProcFSWrapper(BaseWrapper):

    def __init__(self):

        super().__init__("memprocfs")

    def run(self, image_path):
        # Prefer the pip-installed Python API. Only fall back to the
        # external binary if the `memprocfs` package isn't installed.
        try:
            import memprocfs 
        except ImportError:
            print(
                "[MemProcFS] python package not installed "
                "— falling back to binary"
            )
            return self._run_binary(image_path)

        return self._run_api(image_path)

    # API path (preferred on Linux: no FUSE, no mount) 
    def _run_api(self, image_path):

        import memprocfs

        # synthetic command string, purely for the chain-of-custody log
        audit_cmd = ["memprocfs-api", "-device", image_path]

        try:
            vmm = memprocfs.Vmm(["-device", image_path])

        except Exception as exc:

            log_action(
                tool_name=self.tool_name,
                command=audit_cmd,
                input_files=[image_path],
                output_files=[],
                status="failed",
                error=str(exc)[:500],
            )

            print(f"[MemProcFS] API could not parse image: {exc}")

            return [self._failure_item()]

        # success → record custody entry (hashes the input image)
        log_action(
            tool_name=self.tool_name,
            command=audit_cmd,
            input_files=[image_path],
            output_files=[],
            status="success",
        )

        print("[MemProcFS] image parsed via API")

        items = []

        try:
            for proc in vmm.process_list():

                items.append(
                    self.make_evidence_item(
                        artifact_id=f"memprocfs_proc_{proc.pid}",
                        evidence_type="memprocfs_process",
                        value=(
                            f"{proc.name} "
                            f"(PID {proc.pid}, PPID {proc.ppid})"
                        ),
                        severity="medium",
                        confidence=0.80,
                    )
                )

        finally:
            try:
                vmm.close()
            except Exception:
                pass

        if not items:
            items.append(self._no_artifacts_item())

        return items

    # binary path (fallback: requires FUSE + the memprocfs binary) 
    def _run_binary(self, image_path):

        # MEMPROCFS_PATH wins; otherwise look up `memprocfs` on PATH.
        binary = os.environ.get("MEMPROCFS_PATH") or shutil.which("memprocfs")

        if not binary:

            print(
                "[MemProcFS] binary not found "
                "(set MEMPROCFS_PATH or add 'memprocfs' to PATH)"
            )

            return [
                self.make_evidence_item(
                    artifact_id="memprocfs_unavailable",
                    evidence_type="memory_analysis_status",
                    value=(
                        "MemProcFS is unavailable: the python package is "
                        "not installed and no binary was found. Install the "
                        "pip package, or set MEMPROCFS_PATH / add 'memprocfs' "
                        "to PATH."
                    ),
                    severity="low",
                    confidence=0.60,
                )
            ]

        mount_dir = "/tmp/memprocfs_mount"

        os.makedirs(mount_dir, exist_ok=True)

        command = [
            binary,
            "-device",
            image_path,
            "-mount",
            mount_dir,
        ]

        stdout, stderr, code = self.run_command(
            command,
            input_files=[image_path],
            timeout=300,
        )

        if code != 0:

            print("[MemProcFS] mount failed")
            print(stderr)

            return [self._failure_item()]

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
                        confidence=0.80,
                    )
                )

        if not items:
            items.append(self._no_artifacts_item())

        return items

    # shared evidence items 
    def _failure_item(self):

        return self.make_evidence_item(
            artifact_id="memprocfs_mount_failure",
            evidence_type="memory_analysis_status",
            value=(
                "MemProcFS could not parse the memory image "
                "automatically. Possible DTB/CR3 issue or "
                "unsupported dump structure."
            ),
            severity="medium",
            confidence=0.70,
        )

    def _no_artifacts_item(self):

        return self.make_evidence_item(
            artifact_id="memprocfs_no_artifacts",
            evidence_type="memory_analysis_status",
            value=(
                "MemProcFS parsed the image but no process "
                "artifacts were extracted."
            ),
            severity="low",
            confidence=0.60,
        )


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
