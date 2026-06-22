import os
import re
import json
import shutil
import tempfile
from pathlib import Path

from src.wrappers.base_wrapper import BaseWrapper
from src.utils.audit_log import log_action


# Process names that are part of a normal Windows session. Their mere presence
# in the process list is unremarkable, so they stay at low severity rather than
# being escalated. NOTE: name-only, hence masquerade-blind (issue 3.1-D, accepted
# by design) — a malicious binary *named* `svchost.exe` stays low here; the
# pipeline elevates it only via corroborating signals (injection, suspicious
# parent/cmdline) emitted by the other wrappers.
_BENIGN_SYSTEM_PROCESSES = {
    "system", "registry", "memory compression", "secure system",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "lsaiso.exe", "svchost.exe", "explorer.exe", "dwm.exe",
    "spoolsv.exe", "conhost.exe", "taskhostw.exe", "taskhost.exe",
    "runtimebroker.exe", "sihost.exe", "ctfmon.exe", "fontdrvhost.exe",
    "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "dllhost.exe", "wmiprvse.exe", "audiodg.exe", "userinit.exe",
    "smartscreen.exe", "shellexperiencehost.exe", "wudfhost.exe",
}

# Strong malware / ransomware indicators in a process *name*. A hit is suspicious
# on its own (no corroboration needed) and escalates to high.
_MALICIOUS_NAME_TOKENS = (
    "tasksche", "wanadecrypt", "wannacry", "wncry", "wcry", "mssecsvc",
    "@wana", "decrypt0r", "ransom", "locker", "cryptor", "mimikatz",
    "cobaltstrike", "beacon", "meterpreter", "payload", "njrat", "darkcomet",
)


def _looks_like_random_name(name):
    """Heuristic for a randomly generated / hash-like executable name — a common
    malware trait (`a9f3c1b2.exe`, `xkzqwvbn.exe`). Operates on the stem (name
    minus a single trailing extension) and stays conservative to avoid flagging
    ordinary product names."""
    stem = name.rsplit(".", 1)[0] if "." in name else name
    stem = stem.strip().lower()
    # only judge plausible single tokens; real product names carry separators
    if len(stem) < 8 or not re.fullmatch(r"[a-z0-9]+", stem):
        return False
    # hex-string name of reasonable length with at least one digit → hash-like
    if re.fullmatch(r"[0-9a-f]{8,}", stem) and any(c.isdigit() for c in stem):
        return True
    # long, vowel-starved token → keyboard-mash name
    letters = [c for c in stem if c.isalpha()]
    vowels = sum(1 for c in letters if c in "aeiou")
    if len(letters) >= 8 and vowels <= max(1, len(letters) // 6):
        return True
    return False


def _classify_process(name):
    """Classify a MemProcFS-enumerated process by *name* into a severity tier
    (issue 3.5-C). Without this filter every process landed at medium/0.80, which
    floods the medium tier on a MemProcFS-supported image (potentially hundreds).

    Returns ``(severity, confidence, note)``:
      * known malware/ransomware name   → high   / 0.85
      * random / hash-like name         → medium / 0.70
      * common Windows system process   → low    / 0.50
      * unidentified                    → low    / 0.50
      * anything else (ordinary app)    → low    / 0.55
    """
    lowered = (name or "").strip().lower()

    if not lowered or lowered == "unknown":
        return "low", 0.50, "unidentified process"

    for token in _MALICIOUS_NAME_TOKENS:
        if token in lowered:
            return "high", 0.85, f"name matches known-malicious indicator '{token}'"

    if lowered in _BENIGN_SYSTEM_PROCESSES:
        return "low", 0.50, "common Windows system process"

    if _looks_like_random_name(lowered):
        return "medium", 0.70, "random / hash-like process name"

    return "low", 0.55, "ordinary process"


def _read_mount_file(path):
    """First line of a MemProcFS virtual file (e.g. a process's `name`/`ppid`),
    stripped. Returns "" on any read error — these are FUSE-backed files."""
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.readline().strip()
    except Exception:
        return ""


def _enumerate_mounted_processes(mount_dir):
    """Read the process list from a MemProcFS mount.

    MemProcFS exposes processes under ``<mount>/pid/<pid>/`` (the canonical
    per-PID view), each directory carrying a ``name``/``ppid`` virtual file. The
    old code scanned ``<mount>/forensic/processes``, which is not part of the
    mount layout, so even a successful mount enumerated nothing (issue 3.5-B).

    Returns a list of ``{"pid", "name", "ppid"}`` dicts (ppid may be "").
    """
    procs = []
    pid_root = Path(mount_dir) / "pid"
    if not pid_root.is_dir():
        return procs

    for entry in sorted(os.listdir(pid_root), key=lambda e: (not e.isdigit(), e)):
        proc_dir = pid_root / entry
        if not proc_dir.is_dir():
            continue
        # The directory name under /pid/ is the numeric PID; prefer the `pid`
        # virtual file when present, falling back to the directory name.
        pid = _read_mount_file(proc_dir / "pid") or entry.strip()
        name = _read_mount_file(proc_dir / "name") or "unknown"
        ppid = _read_mount_file(proc_dir / "ppid")
        procs.append({"pid": pid, "name": name, "ppid": ppid})

    return procs


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
        input_files = [image_path]

        try:
            vmm = memprocfs.Vmm(["-device", image_path])

        except Exception as exc:

            # log the initial failure
            log_action(
                tool_name=self.tool_name,
                command=audit_cmd,
                input_files=[image_path],
                output_files=[],
                status="failed",
                error=str(exc)[:500],
            )

            print(f"[MemProcFS] API initial parse failed: {exc}")

            # A raw dump often fails to initialise when paged-out memory can't
            # be reconstructed. MemProcFS can use a pagefile for this, but the
            # option is `-pagefile0 <path>` and needs a real file — a bare
            # `-pagefile` is rejected, so only retry when we actually have one.
            pagefile = self._find_pagefile(image_path)

            if not pagefile:
                print("[MemProcFS] no pagefile available; skipping API retry")
                return self._run_binary(image_path)

            audit_cmd = [
                "memprocfs-api", "-device", image_path,
                "-pagefile0", pagefile,
            ]
            input_files = [image_path, pagefile]

            try:
                print(f"[MemProcFS] retrying API with -pagefile0 {pagefile}")
                vmm = memprocfs.Vmm(
                    ["-device", image_path, "-pagefile0", pagefile]
                )
            except Exception as exc2:
                print(f"[MemProcFS] API retry failed: {exc2}")

                # fall back to binary path if available
                return self._run_binary(image_path)

        # success → record custody entry (hashes the input image)
        log_action(
            tool_name=self.tool_name,
            command=audit_cmd,
            input_files=input_files,
            output_files=[],
            status="success",
        )

        print("[MemProcFS] image parsed via API")

        items = []

        try:
            for proc in vmm.process_list():

                severity, confidence, note = _classify_process(proc.name)
                items.append(
                    self.make_evidence_item(
                        artifact_id=f"memprocfs_proc_{proc.pid}",
                        evidence_type="memprocfs_process",
                        value=(
                            f"{proc.name} "
                            f"(PID {proc.pid}, PPID {proc.ppid}) — {note}"
                        ),
                        severity=severity,
                        confidence=confidence,
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

    def _find_pagefile(self, image_path):
        """Locate a pagefile to aid reconstruction of paged-out memory: an
        explicit MEMPROCFS_PAGEFILE env var, else a `pagefile.sys` sitting
        beside the image. Returns the path, or None when none is available — in
        which case retrying the API with `-pagefile0` would be pointless."""

        env_pagefile = os.environ.get("MEMPROCFS_PAGEFILE")
        if env_pagefile and Path(env_pagefile).is_file():
            return env_pagefile

        try:
            sibling = Path(image_path).resolve().parent / "pagefile.sys"
            if sibling.is_file():
                return str(sibling)
        except Exception:
            pass

        return None

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
                        "MemProcFS binary fallback is unavailable: no binary "
                        "was found. Set MEMPROCFS_PATH or add 'memprocfs' to "
                        "PATH."
                    ),
                    severity="low",
                    confidence=0.60,
                )
            ]

        # Create a temporary mount directory in a portable location
        mount_dir = tempfile.mkdtemp(prefix="memprocfs_mount_")

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
            # attempt cleanup
            try:
                shutil.rmtree(mount_dir)
            except Exception:
                pass

            return [self._failure_item()]

        print("[MemProcFS] mounted successfully")

        items = []


        try:
            for proc in _enumerate_mounted_processes(mount_dir):
                ppid = proc.get("ppid")
                severity, confidence, note = _classify_process(proc["name"])
                value = (
                    f"{proc['name']} (PID {proc['pid']}"
                    + (f", PPID {ppid}" if ppid else "")
                    + f") — {note}"
                )
                items.append(
                    self.make_evidence_item(
                        artifact_id=f"memprocfs_proc_{proc['pid']}",
                        evidence_type="memprocfs_process",
                        value=value,
                        severity=severity,
                        confidence=confidence,
                    )
                )
        finally:
            # try to unmount if mounted, then remove the temporary dir
            try:
                # fusermount on Linux, umount as fallback
                self.run_command(["fusermount", "-u", mount_dir], timeout=10)
            except Exception:
                try:
                    self.run_command(["umount", mount_dir], timeout=10)
                except Exception:
                    pass
            try:
                shutil.rmtree(mount_dir)
            except Exception:
                pass

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
