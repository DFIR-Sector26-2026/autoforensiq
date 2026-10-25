import os
import re
import json
import shutil
import tempfile
from pathlib import Path

from src.wrappers.base_wrapper import BaseWrapper, stable_artifact_id
from src.wrappers.tsk_wrapper import _file_signal
from src.data.threat_intel import c2_port_severity
from src.utils.audit_log import log_action


# Normal Windows session processes — stay low. Name-only, hence masquerade- blind (3.1-D, accepted):
# a malicious "svchost.exe" is elevated only via corroborating signals from the other wrappers.
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

# Strong malware / ransomware indicators in a process *name*. A hit is suspicious on its own (no
# corroboration needed) and escalates to high.
_MALICIOUS_NAME_TOKENS = (
    "tasksche", "wanadecrypt", "wannacry", "wncry", "wcry", "mssecsvc",
    "@wana", "decrypt0r", "ransom", "locker", "cryptor", "mimikatz",
    "cobaltstrike", "beacon", "meterpreter", "payload", "njrat", "darkcomet",
)

# Self-descriptive hostile service names never hit.
_HOSTILE_SERVICE_RE = re.compile("|".join(
    f"(?<![a-z]){w}(?![a-z])"
    for w in ("malware", "backdoor", "rootkit", "keylogger", "trojan")
))


def _looks_like_random_name(name):
    """Random / hash-like executable name heuristic (`a9f3c1b2.exe`) — conservative, operates on
    the stem only."""
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
    """Tier a process by *name* (3.5-C — everything at medium/0.80 flooded the medium tier).
    Returns (severity, confidence, note): known-malicious name → high/0.85; random/hash-like →
    medium/0.70; system/unknown → low/0.50; ordinary app → low/0.55."""
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
    """First line of a MemProcFS virtual file (e.g. a process's `name`/`ppid`), stripped. Returns
    "" on any read error — these are FUSE-backed files."""
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.readline().strip()
    except Exception:
        return ""


def _enumerate_mounted_processes(mount_dir):
    """Read processes from <mount>/pid/<pid>/{pid,name,ppid} — the canonical view; the old code
    scanned a nonexistent path and enumerated nothing (3.5-B). Returns [{"pid","name","ppid"}]
    (ppid may be "")."""
    procs = []
    pid_root = Path(mount_dir) / "pid"
    if not pid_root.is_dir():
        return procs

    for entry in sorted(os.listdir(pid_root), key=lambda e: (not e.isdigit(), e)):
        proc_dir = pid_root / entry
        if not proc_dir.is_dir():
            continue
        # The directory name under /pid/ is the numeric PID; prefer the `pid` virtual file when
        # present, falling back to the directory name.
        pid = _read_mount_file(proc_dir / "pid") or entry.strip()
        name = _read_mount_file(proc_dir / "name") or "unknown"
        ppid = _read_mount_file(proc_dir / "ppid")
        procs.append({"pid": pid, "name": name, "ppid": ppid})

    return procs


class MemProcFSWrapper(BaseWrapper):

    consumes = "memory_dump"

    def __init__(self):

        super().__init__("memprocfs")

    def run(self, image_path):
        # Prefer the pip-installed Python API. Only fall back to the external binary if the
        # `memprocfs` package isn't installed.
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

            # Raw dumps often need a pagefile to reconstruct paged-out memory;
            # -pagefile0 requires a real file, so only retry when we have one.
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
            procs = vmm.process_list()
            for proc in procs:

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

            # Modules, services and network objects reach exactly the IOC class vol3 misses on pre-Vista images where MemProcFS still parses.
            items.extend(self._module_items(procs))
            items.extend(self._service_items(vmm))
            items.extend(self._network_items(vmm))

        finally:
            try:
                vmm.close()
            except Exception:
                pass

        if not items:
            items.append(self._no_artifacts_item())

        return items

    def _module_items(self, procs):
        """Loaded modules with a disk-style signal"""
        items = []
        for proc in procs:
            try:
                modules = proc.module_list()
            except Exception:
                continue
            for mod in modules:
                # Attribute reads hit the native binding lazily — a corrupt in-memory
                # module entry can raise (UnicodeDecodeError on Windows_RAM.mem).
                try:
                    path = mod.fullname or mod.name
                except Exception:
                    continue
                if not path:
                    continue
                signal = _file_signal(path.replace("\\", "/"))
                if not signal:
                    continue
                severity, label = signal
                items.append(self.make_evidence_item(
                    artifact_id=stable_artifact_id(
                        "memprocfs_mod", proc.pid, path.lower()
                    ),
                    evidence_type="suspicious_dll",
                    value=(
                        f"{label}: {path} loaded in "
                        f"{proc.name} (PID {proc.pid})"
                    ),
                    severity=severity,
                    confidence=0.75,
                ))
        if items:
            print(f"[MemProcFS] modules → {len(items)} suspicious item(s)")
        return items

    def _service_items(self, vmm):
        """Windows services, emitted only on a hostile name or a disk-style image-path signal
        (a bare XP box already carries 253 services)."""
        try:
            services = vmm.maps.service()
        except Exception:
            return []
        items = []
        for svc in services.values():
            name = str(svc.get("name") or "")
            display = str(svc.get("name-display") or "")
            path = str(svc.get("path") or "")
            image = str(svc.get("path-image") or "")
            signal = _file_signal(image.replace("\\", "/")) if image else None
            if _HOSTILE_SERVICE_RE.search(f"{name} {display} {path} {image}".lower()):
                severity, label = "high", "Hostile-named service"
            elif signal:
                severity, label = signal
            else:
                continue
            kind = ("kernel-driver service"
                    if svc.get("dwServiceType") in (1, 2) else "service")
            items.append(self.make_evidence_item(
                artifact_id=stable_artifact_id("memprocfs_svc", name, path, image),
                evidence_type="service",
                value=(
                    f"{label}: {kind} '{name}' ({display}) "
                    f"path={path or image or 'n/a'}"
                ),
                severity=severity,
                confidence=0.75,
            ))
        if items:
            print(f"[MemProcFS] services → {len(items)} suspicious item(s)")
        return items

    def _network_items(self, vmm):
        """Network object map → network_connection items, value/severity mirroring the
        volatility netstat parser so downstream port/peer heuristics apply uniformly."""
        try:
            net = vmm.maps.net()
        except Exception:
            return []
        items = []
        for entry in (net.values() if isinstance(net, dict) else net):
            src_ip = entry.get("src-ip", "")
            dst_ip = entry.get("dst-ip", "")
            if not (src_ip or dst_ip):
                continue
            src_port = entry.get("src-port", "")
            dst_port = entry.get("dst-port", "")
            pid = entry.get("pid", "")
            proto = entry.get("proto", "?")
            port_sevs = [s for s in (c2_port_severity(src_port),
                                     c2_port_severity(dst_port)) if s]
            severity = ("high" if "high" in port_sevs
                        else "medium" if port_sevs else "low")
            items.append(self.make_evidence_item(
                artifact_id=stable_artifact_id(
                    "memprocfs_net", proto, src_ip, src_port, dst_ip, dst_port, pid
                ),
                evidence_type="network_connection",
                value=(
                    f"{proto} {src_ip}:{src_port} -> "
                    f"{dst_ip}:{dst_port} (PID:{pid})"
                ),
                severity=severity,
                confidence=0.75,
            ))
        if items:
            print(f"[MemProcFS] network → {len(items)} connection item(s)")
        return items

    def _find_pagefile(self, image_path):
        """Locate a pagefile to aid reconstruction of paged-out memory: an explicit
        MEMPROCFS_PAGEFILE env var, else a `pagefile.sys` sitting beside the image. Returns the
        path, or None when none is available — in which case retrying the API with `-pagefile0`
        would be pointless."""

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
