import os
import json
import uuid
import hashlib
import tempfile
from pathlib import Path

from .base_wrapper import BaseWrapper

PLUGINS = [
    "windows.pslist",
    "windows.pstree",
    "windows.cmdline",
    "windows.netstat",
    "windows.malfind",
    "windows.filescan",
    "windows.strings",
    "windows.dlllist"
]


class ProcessNode:

    def __init__(self, pid, ppid, name):

        self.pid = pid
        self.ppid = ppid
        self.name = name
        self.cmdline = ""
        self.children = []
        self.suspicious = False
        self.reasons = []


def serialize_tree(node):

    return {
        "pid": node.pid,
        "ppid": node.ppid,
        "name": node.name,
        "cmdline": node.cmdline,
        "suspicious": node.suspicious,
        "reasons": node.reasons,
        "children": [
            serialize_tree(child)
            for child in node.children
        ]
    }


SUSPICIOUS_PARENTS = [
    "cmd.exe",
    "powershell.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe"
]

SUSPICIOUS_PORTS = [
    4444,
    4445,
    1337,
    31337,
    8888,
    9999
]

SUSPICIOUS_RELATIONSHIPS = {
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("powershell.exe", "rundll32.exe"),
    ("mshta.exe", "cmd.exe"),
    ("wscript.exe", "powershell.exe"),
    ("explorer.exe", "powershell.exe"),
}


class VolatilityWrapper(BaseWrapper):

    def __init__(self):

        super().__init__("volatility3")

    def run(self, image_path: str) -> list:

        if not Path(image_path).exists():
            print(f"  [ERROR] Memory image not found: {image_path}")
            return []

        all_items = []

        volatility_commands = [
            ["vol"],
            ["python3", "-m", "volatility3"]
        ]

        working_command = None

        for base_cmd in volatility_commands:

            try_cmd = base_cmd + ["-h"]

            stdout, stderr, code = self.run_command(
                try_cmd,
                timeout=15
            )

            if code == 0:

                working_command = base_cmd
                break

        if not working_command:

            print(
                "  [ERROR] Could not locate "
                "working Volatility3 installation"
            )

            return []

        print(
            f"  [VOL] Using command: "
            f"{' '.join(working_command)}"
        )

        combined_output = ""

        for plugin in PLUGINS:

            print(f"\n  [VOL] Running {plugin}...")

            command = (
                working_command +
                ["-f", image_path, plugin]
            )

            stdout, stderr, code = self.run_command(
                command,
                input_files=[image_path],
                timeout=180
            )

            print(f"\n  [DEBUG] Return code: {code}")

            if stderr.strip():

                print(
                    f"\n  [DEBUG] STDERR:\n"
                    f"{stderr[:1000]}"
                )

            if stdout.strip():

                print(
                    f"\n  [DEBUG] STDOUT:\n"
                    f"{stdout[:1000]}"
                )

            # keep a combined corpus for regex-based extraction
            if stdout:
                combined_output += "\n" + stdout

            if code != 0:

                print(f"  [SKIP] {plugin} failed")

                continue

            if not stdout.strip():

                print(
                    f"  [SKIP] "
                    f"{plugin} produced empty output"
                )

                continue

            try:
                items = self._parse(plugin, stdout)
            except Exception as exc:
                print(f"  [SKIP] {plugin} parse failed: {exc}")
                continue

            print(
                f"  [VOL] {plugin} → "
                f"{len(items)} evidence items"
            )

            all_items.extend(items)

        # Optional plugin: dumpfiles can write many files to CWD when unfiltered,
        # so keep it opt-in for controlled investigations.
        if os.getenv("VOL_ENABLE_DUMPFILES", "").lower() in {"1", "true", "yes"}:
            plugin = "windows.dumpfiles"
            print(f"\n  [VOL] Running {plugin} (opt-in)...")
            command = working_command + ["-f", image_path, plugin]
            stdout, stderr, code = self.run_command(
                command,
                input_files=[image_path],
                timeout=240
            )
            if code == 0 and stdout.strip():
                try:
                    items = self._parse(plugin, stdout)
                    print(f"  [VOL] {plugin} -> {len(items)} evidence items")
                    all_items.extend(items)
                except Exception as exc:
                    print(f"  [SKIP] {plugin} parse failed: {exc}")

        # Optional plugin: yarascan requires explicit rules/file.
        yara_rules = os.getenv("VOL_YARA_RULES", "").strip()
        yara_file = os.getenv("VOL_YARA_FILE", "").strip()
        if yara_rules or yara_file:
            plugin = "windows.vadyarascan"
            print(f"\n  [VOL] Running {plugin} (configured)...")
            command = working_command + ["-f", image_path, plugin]
            can_run_yara = False
            if yara_file:
                if not Path(yara_file).exists():
                    print(f"  [SKIP] YARA file not found: {yara_file}")
                else:
                    command += ["--yara-file", yara_file]
                    can_run_yara = True
            else:
                command += ["--yara-rules", yara_rules]
                can_run_yara = True

            if can_run_yara:
                stdout, stderr, code = self.run_command(
                    command,
                    input_files=[image_path],
                    timeout=240
                )
                if code == 0 and stdout.strip():
                    try:
                        items = self._parse(plugin, stdout)
                        print(f"  [VOL] {plugin} -> {len(items)} evidence items")
                        all_items.extend(items)
                    except Exception as exc:
                        print(f"  [SKIP] {plugin} parse failed: {exc}")

        # Feed windows.strings with a real strings file generated from the
        # image when possible. This avoids volatility's internal strings
        # collector returning empty results when no strings source is set.
        strings_path = None
        strings_cleanup = None
        try:
            strings_path, strings_cleanup = self._build_strings_file(image_path)
            if strings_path and Path(strings_path).exists():
                plugin = "windows.strings"
                print(f"\n  [VOL] Running {plugin} with generated strings file...")
                command = working_command + ["-f", image_path, plugin, "--strings-file", strings_path]
                stdout, stderr, code = self.run_command(
                    command,
                    input_files=[image_path, strings_path],
                    timeout=240,
                )
                if code == 0 and stdout.strip():
                    try:
                        items = self._parse(plugin, stdout)
                        print(f"  [VOL] {plugin} -> {len(items)} evidence items")
                        all_items.extend(items)
                    except Exception as exc:
                        print(f"  [SKIP] {plugin} parse failed: {exc}")
        finally:
            if strings_cleanup is not None:
                try:
                    strings_cleanup.cleanup()
                except Exception:
                    pass

        # Run a lightweight string/IOC extraction over all plugin output
        try:
            extracted = self._extract_strings(combined_output)
            if extracted:
                print(f"  [VOL] Extracted {len(extracted)} string IOCs")
                all_items.extend(extracted)
        except Exception as exc:
            print(f"  [VOL] string extraction failed: {exc}")

        return all_items

    def _parse(self, plugin: str, output: str) -> list:
        lines = [
            l for l in output.strip().splitlines()
            if l.strip()
        ]

        if plugin == "windows.pslist":

            return self._parse_pslist(lines)

        elif plugin == "windows.pstree":

            return self._parse_pstree(lines)

        elif plugin == "windows.cmdline":

            return self._parse_cmdline(lines)

        elif plugin == "windows.netstat":

            return self._parse_netstat(lines)

        elif plugin == "windows.malfind":

            return self._parse_malfind(lines)

        elif plugin == "windows.filescan":

            return self._parse_filescan(lines)

        elif plugin == "windows.dumpfiles":

            return self._parse_dumpfiles(lines)

        elif plugin in {"windows.vadyarascan", "yarascan.YaraScan", "windows.yarascan"}:

            return self._parse_yarascan(lines)

        elif plugin == "windows.strings":

            return self._parse_strings(lines)

        elif plugin == "windows.dlllist":

            return self._parse_dlllist(lines)

        return []

    def _build_strings_file(self, image_path: str):
        """
        Run the system `strings` utility against the raw image to produce a
        temporary strings file suitable for feeding to volatility's
        `windows.strings --strings-file` option. Returns (path, cleanup)
        where cleanup is an object with a `cleanup()` method that removes
        the tempfile. Returns (None, None) on failure.
        """

        try:
            stdout, stderr, code = self.run_command(
                ["strings", "-a", "-n", "8", image_path],
                input_files=[image_path],
                timeout=120,
            )
        except Exception:
            return None, None

        if code != 0 or not stdout.strip():
            return None, None

        tmp = tempfile.NamedTemporaryFile(delete=False, prefix="af_strings_", suffix=".txt", mode="w", encoding="utf-8")
        try:
            tmp.write(stdout)
            tmp.flush()
            tmp.close()
        except Exception:
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
            return None, None

        class _Cleanup:
            def __init__(self, path):
                self._path = path

            def cleanup(self):
                try:
                    if os.path.exists(self._path):
                        os.unlink(self._path)
                except Exception:
                    pass

        return tmp.name, _Cleanup(tmp.name)

    def _parse_pslist(self, lines: list) -> list:

        items = []

        for line in lines:

            if (
                "Volatility 3 Framework" in line or
                ("PID" in line and "PPID" in line)
            ):
                continue

            parts = line.split()

            if len(parts) < 3:
                continue

            try:

                pid = parts[0]
                ppid = parts[1]
                name = parts[2]

                safe_name = (
                    name.lower()
                    .replace('.', '_')
                    .replace('@', '')
                )

                severity = (
                    "high"
                    if any(
                        s in name.lower()
                        for s in SUSPICIOUS_PARENTS
                    )
                    else "low"
                )

                items.append(
                    self.make_evidence_item(
                        artifact_id=f"proc_{pid}_{safe_name}",
                        evidence_type="process",
                        value=f"{name} (PID:{pid} PPID:{ppid})",
                        severity=severity,
                        confidence=0.75
                    )
                )

            except Exception:
                continue

        return items

    def _parse_pstree(self, lines: list) -> list:

        items = []

        processes = {}

        for line in lines:

            if (
                "Volatility 3 Framework" in line or
                ("PID" in line and "PPID" in line)
            ):
                continue

            clean = line.replace("*", "").strip()

            parts = clean.split()

            if len(parts) < 3:
                continue

            try:

                pid = int(parts[0])
                ppid = int(parts[1])
                name = parts[2]

                node = ProcessNode(pid, ppid, name)

                processes[pid] = node

            except Exception:
                continue

        relation_items = []

        for proc in processes.values():

            if proc.ppid in processes:

                parent = processes[proc.ppid]

                parent.children.append(proc)

                pair = (
                    parent.name.lower(),
                    proc.name.lower()
                )

                if pair in SUSPICIOUS_RELATIONSHIPS:

                    proc.suspicious = True

                    proc.reasons.append(
                        f"Suspicious lineage: "
                        f"{parent.name} -> {proc.name}"
                    )

                    relation_items.append(
                        self.make_evidence_item(
                            artifact_id=(
                                f"relation_{parent.pid}_{proc.pid}"
                            ),
                            evidence_type="process_relation",
                            value=(
                                f"Suspicious parent-child "
                                f"relationship: "
                                f"{parent.name} -> {proc.name}"
                            ),
                            severity="critical",
                            confidence=0.92,
                            linked_artifacts=[
                                f"proc_{parent.pid}",
                                f"proc_{proc.pid}"
                            ]
                        )
                    )

        roots = []

        for proc in processes.values():

            if proc.ppid not in processes:
                roots.append(proc)

        tree_items = []

        for root in roots:

            serialized_tree = serialize_tree(root)

            tree_items.append(
                self.make_evidence_item(
                    artifact_id=f"process_tree_{root.pid}",
                    evidence_type="process_tree",
                    value=json.dumps(
                        serialized_tree,
                        indent=2
                    ),
                    severity="medium",
                    confidence=0.95,
                    linked_artifacts=[]
                )
            )

        items.extend(tree_items)
        items.extend(relation_items)

        return items

    def _parse_cmdline(self, lines: list) -> list:

        items = []

        suspicious_keywords = [
            "-enc",
            "-encodedcommand",
            "invoke-",
            "downloadstring",
            "iex",
            "bypass",
            "hidden",
            "frombase64"
        ]

        for line in lines:

            lower = line.lower()

            if any(
                kw in lower
                for kw in suspicious_keywords
            ):

                parts = line.split()

                pid = (
                    parts[1]
                    if len(parts) > 1
                    else "unknown"
                )

                items.append(
                    self.make_evidence_item(
                        artifact_id=f"cmdline_{pid}",
                        evidence_type="commandline",
                        value=line.strip(),
                        severity="high",
                        confidence=0.90
                    )
                )

        return items

    def _parse_netstat(self, lines: list) -> list:

        items = []

        for line in lines:

            if (
                "Volatility 3 Framework" in line or
                "Offset" in line
            ):
                continue

            parts = line.split()

            if len(parts) < 8:
                continue

            try:

                proto = parts[1]
                local = f"{parts[2]}:{parts[3]}"
                foreign = f"{parts[4]}:{parts[5]}"
                state = parts[6]
                pid = parts[7]

                port = int(parts[5])

                severity = (
                    "high"
                    if port in SUSPICIOUS_PORTS
                    else "medium"
                )

                items.append(
                    self.make_evidence_item(
                        artifact_id=f"net_{pid}_{port}",
                        evidence_type="network_connection",
                        value=(
                            f"{proto} "
                            f"{local} -> {foreign} "
                            f"[{state}] PID:{pid}"
                        ),
                        severity=severity,
                        confidence=0.80,
                        linked_artifacts=[
                            f"proc_{pid}"
                        ]
                    )
                )

            except Exception:
                continue

        return items

    def _parse_malfind(self, lines: list) -> list:

        items = []

        grouped_regions = {}
        current_pid = None

        def _has_pe_signature(text: str) -> bool:

            lowered = text.lower()

            return (
                "shellcode" in lowered or
                " mz" in lowered or
                lowered.startswith("mz") or
                "4d 5a" in lowered or
                "4d5a" in lowered or
                "50 45 00 00" in lowered
            )

        for line in lines:

            stripped = line.strip()

            if (
                not stripped or
                "Volatility 3 Framework" in stripped or
                ("PID" in stripped and "Process" in stripped) or
                "Disasm" in stripped
            ):

                if "Volatility 3 Framework" in stripped or "PID" in stripped:
                    current_pid = None

                continue

            parts = stripped.split()

            if len(parts) < 2:
                continue

            if parts[0].isdigit():
                try:
                    pid = parts[0]
                    name = parts[1]

                    flags = " ".join(parts[2:]).lower()
                    current_pid = pid

                    if pid not in grouped_regions:

                        grouped_regions[pid] = {
                            "name": name,
                            "count": 0,
                            "has_rwx": False,
                            "has_pe": False
                        }

                    grouped_regions[pid]["count"] += 1

                    if (
                        "rwx" in flags or
                        "rw-x" in flags or
                        "rx" in flags or
                        "page_execute" in flags or
                        "page_exec" in flags or
                        ("execute" in flags and "write" in flags)
                    ):
                        grouped_regions[pid]["has_rwx"] = True

                    if _has_pe_signature(stripped) or "mz" in flags or "pe" in flags:
                        grouped_regions[pid]["has_pe"] = True
                except Exception:
                    pass

                continue

            if current_pid and current_pid in grouped_regions:

                # Continuation lines often carry MZ/hexdump markers.
                if _has_pe_signature(stripped):
                    grouped_regions[current_pid]["has_pe"] = True

        for pid, info in grouped_regions.items():

            name = info.get("name", "unknown")
            has_rwx = info.get("has_rwx", False)
            has_pe = info.get("has_pe", False)
            corroborated = has_rwx and has_pe

            if has_rwx and has_pe:
                severity = "critical"
                confidence = 0.92
                reasons = ["RWX region and embedded PE/shellcode detected"]
            elif has_rwx or has_pe:
                severity = "high"
                confidence = 0.86
                reasons = [
                    "RWX region detected" if has_rwx else "Embedded PE/shellcode detected"
                ]
            else:
                severity = "medium"
                confidence = 0.70
                reasons = ["Injected regions detected (no RWX/PE signature)"]

            system_allowlist = {
                "explorer.exe",
                "chrome.exe",
                "csrss.exe",
                "winlogon.exe",
                "wmiprvse.exe",
                "svchost.exe",
                "system"
            }

            if name.lower() in system_allowlist and not corroborated and severity in {"critical", "high"}:
                severity = "medium"
                confidence = 0.65
                reasons.append("Process is common system process without corroborating IOC: down-ranked")
            elif name.lower() in system_allowlist and corroborated:
                reasons.append("Corroborated by another IOC; system-process down-rank skipped")

            items.append(
                self.make_evidence_item(
                    artifact_id=f"malfind_{pid}",
                    evidence_type="injected_code",
                    value=(
                        f"Injected memory regions detected in {info['name']} "
                        f"(PID:{pid}). Reasons: {'; '.join(reasons)}"
                    ),
                    severity=severity,
                    confidence=confidence,
                    linked_artifacts=[f"proc_{pid}"]
                )
            )

        return items

    def _parse_dlllist(self, lines: list) -> list:

        items = []

        suspicious_dlls = [
            "unknown",
            "temp",
            "appdata\\roaming",
            "programdata"
        ]

        for line in lines:

            lower = line.lower()

            if any(
                s in lower
                for s in suspicious_dlls
            ):

                items.append(
                    self.make_evidence_item(
                        artifact_id=(
                            f"dll_{str(uuid.uuid4())[:8]}"
                        ),
                        evidence_type="suspicious_dll",
                        value=line.strip(),
                        severity="high",
                        confidence=0.78
                    )
                )

        return items

    def _parse_filescan(self, lines: list) -> list:

        import re

        items = []
        seen = set()

        # Markers that indicate staging/execution locations or payloads.
        suspicious_markers = [
            "\\appdata\\",
            "\\temp\\",
            "\\users\\public\\",
            "\\programdata\\",
            "\\startup",
            "\\runonce",
            "\\tasks\\",
            "\\intel\\",
            ".onion",
            ".ps1",
            ".vbs",
            ".js",
            ".hta",
            ".bat",
            ".cmd"
        ]

        def _has_suspicious_staging_path(path: str) -> bool:

            lowered = path.lower().replace("/", "\\")
            segments = [segment for segment in lowered.split("\\") if segment]

            for index, segment in enumerate(segments[:-1]):
                if segment == "intel" and index + 1 < len(segments):
                    child = segments[index + 1]

                    if (
                        len(child) >= 12 and
                        re.match(r"^[a-z0-9]+$", child) and
                        re.search(r"[a-z]", child) and
                        re.search(r"\d", child)
                    ):
                        return True

            return False

        # Extensions that are common system binaries; only consider them
        # suspicious when they appear in staging/execution paths above.
        binary_exts = {".dll", ".exe"}

        for line in lines:

            # crude heuristic: look for absolute paths (Windows backslash or Unix slash)
            if "\\" in line or "/" in line:

                parts = line.split()

                # prefer the last token if it looks like a path
                candidate = parts[-1]

                if "\\" in candidate or "/" in candidate:

                    normalized = candidate.lower()

                    if normalized in seen:
                        continue

                    # relevance gate to avoid flooding with low-signal paths.
                    marker_hits = sum(1 for marker in suspicious_markers if marker in normalized)

                    if marker_hits == 0 and _has_suspicious_staging_path(normalized):
                        marker_hits = 1

                    # If this looks like a plain system binary (dll/exe) but is
                    # not located in a staging/execution path, skip it to avoid
                    # mass noise from benign system files.
                    ext = ""
                    try:
                        ext = Path(normalized).suffix
                    except Exception:
                        ext = ""

                    if ext in binary_exts and marker_hits == 0:
                        continue

                    if marker_hits == 0:
                        continue

                    seen.add(normalized)

                    if marker_hits >= 2:
                        severity = "high"
                        confidence = 0.90
                    else:
                        severity = "medium"
                        confidence = 0.80

                    items.append(
                        self.make_evidence_item(
                            artifact_id=(
                                f"file_{str(uuid.uuid4())[:8]}"
                            ),
                            evidence_type="file_artifact",
                            value=candidate,
                            severity=severity,
                            confidence=confidence
                        )
                    )

        return items

    def _parse_dumpfiles(self, lines: list) -> list:

        import re

        items = []
        seen = set()

        suspicious_markers = [
            "\\appdata\\",
            "\\temp\\",
            "\\users\\public\\",
            "\\programdata\\",
            ".exe",
            ".dll",
            ".ps1",
            ".vbs",
            ".js",
            ".bat",
            ".cmd",
            ".hta"
        ]

        for line in lines:

            stripped = line.strip()

            if not stripped:
                continue

            if (
                "Volatility 3 Framework" in stripped or
                "Progress:" in stripped or
                stripped.startswith("Cache")
            ):
                continue

            # Volatility dumpfiles output is tabular:
            # Cache  FileObject  FileName  Result
            cols = re.split(r"\s{2,}", stripped)

            if len(cols) < 4:
                continue

            file_name = cols[2].strip()
            result = cols[3].strip()

            if not file_name or file_name in {"N/A", "-"}:
                continue

            if not result or result in {"N/A", "-"}:
                continue

            lowered_name = file_name.lower()
            lowered_result = result.lower()

            if lowered_name in seen:
                continue

            if not any(marker in lowered_name for marker in suspicious_markers):
                continue

            # Skip rows where extraction did not actually produce a file.
            if "error" in lowered_result or "failed" in lowered_result:
                continue

            seen.add(lowered_name)

            items.append(
                self.make_evidence_item(
                    artifact_id=f"dumpfile_{str(uuid.uuid4())[:8]}",
                    evidence_type="extracted_file",
                    value=f"{file_name} -> {result}",
                    severity="high",
                    confidence=0.90
                )
            )

        return items

    def _parse_yarascan(self, lines: list) -> list:

        items = []

        for line in lines:

            cleaned = line.strip()

            if (
                not cleaned or
                "Volatility 3 Framework" in cleaned or
                "Progress:" in cleaned
            ):
                continue

            if "Offset" in cleaned and "Rule" in cleaned:
                continue

            items.append(
                self.make_evidence_item(
                    artifact_id=f"yara_{str(uuid.uuid4())[:8]}",
                    evidence_type="yara_match",
                    value=cleaned,
                    severity="high",
                    confidence=0.90
                )
            )

        return items

    def _parse_strings(self, lines: list) -> list:

        corpus = "\n".join(lines)

        return self._extract_strings(corpus)

    def _extract_strings(self, corpus: str) -> list:

        import re

        items = []

        if not corpus:
            return items

        seen = set()

        valid_tlds = {
            "com", "net", "org", "info", "biz", "us", "uk", "ru", "cn", 
            "onion", "io", "cc", "ws", "xyz", "co", "me", "to", "tv", "eu"
        }

        def _add_item(value: str, evidence_type: str, severity: str, confidence: float, artifact_prefix: str):
            normalized = value.lower()
            if normalized in seen:
                return

            seen.add(normalized)
            items.append(
                self.make_evidence_item(
                    artifact_id=f"{artifact_prefix}_{str(uuid.uuid4())[:8]}",
                    evidence_type=evidence_type,
                    value=value,
                    severity=severity,
                    confidence=confidence
                )
            )

        def _base58_decode(value: str):

            alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
            decoded = bytearray()
            num = 0

            for char in value:
                index = alphabet.find(char)
                if index == -1:
                    return None
                num = num * 58 + index

            while num > 0:
                num, remainder = divmod(num, 256)
                decoded.insert(0, remainder)

            leading_zeros = len(value) - len(value.lstrip("1"))
            return bytearray(b"\x00" * leading_zeros) + decoded

        def _is_valid_btc_address(value: str) -> bool:
            if not re.fullmatch(r"^[13][1-9A-HJ-NP-Za-km-z]{25,34}$", value):
                return False

            decoded = _base58_decode(value)
            if not decoded or len(decoded) < 5:
                return False

            payload = bytes(decoded[:-4])
            checksum = bytes(decoded[-4:])
            digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

            return digest == checksum and len(payload) == 21

        for match in re.finditer(r"[a-z0-9]{16,56}\.onion", corpus, flags=re.IGNORECASE):

            _add_item(match.group(0).lower(), "suspicious_domain", "high", 0.95, "ioc")

        for match in re.finditer(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", corpus):

            candidate = match.group(0)

            if _is_valid_btc_address(candidate):
                _add_item(candidate, "suspicious_crypto", "high", 0.93, "btc")

        for match in re.finditer(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", corpus):

            _add_item(match.group(0), "email_address", "medium", 0.85, "email")

        registry_patterns = [
            r"(?:HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKCR|HKEY_CLASSES_ROOT|HKU|HKEY_USERS)\\[^\s\"']+",
            r"\\Registry\\Machine\\[^\s\"']+",
            r"\\Registry\\User\\[^\s\"']+",
        ]

        for pattern in registry_patterns:

            for match in re.finditer(pattern, corpus, flags=re.IGNORECASE):

                _add_item(match.group(0), "registry_key", "medium", 0.88, "reg")

        domain_pattern = re.compile(
            r"(?<![@\\])\b(?:[a-z0-9-]{1,63}\.)+(?P<tld>[a-z]{2,24})\b",
            flags=re.IGNORECASE,
        )

        for match in domain_pattern.finditer(corpus):

            value = match.group(0).lower()
            tld = match.group("tld").lower()

            if tld not in valid_tlds:
                continue

            labels = value.split(".")
            if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
                continue

            _add_item(value, "suspicious_domain", "medium", 0.80, "dom")

        return items


if __name__ == "__main__":

    import sys

    if len(sys.argv) < 2:

        print(
            "Usage: python -m "
            "src.wrappers.volatility_wrapper "
            "<memory.dmp>"
        )

        sys.exit(1)

    wrapper = VolatilityWrapper()

    items = wrapper.run(sys.argv[1])

    output = {
        "tool": "volatility3",
        "items": items
    }

    os.makedirs("output/raw", exist_ok=True)

    with open(
        "output/raw/volatility3_output.json",
        "w"
    ) as f:

        json.dump(output, f, indent=2)

    print(
        f"\n[DONE] {len(items)} "
        f"evidence items saved to "
        f"output/raw/volatility3_output.json"
    )
