import os
import json
import uuid
from pathlib import Path

from src.wrappers.base_wrapper import BaseWrapper

PLUGINS = [
    "windows.pslist",
    "windows.pstree",
    "windows.cmdline",
    "windows.netstat",
    "windows.malfind",
    "windows.filescan",
    "windows.dumpfiles",
    "windows.yarascan",
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

            # keep a combined corpus for regex-based extraction
            if stdout:
                combined_output += "\n" + stdout

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

            if code != 0:

                print(f"  [SKIP] {plugin} failed")

                continue

            if not stdout.strip():

                print(
                    f"  [SKIP] "
                    f"{plugin} produced empty output"
                )

                continue

            items = self._parse(plugin, stdout)

            print(
                f"  [VOL] {plugin} → "
                f"{len(items)} evidence items"
            )

            all_items.extend(items)

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

        elif plugin == "windows.yarascan":

            return self._parse_yarascan(lines)

        elif plugin == "windows.dlllist":

            return self._parse_dlllist(lines)

        return []

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

        for line in lines:

            if (
                "Volatility 3 Framework" in line or
                ("PID" in line and "Process" in line) or
                "Disasm" in line
            ):
                continue

            parts = line.split()

            if len(parts) < 2:
                continue

            if not parts[0].isdigit():
                continue

            if len(parts) < 2:
                continue

            if ".exe" not in parts[1].lower():
                continue

            try:

                pid = parts[0]
                name = parts[1]

                flags = " ".join(parts[2:]).lower()

                if pid not in grouped_regions:

                    grouped_regions[pid] = {
                        "name": name,
                        "count": 0,
                        "has_rwx": False,
                        "has_pe": False
                    }

                grouped_regions[pid]["count"] += 1

                # heuristics: detect RWX regions or embedded PE/shellcode markers
                if "rwx" in flags or "rw-x" in flags or "rx" in flags:
                    grouped_regions[pid]["has_rwx"] = True

                if "mz" in flags or "pe" in flags or "shellcode" in flags:
                    grouped_regions[pid]["has_pe"] = True

            except Exception:
                continue

        for pid, info in grouped_regions.items():

            # determine severity with gating
            name = info.get("name", "unknown")
            has_rwx = info.get("has_rwx", False)
            has_pe = info.get("has_pe", False)

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
                reasons = ["Injected regions detected (no RWX/PE signature)" ]

            # down-rank for common system processes unless corroborated
            system_allowlist = {
                "explorer.exe",
                "chrome.exe",
                "csrss.exe",
                "winlogon.exe",
                "wmiprvse.exe",
                "svchost.exe"
            }

            if name.lower() in system_allowlist and severity == "critical":
                severity = "medium"
                confidence = 0.75
                reasons.append("Process is common system process: down-ranked")
            elif name.lower() in system_allowlist and severity == "high":
                severity = "medium"
                confidence = 0.65
                reasons.append("Process is common system process: down-ranked")

            items.append(
                self.make_evidence_item(
                    artifact_id=f"malfind_{pid}",
                    evidence_type="injected_code",
                    value=(
                        f"Injected memory regions detected in {info['name']} (PID:{pid})"
                    ),
                    severity=severity,
                    confidence=confidence,
                    linked_artifacts=[f"proc_{pid}"],
                    # include reasons to aid downstream gating/rescoring
                    extra={"reasons": reasons}
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

        items = []

        for line in lines:

            lower = line.lower()

            # crude heuristic: look for absolute paths
            if "\\\" in line or "/" in line:

                parts = line.split()

                # prefer the last token if it looks like a path
                candidate = parts[-1]

                if "\\" in candidate or "/" in candidate:

                    items.append(
                        self.make_evidence_item(
                            artifact_id=(
                                f"file_{str(uuid.uuid4())[:8]}"
                            ),
                            evidence_type="file_artifact",
                            value=candidate,
                            severity="medium",
                            confidence=0.85
                        )
                    )

        return items

    def _parse_dumpfiles(self, lines: list) -> list:

        items = []

        for line in lines:

            if line.strip().startswith("Saved file") or "->" in line:

                # try to extract filename after arrow or prefix
                if "->" in line:
                    candidate = line.split("->")[-1].strip()
                else:
                    candidate = line.split()[-1]

                items.append(
                    self.make_evidence_item(
                        artifact_id=f"dumpfile_{str(uuid.uuid4())[:8]}",
                        evidence_type="extracted_file",
                        value=candidate,
                        severity="medium",
                        confidence=0.88
                    )
                )

        return items

    def _parse_yarascan(self, lines: list) -> list:

        items = []

        for line in lines:

            # yara output typically shows rule names
            if line.strip():

                items.append(
                    self.make_evidence_item(
                        artifact_id=f"yara_{str(uuid.uuid4())[:8]}",
                        evidence_type="yara_match",
                        value=line.strip(),
                        severity="high",
                        confidence=0.90
                    )
                )

        return items

    def _extract_strings(self, corpus: str) -> list:

        import re

        items = []

        if not corpus:
            return items

        seen = set()

        # onion addresses
        for m in re.findall(r"[a-z2-7]{16,56}\.onion", corpus, flags=re.IGNORECASE):
            v = m.lower()
            if v in seen:
                continue
            seen.add(v)
            items.append(
                self.make_evidence_item(
                    artifact_id=f"ioc_{str(uuid.uuid4())[:8]}",
                    evidence_type="suspicious_domain",
                    value=v,
                    severity="high",
                    confidence=0.95
                )
            )

        # bitcoin/wallet-like addresses
        for m in re.findall(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", corpus):
            if m in seen:
                continue
            seen.add(m)
            items.append(
                self.make_evidence_item(
                    artifact_id=f"btc_{str(uuid.uuid4())[:8]}",
                    evidence_type="suspicious_crypto",
                    value=m,
                    severity="high",
                    confidence=0.93
                )
            )

        # emails
        for m in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", corpus):
            if m in seen:
                continue
            seen.add(m)
            items.append(
                self.make_evidence_item(
                    artifact_id=f"email_{str(uuid.uuid4())[:8]}",
                    evidence_type="email_address",
                    value=m,
                    severity="medium",
                    confidence=0.85
                )
            )

        # domains (coarse)
        for m in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", corpus, flags=re.IGNORECASE):
            v = m.lower()
            if v in seen:
                continue
            seen.add(v)
            items.append(
                self.make_evidence_item(
                    artifact_id=f"dom_{str(uuid.uuid4())[:8]}",
                    evidence_type="suspicious_domain",
                    value=v,
                    severity="medium",
                    confidence=0.80
                )
            )

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
