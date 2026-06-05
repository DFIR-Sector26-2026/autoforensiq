import os
import json
import uuid

from src.wrappers.base_wrapper import BaseWrapper

PLUGINS = [
    "windows.pslist",
    "windows.pstree",
    "windows.cmdline",
    "windows.netstat",
    "windows.malfind",
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


def summarise_tree(node, depth=0, max_depth=5):
    """Human-readable indented process-tree summary used as the evidence value."""

    if not node:
        return ""

    if depth > max_depth:
        return ""

    lines = [
        f"{'  ' * depth}{node.name} (PID:{node.pid})"
    ]

    for child in node.children:

        child_text = summarise_tree(
            child,
            depth + 1,
            max_depth
        )

        if child_text:
            lines.append(child_text)

    return "\n".join(lines)



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

        if not os.path.exists(image_path):

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

            tree_items.append(
                self.make_evidence_item(
                    artifact_id=f"process_tree_{root.pid}",
                    evidence_type="process_tree",
                    value=summarise_tree(root),
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

            line = line.strip()

            if (
                not line or
                "Volatility 3 Framework" in line or
                ("PID" in line and "Process" in line)
            ):
                continue

            lower = line.lower()

            if (
                "unsatisfied requirement" in lower or
                "unable to validate" in lower or
                "traceback" in lower
            ):
                items.append(
                    self.make_evidence_item(
                        artifact_id=f"cmdline_warning_{len(items)}",
                        evidence_type="parser_warning",
                        value=line,
                        severity="medium",
                        confidence=1.0
                    )
                )
                continue

            parts = line.split()

            pid = parts[0] if len(parts) > 0 else "unknown"

            if len(parts) == 1:
                items.append(
                    self.make_evidence_item(
                        artifact_id=f"cmdline_empty_{pid}",
                        evidence_type="commandline_missing",
                        value=line,
                        severity="low",
                        confidence=1.0
                    )
                )
                continue

            process_name = parts[1]

            cmdline = line

            if len(parts) > 2:
                cmdline = line.split(process_name, 1)[1].strip()

            severity = (
                "high"
                if any(
                    kw in lower
                    for kw in suspicious_keywords
                )
                else "low"
            )

            confidence = (
                0.90
                if severity == "high"
                else 0.60
            )

            items.append(
                self.make_evidence_item(
                    artifact_id=f"cmdline_{pid}",
                    evidence_type="commandline",
                    value=cmdline,
                    severity=severity,
                    confidence=confidence
                )
            )

        return items


    def _parse_netstat(self, lines: list) -> list:

        items = []

        for line in lines:

            line = line.strip()

            if (
                not line or
                "Volatility 3 Framework" in line or
                "Offset" in line
            ):
                continue

            parts = line.split()

            if len(parts) < 8:
                continue

            try:

                proto = parts[1]
                local_addr = parts[2]
                local_port = parts[3]
                foreign_addr = parts[4]
                foreign_port = parts[5]
                pid = parts[7]

                port = (
                    int(local_port)
                    if str(local_port).isdigit()
                    else 0
                )

                severity = (
                    "high"
                    if port in SUSPICIOUS_PORTS
                    else "low"
                )

                items.append(
                    self.make_evidence_item(
                        artifact_id=(
                            f"netstat_"
                            f"{pid}_"
                            f"{local_addr.replace('.', '_')}_"
                            f"{local_port}"
                        ),
                        evidence_type="network_connection",
                        value=(
                            f"{proto} "
                            f"{local_addr}:{local_port} -> "
                            f"{foreign_addr}:{foreign_port} "
                            f"(PID:{pid})"
                        ),
                        severity=severity,
                        confidence=0.75
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

                if pid not in grouped_regions:

                    grouped_regions[pid] = {
                        "name": name,
                        "count": 0
                    }

                grouped_regions[pid]["count"] += 1

            except Exception:
                continue

        for pid, info in grouped_regions.items():

            items.append(
                self.make_evidence_item(
                    artifact_id=f"malfind_{pid}",
                    evidence_type="injected_code",
                    value=(
                        f"Injected memory regions "
                        f"detected in "
                        f"{info['name']} "
                        f"(PID:{pid})"
                    ),
                    severity="critical",
                    confidence=0.92
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
