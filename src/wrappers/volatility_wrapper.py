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

        if not os.path.exists(image_path):
            print(f"  [ERROR] Memory image not found: {image_path}")
            return []

        all_items = []

        # --------------------------------------------------
        # Try multiple volatility execution methods
        # --------------------------------------------------

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
            print("  [ERROR] Could not locate working Volatility3 installation")
            return []

        print(f"  [VOL] Using command: {' '.join(working_command)}")

        # --------------------------------------------------
        # Execute plugins
        # --------------------------------------------------

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

            # DEBUG OUTPUT
            print(f"\n  [DEBUG] Return code: {code}")

            if stderr.strip():
                print(f"\n  [DEBUG] STDERR:\n{stderr[:1000]}")

            if stdout.strip():
                print(f"\n  [DEBUG] STDOUT:\n{stdout[:1000]}")

            if code != 0:
                print(f"  [SKIP] {plugin} failed")
                continue

            if not stdout.strip():
                print(f"  [SKIP] {plugin} produced empty output")
                continue

            items = self._parse(plugin, stdout)

            print(f"  [VOL] {plugin} → {len(items)} evidence items")

            all_items.extend(items)

        return all_items

    def _parse(self, plugin: str, output: str) -> list:

        lines = [
            l for l in output.strip().splitlines()
            if l.strip()
        ]

        data_lines = lines

        if plugin == "windows.pslist":
            return self._parse_pslist(data_lines)

        elif plugin == "windows.pstree":
            return self._parse_pstree(data_lines)

        elif plugin == "windows.cmdline":
            return self._parse_cmdline(data_lines)

        elif plugin == "windows.netstat":
            return self._parse_netstat(data_lines)

        elif plugin == "windows.malfind":
            return self._parse_malfind(data_lines)

        elif plugin == "windows.dlllist":
            return self._parse_dlllist(data_lines)

        return []

    def _parse_pslist(self, lines: list) -> list:

        items = []

        for line in lines:

            parts = line.split()

            if len(parts) < 3:
                continue

            try:
                pid = parts[1]
                ppid = parts[2]
                name = parts[0]

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

        # --------------------------------------------------
        # Parse Process Nodes
        # --------------------------------------------------

        for line in lines:

            parts = line.split()

            if len(parts) < 3:
                continue

            try:
                name = parts[0].lstrip("*. ")
                pid = int(parts[1])
                ppid = int(parts[2])

                node = ProcessNode(pid, ppid, name)

                processes[pid] = node

            except Exception:
                continue

        # --------------------------------------------------
        # Build Relationships
        # --------------------------------------------------

        relation_items = []

        for proc in processes.values():

            if proc.ppid in processes:

                parent = processes[proc.ppid]

                parent.children.append(proc)

                pair = (
                    parent.name.lower(),
                    proc.name.lower()
                )

                # Suspicious lineage detection
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

        # --------------------------------------------------
        # Find Root Processes
        # --------------------------------------------------

        roots = []

        for proc in processes.values():

            if proc.ppid not in processes:
                roots.append(proc)

        # --------------------------------------------------
        # Create Recursive Tree Evidence
        # --------------------------------------------------

        tree_items = []

        for root in roots:

            tree_items.append(
                self.make_evidence_item(
                    artifact_id=f"process_tree_{root.pid}",
                    evidence_type="process_tree",
                    value=serialize_tree(root),
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

            if any(kw in lower for kw in suspicious_keywords):

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

            parts = line.split()

            if len(parts) < 4:
                continue

            try:
                proto = parts[0]
                local = parts[1]
                foreign = parts[2]

                state = (
                    parts[3]
                    if len(parts) > 3
                    else ""
                )

                pid = (
                    parts[-1]
                    if parts[-1].isdigit()
                    else "unknown"
                )

                port = (
                    int(foreign.split(":")[-1])
                    if ":" in foreign
                    else 0
                )

                severity = (
                    "high"
                    if port in SUSPICIOUS_PORTS
                    else "medium"
                )

                if foreign not in [
                    "0.0.0.0:0",
                    "*:*",
                    ":::*"
                ]:

                    items.append(
                        self.make_evidence_item(
                            artifact_id=f"net_{pid}_{port}",
                            evidence_type="network_connection",
                            value=(
                                f"{proto} "
                                f"{local} → {foreign} "
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

            parts = line.split()

            if len(parts) < 2:
                continue

            try:
                pid = (
                    parts[1]
                    if parts[1].isdigit()
                    else "unknown"
                )

                name = parts[0]

                hex_tokens = [
                    p for p in parts
                    if len(p) == 2 and all(
                        c in '0123456789abcdefABCDEF'
                        for c in p
                    )
                ]

                # Ignore null-byte regions
                if (
                    len(hex_tokens) >= 8 and
                    all(h == '00' for h in hex_tokens[:8])
                ):
                    continue

                if pid not in grouped_regions:

                    grouped_regions[pid] = {
                        "name": name,
                        "count": 0
                    }

                grouped_regions[pid]["count"] += 1

            except Exception:
                continue

        # Aggregate suspicious regions
        for pid, info in grouped_regions.items():

            items.append(
                self.make_evidence_item(
                    artifact_id=f"malfind_{pid}",
                    evidence_type="injected_code",
                    value=(
                        f"Injected memory regions "
                        f"detected in "
                        f"{info['name']} "
                        f"(PID:{pid}) — "
                        f"{info['count']} suspicious regions"
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
        "output/raw/volatility_output.json",
        "w"
    ) as f:

        json.dump(output, f, indent=2)

    print(
        f"\n[DONE] {len(items)} "
        f"evidence items saved to "
        f"output/raw/volatility_output.json"
    )
