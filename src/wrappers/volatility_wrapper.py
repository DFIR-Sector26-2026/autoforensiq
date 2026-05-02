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

SUSPICIOUS_PARENTS = ["cmd.exe", "powershell.exe", "wscript.exe",
                       "cscript.exe", "mshta.exe", "regsvr32.exe"]
SUSPICIOUS_PORTS   = [4444, 4445, 1337, 31337, 8888, 9999]

class VolatilityWrapper(BaseWrapper):
    def __init__(self):
        super().__init__("volatility3")

    def run(self, image_path: str) -> list:
        if not os.path.exists(image_path):
            print(f"  [ERROR] Memory image not found: {image_path}")
            return []

        all_items = []
        for plugin in PLUGINS:
            print(f"\n  [VOL] Running {plugin}...")
            stdout, stderr, code = self.run_command(
                ["./venv/bin/vol", "-f", image_path, plugin],   # ✅ FIXED LINE
                input_files=[image_path],
                timeout=120
            )
            if code != 0 or not stdout.strip():
                print(f"  [SKIP] {plugin} produced no output")
                continue
            items = self._parse(plugin, stdout)
            print(f"  [VOL] {plugin} → {len(items)} evidence items")
            all_items.extend(items)

        return all_items

    def _parse(self, plugin: str, output: str) -> list:
        lines = [l for l in output.strip().splitlines() if l.strip()]
        data_lines = [l for l in lines if l and (l[0].isdigit() or l[0] == '*')]

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
                pid  = parts[1]
                ppid = parts[2]
                name = parts[0]
                severity = "high" if any(s in name.lower()
                           for s in SUSPICIOUS_PARENTS) else "low"
                items.append(self.make_evidence_item(
                    artifact_id=f"proc_{pid}",
                    evidence_type="process",
                    value=f"{name} (PID:{pid} PPID:{ppid})",
                    severity=severity,
                    confidence=0.75
                ))
            except Exception:
                continue
        return items

    def _parse_pstree(self, lines: list) -> list:
        items = []
        for line in lines:
            parts = line.split()
            if len(parts) < 3:
                continue
            try:
                name = parts[0].lstrip("*. ")
                pid  = parts[1]
                ppid = parts[2]
                is_suspicious = any(s in name.lower() for s in SUSPICIOUS_PARENTS)
                if is_suspicious:
                    items.append(self.make_evidence_item(
                        artifact_id=f"proc_tree_{pid}",
                        evidence_type="process_tree",
                        value=f"Suspicious parent-child: {name} (PID:{pid}) under PPID:{ppid}",
                        severity="high",
                        confidence=0.85
                    ))
            except Exception:
                continue
        return items

    def _parse_cmdline(self, lines: list) -> list:
        items = []
        for line in lines:
            lower = line.lower()
            if any(kw in lower for kw in [
                "-enc", "-encodedcommand", "invoke-", "downloadstring",
                "iex", "bypass", "hidden", "frombase64"
            ]):
                parts = line.split()
                pid = parts[1] if len(parts) > 1 else "unknown"
                items.append(self.make_evidence_item(
                    artifact_id=f"cmdline_{pid}",
                    evidence_type="commandline",
                    value=line.strip(),
                    severity="high",
                    confidence=0.90
                ))
        return items

    def _parse_netstat(self, lines: list) -> list:
        items = []
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                proto   = parts[0]
                local   = parts[1]
                foreign = parts[2]
                state   = parts[3] if len(parts) > 3 else ""
                pid     = parts[-1] if parts[-1].isdigit() else "unknown"
                port = int(foreign.split(":")[-1]) if ":" in foreign else 0
                severity = "high" if port in SUSPICIOUS_PORTS else "medium"
                if foreign not in ["0.0.0.0:0", "*:*", ":::*"]:
                    items.append(self.make_evidence_item(
                        artifact_id=f"net_{pid}_{port}",
                        evidence_type="network_connection",
                        value=f"{proto} {local} → {foreign} [{state}] PID:{pid}",
                        severity=severity,
                        confidence=0.80,
                        linked_artifacts=[f"proc_{pid}"]
                    ))
            except Exception:
                continue
        return items

    def _parse_malfind(self, lines: list) -> list:
        items = []
        for line in lines:
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                pid  = parts[1] if parts[1].isdigit() else "unknown"
                name = parts[0]
                items.append(self.make_evidence_item(
                    artifact_id=f"malfind_{pid}_{str(uuid.uuid4())[:4]}",
                    evidence_type="injected_code",
                    value=f"Suspicious memory region in {name} (PID:{pid}): {line.strip()}",
                    severity="critical",
                    confidence=0.92
                ))
            except Exception:
                continue
        return items

    def _parse_dlllist(self, lines: list) -> list:
        items = []
        suspicious_dlls = ["unknown", "temp", "appdata\\roaming", "programdata"]
        for line in lines:
            lower = line.lower()
            if any(s in lower for s in suspicious_dlls):
                items.append(self.make_evidence_item(
                    artifact_id=f"dll_{str(uuid.uuid4())[:8]}",
                    evidence_type="suspicious_dll",
                    value=line.strip(),
                    severity="high",
                    confidence=0.78
                ))
        return items


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 2:
        print("Usage: python -m src.wrappers.volatility_wrapper <memory.dmp>")
        sys.exit(1)
    wrapper = VolatilityWrapper()
    items = wrapper.run(sys.argv[1])
    output = {"tool": "volatility3", "items": items}
    os.makedirs("output/raw", exist_ok=True)
    with open("output/raw/volatility_output.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n[DONE] {len(items)} evidence items saved to output/raw/volatility_output.json")
