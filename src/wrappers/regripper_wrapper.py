import os
import json
from src.wrappers.base_wrapper import BaseWrapper, stable_artifact_id

def _resolve_regripper_path() -> str | None:
    candidate_paths = [
        os.environ.get("REGRIPPER_PATH", ""),
        "~/regripper/rip.pl",
        "~/RegRipper3.0/rip.pl",
        "~/RegRipper/rip.pl",
        "~/Desktop/RegRipper3.0/rip.pl",
    ]

    for candidate in candidate_paths:
        if not candidate:
            continue
        resolved = os.path.expanduser(candidate)
        if os.path.exists(resolved):
            return resolved
    return None

SUSPICIOUS_KEYS = [
    "run", "runonce", "userinit", "shell", "load",
    "autoruns", "startup", "services", "scheduled"
]

class RegRipperWrapper(BaseWrapper):
    consumes = "registry_hive"

    def __init__(self):
        super().__init__("regripper")

    def run(self, hive_path: str) -> list:
        if not os.path.exists(hive_path):
            print(f"  [ERROR] Registry hive not found: {hive_path}")
            return []

        regripper_path = _resolve_regripper_path()
        if not regripper_path:
            print("  [ERROR] RegRipper not found.")
            print("  Set REGRIPPER_PATH or install one of:")
            print("    ~/regripper/rip.pl")
            print("    ~/RegRipper3.0/rip.pl")
            print("    ~/RegRipper/rip.pl")
            return []

        all_items = []
        all_items.extend(self._run_plugin(hive_path, "ntuser", regripper_path))
        all_items.extend(self._run_plugin(hive_path, "run", regripper_path))
        all_items.extend(self._run_plugin(hive_path, "autoruns", regripper_path))
        return all_items

    def _run_plugin(self, hive_path: str, plugin: str, regripper_path: str) -> list:
        print(f"  [REGRIP] Running plugin: {plugin}...")
        stdout, _, code = self.run_command(
            ["perl", regripper_path, "-r", hive_path, "-p", plugin],
            input_files=[hive_path],
            timeout=60
        )

        if not stdout.strip():
            return []

        return self._parse_output(stdout, plugin)

    def _parse_output(self, output: str, plugin: str) -> list:
        items = []
        lines = output.strip().splitlines()
        current_section = ""

        for line in lines:
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#"):
                continue

            # detect section headers
            if line_stripped.endswith(":") or line_stripped.startswith("Launching"):
                current_section = line_stripped
                continue

            lower = line_stripped.lower()
            is_suspicious = any(k in lower for k in SUSPICIOUS_KEYS)

            if is_suspicious or any(ext in lower for ext in [
                ".exe", ".dll", ".bat", ".ps1", ".vbs", ".cmd"
            ]):
                severity = "high" if any(k in lower for k in [
                    "run", "runonce", "startup", "shell"
                ]) else "medium"

                items.append(self.make_evidence_item(
                    artifact_id=stable_artifact_id(f"reg_{plugin}", line_stripped),
                    evidence_type="registry_entry",
                    value=f"[{plugin}] {line_stripped}",
                    severity=severity,
                    confidence=0.80
                ))

        print(f"  [REGRIP] {plugin} → {len(items)} registry items")
        return items


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 2:
        print("Usage: python -m src.wrappers.regripper_wrapper <NTUSER.DAT>")
        sys.exit(1)
    wrapper = RegRipperWrapper()
    items = wrapper.run(sys.argv[1])
    output = {"tool": "regripper", "items": items}
    os.makedirs("output/raw", exist_ok=True)
    with open("output/raw/regripper_output.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n[DONE] {len(items)} evidence items saved to output/raw/regripper_output.json")
