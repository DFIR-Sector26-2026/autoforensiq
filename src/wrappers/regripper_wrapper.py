import os
import re
import json
from src.wrappers.base_wrapper import BaseWrapper, stable_artifact_id

# A bare checked-path announcement ("Software\Microsoft\...\Run") with nothing else on the line —
# no " - name/value" pair, no punctuation, just path segments. RegRipper prints one of these before
# listing (or not finding) a key's contents; it is never itself a finding.
_BARE_REG_PATH_RE = re.compile(r"^[A-Za-z0-9_ ]+(\\[A-Za-z0-9_ ]+)+$")

# Every plugin prints its own two-line banner before doing anything: a bare "<name> v.<date>"
# version line, then a "(<hive type(s)>) [<category>] <description>" line. Under a profile (-f) —
# which runs ~100+ plugins per hive — that is a lot of banners, and a plugin whose own name/
# category/description happens to mention "run"/"shell"/"startup" (there are many: run, runmru,
# runvirtual, shellfolders, ...) got reported as a finding despite having said nothing about the
# hive's actual contents yet.
_PLUGIN_VERSION_BANNER_RE = re.compile(r"^\w+ v\.\d+$")
_PLUGIN_DESCRIPTION_BANNER_RE = re.compile(
    r"^\((?:NTUSER\.DAT|Software|System|SAM|Security)[^)]*\)"
)

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
        # expanduser() substitutes ~ with the (backslash-separated) home dir but leaves the
        # literal "/"s in these candidates untouched, producing a mixed-separator path like
        # "C:\Users\name/RegRipper3.0/rip.pl". Perl can open that fine, but RegRipper derives its
        # own plugins/ directory from this path with naive backslash-only parsing, so it silently
        # resolves to the wrong directory and every plugin lookup fails. normpath() fixes it.
        resolved = os.path.normpath(os.path.expanduser(candidate))
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
        # "ntuser" is a RegRipper *profile* (a curated list of ~100+ plugins for NTUSER.DAT-type
        # hives), not a plugin itself — `-p ntuser` always fails with "plugins\ntuser.pl not
        # found" and silently returns 0 items. Run it as a profile via `-f` instead.
        all_items.extend(self._run_plugin(hive_path, "ntuser", regripper_path, use_profile=True))
        all_items.extend(self._run_plugin(hive_path, "run", regripper_path))
        # "autoruns" was never a real plugin in RegRipper3.0 either — "services" is a genuine
        # plugin covering another persistence vector already named in SUSPICIOUS_KEYS.
        all_items.extend(self._run_plugin(hive_path, "services", regripper_path))
        return all_items

    def _run_plugin(self, hive_path: str, plugin: str, regripper_path: str,
                    use_profile: bool = False) -> list:
        print(f"  [REGRIP] Running {'profile' if use_profile else 'plugin'}: {plugin}...")
        flag = "-f" if use_profile else "-p"
        stdout, _, code = self.run_command(
            ["perl", regripper_path, "-r", hive_path, flag, plugin],
            input_files=[hive_path],
            timeout=60
        )

        if not stdout.strip():
            return []

        return self._parse_output(stdout, plugin)

    def _parse_output(self, output: str, plugin: str) -> list:
        items = []
        lines = output.strip().splitlines()

        for line in lines:
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#"):
                continue

            # skip section headers
            if line_stripped.endswith(":") or line_stripped.startswith("Launching"):
                continue

            # RegRipper's own report boilerplate — a negative/status line about a checked
            # registry path, not an actual finding. Its own path text routinely contains a
            # SUSPICIOUS_KEYS word as a substring of the checked key's NAME (e.g. "...CurrentVersion
            # \RunOnce has no subkeys." contains "run"), which used to slip past the keyword filter
            # below and even get escalated to HIGH severity despite reporting nothing was found.
            if (line_stripped.endswith((" not found.", " has no subkeys.", " has no values."))
                    or line_stripped.startswith("LastWrite Time")
                    or _BARE_REG_PATH_RE.match(line_stripped)
                    or _PLUGIN_VERSION_BANNER_RE.match(line_stripped)
                    or _PLUGIN_DESCRIPTION_BANNER_RE.match(line_stripped)):
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
    import sys
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
