import os
import json

from src.wrappers.volatility_wrapper import VolatilityWrapper
from src.wrappers.tshark_wrapper import TsharkWrapper
from src.wrappers.tsk_wrapper import TSKWrapper
from src.wrappers.regripper_wrapper import RegRipperWrapper
from src.wrappers.plaso_wrapper import PlasoWrapper
from src.wrappers.email_wrapper import EmailWrapper
from src.wrappers.browser_wrapper import BrowserWrapper
from src.wrappers.memprocfs_wrapper import MemProcFSWrapper


# ─────────────────────────────────────────────────────────────
# WRAPPER MAP
# ─────────────────────────────────────────────────────────────

WRAPPER_MAP = {
    "volatility3": VolatilityWrapper,
    "memprocfs": MemProcFSWrapper,
    "tshark": TsharkWrapper,
    "tsk_fls": TSKWrapper,
    "regripper": RegRipperWrapper,
    "plaso": PlasoWrapper,
    "email": EmailWrapper,
    "browser": BrowserWrapper,
}


# ─────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────

def run_tools(execution_plan: dict, evidence_files: dict):

    tools = sorted(
        execution_plan["tools"],
        key=lambda t: t["order"]
    )

    all_raw_outputs = {}

    for tool_spec in tools:

        name = tool_spec["name"]

        print(f"\n{'=' * 50}")
        print(f"  Running: {name}")
        print(f"{'=' * 50}")

        # UNKNOWN TOOL
        if name not in WRAPPER_MAP:

            print(f"  [SKIP] No wrapper found for: {name}")

            continue

        wrapper = WRAPPER_MAP[name]()

        evidence_path = None

        # ─────────────────────────────────────────
        # VOLATILITY — MEMORY FORENSICS
        # ─────────────────────────────────────────

        if name == "volatility3":

            evidence_path = evidence_files.get(
                "memory_dump"
            )

        # ─────────────────────────────────────────
        # MEMPROCFS — MEMORY FORENSICS
        # ─────────────────────────────────────────

        elif name == "memprocfs":

            evidence_path = evidence_files.get(
                "memory_dump"
            )

        # ─────────────────────────────────────────
        # TSHARK — NETWORK FORENSICS
        # ─────────────────────────────────────────

        elif name == "tshark":

            evidence_path = evidence_files.get(
                "pcap"
            )

        # ─────────────────────────────────────────
        # TSK / SLEUTHKIT — DISK FORENSICS
        # ─────────────────────────────────────────

        elif name == "tsk_fls":

            evidence_path = evidence_files.get(
                "disk_image"
            )

        # ─────────────────────────────────────────
        # REGRIPPER — REGISTRY FORENSICS
        # ─────────────────────────────────────────

        elif name == "regripper":

            evidence_path = evidence_files.get(
                "registry_hive"
            )

        # ─────────────────────────────────────────
        # PLASO — TIMELINE ANALYSIS
        # ─────────────────────────────────────────

        elif name == "plaso":

            evidence_path = evidence_files.get(
                "disk_image"
            )

        # ─────────────────────────────────────────
        # EMAIL ANALYSIS
        # ─────────────────────────────────────────

        elif name == "email":

            evidence_path = evidence_files.get(
                "email"
            )

        # ─────────────────────────────────────────
        # BROWSER ANALYSIS
        # ─────────────────────────────────────────

        elif name == "browser":

            evidence_path = evidence_files.get(
                "browser"
            )

        # ─────────────────────────────────────────
        # VALIDATE EVIDENCE PATH
        # ─────────────────────────────────────────

        if not evidence_path:

            print(
                f"  [SKIP] No evidence file provided for {name}"
            )

            all_raw_outputs[name] = []

            continue

        if not os.path.exists(evidence_path):

            print(
                f"  [SKIP] Evidence path does not exist: {evidence_path}"
            )

            all_raw_outputs[name] = []

            continue

        # ─────────────────────────────────────────
        # EXECUTE TOOL
        # ─────────────────────────────────────────

        try:

            items = wrapper.run(evidence_path)

            if items is None:
                items = []

            all_raw_outputs[name] = items

            os.makedirs(
                "output/raw",
                exist_ok=True
            )

            out_path = (
                f"output/raw/{name}_output.json"
            )

            with open(out_path, "w") as f:

                json.dump(
                    {
                        "tool": name,
                        "items": items
                    },
                    f,
                    indent=2
                )

            print(
                f"  [SAVED] {len(items)} items → {out_path}"
            )

        except Exception as e:

            print(
                f"  [ERROR] {name} failed: {e}"
            )

            all_raw_outputs[name] = []

    return all_raw_outputs


# ─────────────────────────────────────────────────────────────
# STANDALONE TEST MODE
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":

    plan_path = "output/execution_plan.json"

    if not os.path.exists(plan_path):

        plan_path = "src/schemas/execution_plan.json"

    with open(plan_path) as f:

        plan = json.load(f)

    evidence = {

        "memory_dump":
            "data/live_case/memory.dmp",

        "pcap":
            "data/live_case/capture.pcap",

        "disk_image":
            "data/live_case/disk.img",

        "registry_hive":
            "data/live_case/SYSTEM",

        "email":
            "data/live_case/phish.eml",

        "browser":
            "data/live_case/History"
    }

    results = run_tools(
        plan,
        evidence
    )

    print(f"\n{'=' * 50}")
    print("  ORCHESTRATOR COMPLETE")
    print(f"{'=' * 50}")

    for tool, items in results.items():

        if len(items) > 0:

            print(
                f"  ✔ {tool}: {len(items)} items (SUCCESS)"
            )

        else:

            print(
                f"  ⚠ {tool}: no data / skipped"
            )
