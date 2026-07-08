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

from src.ioc.ioc_engine import extract_iocs


# WRAPPER MAP

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


# Single source of truth for "which evidence type each tool consumes" (D2), derived from each
# wrapper's `consumes` — pre-flight and the report import it.
TOOL_EVIDENCE_MAP = {
    name: cls.consumes
    for name, cls in WRAPPER_MAP.items()
    if cls.consumes is not None
}


# MAIN ORCHESTRATOR

def run_tools(execution_plan: dict, evidence_files: dict):

    tools = sorted(
        execution_plan["tools"],
        key=lambda t: t["order"]
    )

    all_raw_outputs = {}

    merged_items = []

    # EXECUTE TOOLS

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

        # Each wrapper declares the evidence key it consumes (D2) — one lookup instead of a per-tool
        # if/elif ladder.
        evidence_path = evidence_files.get(wrapper.consumes)

        # VALIDATE EVIDENCE PATH(S) — one evidence type may carry several artifacts, so normalise to
        # a list and run the tool on each.

        if not evidence_path:

            print(
                f"  [SKIP] No evidence file provided for {name}"
            )

            all_raw_outputs[name] = []

            continue

        evidence_paths = (
            evidence_path
            if isinstance(evidence_path, list)
            else [evidence_path]
        )

        # EXECUTE TOOL (once per supplied artifact)

        items = []

        for path in evidence_paths:

            if not os.path.exists(path):

                print(
                    f"  [SKIP] Evidence path does not exist: {path}"
                )

                continue

            try:

                out = wrapper.run(path)

                if out:

                    items.extend(out)

            except Exception as e:

                print(
                    f"  [ERROR] {name} failed on {path}: {e}"
                )

        all_raw_outputs[name] = items

        merged_items.extend(items)

        # SAVE RAW TOOL OUTPUT (combined across artifacts)

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

    # IOC EXTRACTION

    print(f"\n{'=' * 50}")
    print("  IOC EXTRACTION")
    print(f"{'=' * 50}")

    ioc_items = extract_iocs(
        merged_items
    )

    print(
        f"  [IOC] Extracted {len(ioc_items)} IOC items"
    )

    merged_items.extend(
        ioc_items
    )

    # SAVE IOC RAW OUTPUT

    os.makedirs(
        "output/raw",
        exist_ok=True
    )

    with open(
        "output/raw/ioc_output.json",
        "w"
    ) as f:

        json.dump(
            {
                "tool": "ioc_engine",
                "items": ioc_items
            },
            f,
            indent=2
        )

    print(
        f"  [SAVED] {len(ioc_items)} IOC items → output/raw/ioc_output.json"
    )

    # SAVE UNIFIED EVIDENCE

    os.makedirs(
        "output",
        exist_ok=True
    )

    with open(
        "output/unified_evidence.json",
        "w"
    ) as f:

        json.dump(
            merged_items,
            f,
            indent=2
        )

    print(
        f"\n[MERGE] {len(merged_items)} total evidence items saved"
    )

    return all_raw_outputs


# STANDALONE TEST MODE

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

