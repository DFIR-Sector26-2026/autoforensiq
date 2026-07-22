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


# Single source of truth for "which evidence type each tool consumes" 
TOOL_EVIDENCE_MAP = {
    name: cls.consumes if isinstance(cls.consumes, tuple) else (cls.consumes,)
    for name, cls in WRAPPER_MAP.items()
    if cls.consumes is not None
}

# How to acquire each evidence type — shown by the CLI pre-flight check and the report's coverage
# table; was maintained as near-identical twins in both (review-1 3.2).
ACQUIRE_HINTS = {
    "memory_dump":    "Acquire a memory dump (.dmp / .mem) using WinPmem, DumpIt, or LiME.",
    "pcap":           "Capture network traffic (.pcap) via Wireshark or tcpdump.",
    "disk_image":     "Acquire a disk image (.img / .dd / .e01) using FTK Imager or dd.",
    "registry_hive":  "Export registry hives (NTUSER.DAT / SYSTEM / SOFTWARE) from the affected host.",
    "log_files":      "Export Windows event logs (.evtx) via Event Viewer or wevtutil.",
    "email":          "Export email artifacts (.eml / .msg) from the affected mail client.",
    "browser":        "Export browser History files from the user profile directory.",
}


def run_tools(execution_plan: dict, evidence_files: dict):

    tools = sorted(execution_plan["tools"], key=lambda t: t["order"])
    all_raw_outputs = {}
    merged_items = []
    os.makedirs("output/raw", exist_ok=True)

    for tool_spec in tools:
        name = tool_spec["name"]

        print(f"\n{'=' * 50}")
        print(f"  Running: {name}")
        print(f"{'=' * 50}")

        if name not in WRAPPER_MAP:
            print(f"  [SKIP] No wrapper found for: {name}")
            continue

        wrapper = WRAPPER_MAP[name]()

        # Each wrapper declares the evidence key(s) it consumes 
        evidence_paths = []
        for key in TOOL_EVIDENCE_MAP.get(name, ()):
            paths = evidence_files.get(key)
            if paths:
                evidence_paths.extend(paths if isinstance(paths, list) else [paths])

        if not evidence_paths:
            print(f"  [SKIP] No evidence file provided for {name}")
            all_raw_outputs[name] = []
            continue

        items = []
        for path in evidence_paths:
            if not os.path.exists(path):
                print(f"  [SKIP] Evidence path does not exist: {path}")
                continue
            try:
                out = wrapper.run(path)
                if out:
                    items.extend(out)
            except Exception as e:
                print(f"  [ERROR] {name} failed on {path}: {e}")

        all_raw_outputs[name] = items
        merged_items.extend(items)

        # save raw tool output (combined across artifacts)
        out_path = f"output/raw/{name}_output.json"
        with open(out_path, "w") as f:
            json.dump({"tool": name, "items": items}, f, indent=2)
        print(f"  [SAVED] {len(items)} items → {out_path}")

    print(f"\n{'=' * 50}")
    print("  IOC EXTRACTION")
    print(f"{'=' * 50}")

    ioc_items = extract_iocs(merged_items)
    print(f"  [IOC] Extracted {len(ioc_items)} IOC items")
    merged_items.extend(ioc_items)

    with open("output/raw/ioc_output.json", "w") as f:
        json.dump({"tool": "ioc_engine", "items": ioc_items}, f, indent=2)
    print(f"  [SAVED] {len(ioc_items)} IOC items → output/raw/ioc_output.json")

    # unified_evidence.json is written only by the P4 aggregator (single owner, dict shape)
    print(f"\n[MERGE] {len(merged_items)} total evidence items collected")

    return all_raw_outputs
