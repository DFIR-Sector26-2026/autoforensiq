import os
import json
from src.wrappers.volatility_wrapper import VolatilityWrapper
from src.wrappers.tshark_wrapper import TsharkWrapper
from src.wrappers.tsk_wrapper import TSKWrapper
from src.wrappers.regripper_wrapper import RegRipperWrapper
from src.wrappers.plaso_wrapper import PlasoWrapper
from src.wrappers.email_wrapper import EmailWrapper
from src.wrappers.browser_wrapper import BrowserWrapper

WRAPPER_MAP = {
    "volatility3": VolatilityWrapper,
    "tshark": TsharkWrapper,
    "tsk_fls": TSKWrapper,
    "regripper": RegRipperWrapper,
    "plaso": PlasoWrapper,
    "email": EmailWrapper,
    "browser": BrowserWrapper
}


def run_tools(execution_plan: dict, evidence_files: dict) -> dict:
    tools = sorted(execution_plan["tools"], key=lambda t: t["order"])
    all_raw_outputs = {}

    for tool_spec in tools:
        name = tool_spec["name"]
        print(f"\n{'='*50}")
        print(f"  Running: {name}")
        print(f"{'='*50}")

        if name not in WRAPPER_MAP:
            print(f"  [SKIP] No wrapper found for: {name}")
            continue

        wrapper = WRAPPER_MAP[name]()

        args = tool_spec.get("args", {})
        evidence_path = None

        # ✅ CLEAN FIXED MAPPING
        if name == "volatility3":
            evidence_path = evidence_files.get("memory_dump")

        elif name == "tsk_fls":
            evidence_path = evidence_files.get("disk_image")

        elif name == "email":
            evidence_path = evidence_files.get("email")

        elif name == "browser":
            evidence_path = evidence_files.get("browser")

        elif "pcap" in args:
            evidence_path = evidence_files.get("pcap") or args["pcap"]

        elif "hive" in args:
            evidence_path = evidence_files.get("registry_hive") or args["hive"]

        elif "source" in args:
            evidence_path = evidence_files.get("source") or args["source"]

        if not evidence_path:
            print(f"  [SKIP] No evidence file provided for {name}")
            all_raw_outputs[name] = []
            continue

        try:
            items = wrapper.run(evidence_path)
            all_raw_outputs[name] = items

            os.makedirs("output/raw", exist_ok=True)
            out_path = f"output/raw/{name}_output.json"

            with open(out_path, "w") as f:
                json.dump({"tool": name, "items": items}, f, indent=2)

            print(f"  [SAVED] {len(items)} items → {out_path}")

        except Exception as e:
            print(f"  [ERROR] {name} failed: {e}")
            all_raw_outputs[name] = []

    return all_raw_outputs


if __name__ == "__main__":
    plan_path = "output/execution_plan.json"
    if not os.path.exists(plan_path):
        plan_path = "src/schemas/execution_plan.json"

    with open(plan_path) as f:
        plan = json.load(f)

    evidence = {
        "memory_dump": "data/test_cases/memory.dmp",
        "pcap": "data/test_cases/capture.pcap",
        "disk_image": "data/test_cases/disk.img",
        "registry_hive": "data/test_cases/NTUSER.DAT",
        "source": "data/test_cases/capture.pcap",
        "email": "data/test_cases/email.txt",
        "browser": "data/test_cases/history.txt"
    }

    results = run_tools(plan, evidence)

    print(f"\n{'='*50}")
    print("  ORCHESTRATOR COMPLETE")
    print(f"{'='*50}")

    for tool, items in results.items():
        if len(items) > 0:
            print(f"  ✔ {tool}: {len(items)} items (SUCCESS)")
        else:
            print(f"  ⚠ {tool}: no data / skipped")
