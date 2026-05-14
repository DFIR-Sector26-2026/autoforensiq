"""
AutoForensiq — Main CLI Entry Point
"""

import argparse
import json
import sys
import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _stage(num: int, name: str, owner: str):
    print(f"\n{'=' * 60}")
    print(f"  STAGE {num}: {name}  [{owner}]")
    print(f"{'=' * 60}")


def _stub(stage_name: str, expected_output: str):
    print(f"  [STUB] {stage_name} not yet integrated.")
    print(f"         Expected output: {expected_output}")


def _load_json(path: str):
    with open(path) as f:
        return json.load(f)


def _ensure_output_dir():
    (ROOT_DIR / "output").mkdir(exist_ok=True)
    (ROOT_DIR / "output" / "raw").mkdir(exist_ok=True)


# ─────────────────────────────────────────────────────────────
# STAGE 1 — CLASSIFIER
# ─────────────────────────────────────────────────────────────

def run_classifier(report_path: str):

    _stage(1, "Intent Classifier", "P1")

    from src.classifier.intent_classifier import classify_file

    import yaml

    cfg_path = ROOT_DIR / "config.yaml"

    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)

    output_path = ROOT_DIR / cfg["paths"]["case_context_output"]

    return classify_file(report_path, str(output_path))


# ─────────────────────────────────────────────────────────────
# STAGE 2 — TOOL SELECTOR
# ─────────────────────────────────────────────────────────────

def run_tool_selector(case_context: dict):

    _stage(2, "Dynamic Tool Selector", "P2")

    out_path = ROOT_DIR / "output" / "execution_plan.json"

    try:

        from src.agents.tool_selector import (
            generate_execution_plan,
            load_json as _load_ontology
        )

        ontology_path = ROOT_DIR / "src" / "data" / "tool_ontology.json"

        ontology = _load_ontology(str(ontology_path))

        plan = generate_execution_plan(case_context, ontology)

        with open(out_path, "w") as f:
            json.dump(plan, f, indent=2)

        print(f"  [LIVE] Execution plan generated → {out_path}")

        return plan

    except Exception as exc:

        print(f"  [WARN] Tool selector failed ({exc})")

        stub_plan = {
            "tools": [
                {"name": "volatility3", "order": 1},
                {"name": "tshark", "order": 2},
                {"name": "tsk_fls", "order": 3},
                {"name": "regripper", "order": 4},
                {"name": "plaso", "order": 5},
                {"name": "email", "order": 6},
                {"name": "browser", "order": 7}
            ]
        }

        with open(out_path, "w") as f:
            json.dump(stub_plan, f, indent=2)

        return stub_plan


# ─────────────────────────────────────────────────────────────
# STAGE 3 — ORCHESTRATOR
# ─────────────────────────────────────────────────────────────

def run_orchestrator(execution_plan: dict, evidence_files: dict):

    _stage(3, "Execution Orchestrator", "P3")

    if not evidence_files:
        _stub(
            "Orchestrator (P3)",
            "output/raw/<tool>_output.json"
        )
        return {}

    try:

        sys.path.insert(0, str(ROOT_DIR))

        from src.orchestrator import run_tools

        print("  [LIVE] Running P3 orchestrator...")

        return run_tools(execution_plan, evidence_files)

    except Exception as exc:

        print(f"  [ERROR] Orchestrator failed: {exc}")

        return {}


# ─────────────────────────────────────────────────────────────
# STAGE 4 — AGGREGATOR
# ─────────────────────────────────────────────────────────────

def run_aggregator(case_context: dict):

    _stage(4, "Evidence Aggregator", "P4")

    unified_path = ROOT_DIR / "output" / "unified_evidence.json"

    if unified_path.exists():

        print("  [LOADED] Using existing unified_evidence.json")

        return _load_json(str(unified_path))

    try:

        sys.path.insert(0, str(ROOT_DIR))

        from src.aggregator.evidence_aggregator import (
            aggregate_evidence
        )

        print("  [LIVE] Running P4 aggregator...")

        return aggregate_evidence(
            case_context=case_context,
            raw_outputs_dir=str(ROOT_DIR / "output" / "raw"),
            output_path=str(unified_path)
        )

    except Exception as exc:

        print(f"  [ERROR] Aggregator failed: {exc}")

        return {
            "evidence_items": [],
            "generated_at": "",
            "total_items": 0
        }


# ─────────────────────────────────────────────────────────────
# STAGE 5/6 — ML + XAI
# ─────────────────────────────────────────────────────────────

def run_ml_pipeline():

    _stage(5, "Anomaly Detector + XAI Explainer", "P5")

    shap_path = ROOT_DIR / "output" / "shap_explanations.json"

    if shap_path.exists():

        print("  [LOADED] Using existing shap_explanations.json")

        return _load_json(str(shap_path))

    try:

        sys.path.insert(0, str(ROOT_DIR))

        from src.ml.pipeline import (
            run_ml_pipeline as _run_p5
        )

        print("  [LIVE] Running P5 ML pipeline...")

        result = _run_p5(
            input_path=str(ROOT_DIR / "output" / "unified_evidence.json"),
            output_path=str(shap_path),
            baseline_path=str(ROOT_DIR / "data" / "baseline_normal.json")
        )

        return result if result else {
            "explanations": [],
            "generated_at": ""
        }

    except Exception as exc:

        print(f"  [ERROR] ML pipeline failed: {exc}")

        return {
            "explanations": [],
            "generated_at": ""
        }


# ─────────────────────────────────────────────────────────────
# STAGE 7 — REPORT GENERATOR
# ─────────────────────────────────────────────────────────────

def run_report_generator(
    unified_evidence: dict,
    shap_explanations: dict,
    case_context: dict
):

    _stage(7, "Report Generator", "P1")

    try:

        from src.report_generator.report_generator import (
            generate_report
        )

        print("  [LIVE] Running report generator...")

        return generate_report(
            unified_evidence,
            shap_explanations,
            case_context
        )

    except Exception as exc:

        print(f"  [ERROR] Report generator failed: {exc}")

        return ""


# ─────────────────────────────────────────────────────────────
# ARGUMENTS
# ─────────────────────────────────────────────────────────────

def parse_args():

    parser = argparse.ArgumentParser(
        description="AutoForensiq — run with no arguments to open the GUI"
    )

    parser.add_argument(
        "--report",
        default=None,
        help="Path to plain-text incident report. Omit to launch the GUI."
    )

    parser.add_argument(
        "--evidence",
        nargs="*",
        default=[]
    )

    parser.add_argument(
        "--mock",
        action="store_true"
    )

    parser.add_argument(
        "--skip-tools",
        action="store_true"
    )

    parser.add_argument(
        "--gui",
        action="store_true",
        help="Force the GUI even when other flags are provided."
    )

    return parser.parse_args()


# ─────────────────────────────────────────────────────────────
# EVIDENCE MAPPING
# ─────────────────────────────────────────────────────────────

def _map_evidence_files(paths: list):

    mapping = {}

    for path in paths:

        lower = path.lower()

        ext = Path(path).suffix.lower()

        # MEMORY
        if (
            ext in [".dmp", ".mem", ".raw"]
            or "memory" in lower
        ):
            mapping["memory_dump"] = path

        # PCAP
        elif ext in [".pcap", ".pcapng"]:
            mapping["pcap"] = path

        # DISK IMAGE
        elif ext in [".img", ".dd", ".e01"]:
            mapping["disk_image"] = path

        # REGISTRY
        elif (
            "system" in lower
            or "ntuser" in lower
            or "software" in lower
            or ext in [".dat", ".hiv"]
        ):
            mapping["registry_hive"] = path

        # EMAIL
        elif ext in [".eml", ".msg"]:
            mapping["email"] = path

        # BROWSER
        elif "history" in lower:
            mapping["browser"] = path

        # LOGS
        elif ext in [".log", ".evtx"]:
            mapping["log_files"] = path

    return mapping


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main(args=None):

    if args is None:
        args = parse_args()

    print("\n" + "=" * 60)
    print("  AutoForensiq — Autonomous Forensics Pipeline")
    print("=" * 60)

    print(f"  Report:   {args.report}")
    print(f"  Evidence: {args.evidence or 'none'}")
    print(f"  Mock LLM: {args.mock}")

    _ensure_output_dir()

    os.chdir(ROOT_DIR)

    # STAGE 1
    case_context = run_classifier(args.report)

    if args.skip_tools:

        print("\n[SKIP] --skip-tools enabled")

        return

    # STAGE 2
    execution_plan = run_tool_selector(case_context)

    # STAGE 3
    evidence_files = _map_evidence_files(args.evidence)

    raw_outputs = run_orchestrator(
        execution_plan,
        evidence_files
    )

    # STAGE 4
    unified_evidence = run_aggregator(case_context)

    # STAGE 5/6
    shap_explanations = run_ml_pipeline()

    # STAGE 7
    run_report_generator(
        unified_evidence,
        shap_explanations,
        case_context
    )

    print("\n" + "=" * 60)
    print("  PIPELINE COMPLETE")
    print("=" * 60)

    print(f"  case_type  : {case_context['case_type']}")
    print(f"  confidence : {case_context['classifier_confidence']}")
    print(f"  artifacts  : {', '.join(case_context['artifact_types'])}")

    print("  output/    : final_report.md")

    print("=" * 60 + "\n")


if __name__ == "__main__":
    args = parse_args()
    if args.gui or args.report is None:
        from src.gui.launcher import AutoForensiqGUI
        app = AutoForensiqGUI()
        app.mainloop()
    else:
        main(args)
