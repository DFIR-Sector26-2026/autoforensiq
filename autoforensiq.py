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

def _stage(num: int, name: str):
    print(f"\n{'=' * 60}")
    print(f"  STAGE {num}: {name}")
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


def _clear_stale_outputs():
    raw_dir = ROOT_DIR / "output" / "raw"
    if raw_dir.exists():
        for f in raw_dir.glob("*.json"):
            f.unlink()
    for name in ("unified_evidence.json", "shap_explanations.json"):
        stale = ROOT_DIR / "output" / name
        if stale.exists():
            stale.unlink()


# ─────────────────────────────────────────────────────────────
# STAGE 1 — CLASSIFIER
# ─────────────────────────────────────────────────────────────

def run_classifier(report_path: str, config_override: dict = None,
                   provided_artifact_types=None):

    _stage(1, "Intent Classifier")

    from src.classifier.intent_classifier import classify_file

    import yaml

    cfg_path = ROOT_DIR / "config.yaml"

    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)

    output_path = ROOT_DIR / cfg["paths"]["case_context_output"]

    return classify_file(report_path, str(output_path),
                         config_override=config_override,
                         provided_artifact_types=provided_artifact_types)


# ─────────────────────────────────────────────────────────────
# STAGE 2 — TOOL SELECTOR
# ─────────────────────────────────────────────────────────────

def run_tool_selector(case_context: dict):

    _stage(2, "Dynamic Tool Selector")

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

    _stage(3, "Execution Orchestrator")

    if not evidence_files:
        _stub(
            "Orchestrator (P3)",
            "output/raw/<tool>_output.json"
        )
        return {}

    _clear_stale_outputs()

    try:

        sys.path.insert(0, str(ROOT_DIR))

        from src.orchestrator import run_tools

        print("  [LIVE] Running orchestrator...")

        return run_tools(execution_plan, evidence_files)

    except Exception as exc:

        print(f"  [ERROR] Orchestrator failed: {exc}")

        return {}


# ─────────────────────────────────────────────────────────────
# STAGE 4 — AGGREGATOR
# ─────────────────────────────────────────────────────────────

def run_aggregator(case_context: dict):

    _stage(4, "Evidence Aggregator")

    unified_path = ROOT_DIR / "output" / "unified_evidence.json"

    try:

        sys.path.insert(0, str(ROOT_DIR))

        from src.aggregator.evidence_aggregator import (
            aggregate_evidence
        )

        print("  [LIVE] Running aggregator...")

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


def _load_bulk_manifest(manifest_path: str) -> tuple[dict[str, dict], str, str]:
    with open(manifest_path) as f:
        manifest = json.load(f)

    if isinstance(manifest, dict) and "machines" in manifest:
        machine_specs = manifest["machines"]
    elif isinstance(manifest, dict):
        machine_specs = [
            {"machine_name": machine_name, **spec}
            for machine_name, spec in manifest.items()
        ]
    elif isinstance(manifest, list):
        machine_specs = manifest
    else:
        raise ValueError("Bulk manifest must be a list or object")

    machine_runs = {}
    for index, spec in enumerate(machine_specs, 1):
        if not isinstance(spec, dict):
            raise ValueError("Each bulk manifest entry must be an object")

        machine_name = (
            spec.get("machine_name")
            or spec.get("machine_id")
            or f"machine_{index}"
        )
        raw_outputs_dir = spec.get("raw_outputs_dir") or spec.get("raw_dir")
        if not raw_outputs_dir:
            raise ValueError(
                f"Missing raw_outputs_dir for bulk machine '{machine_name}'"
            )

        case_context = spec.get("case_context") or {}
        if "case_id" not in case_context:
            case_context["case_id"] = machine_name

        machine_runs[machine_name] = {
            "case_context": case_context,
            "raw_outputs_dir": raw_outputs_dir,
            "output_path": spec.get("output_path"),
        }

    output_root = manifest.get("output_root", str(ROOT_DIR / "output" / "bulk")) if isinstance(manifest, dict) else str(ROOT_DIR / "output" / "bulk")
    summary_path = manifest.get("summary_path", str(ROOT_DIR / "output" / "bulk_summary.json")) if isinstance(manifest, dict) else str(ROOT_DIR / "output" / "bulk_summary.json")
    return machine_runs, output_root, summary_path


def run_bulk_aggregation(manifest_path: str):

    _stage(4, "Bulk Evidence Aggregator")

    try:
        sys.path.insert(0, str(ROOT_DIR))

        from src.aggregator.evidence_aggregator import aggregate_bulk_evidence

        machine_runs, output_root, summary_path = _load_bulk_manifest(manifest_path)

        print(f"  [LIVE] Running bulk aggregation for {len(machine_runs)} machines...")

        bulk_summary = aggregate_bulk_evidence(
            machine_runs=machine_runs,
            output_root=output_root,
        )

        summary = {
            "generated_at": bulk_summary.get("generated_at", ""),
            "manifest_path": manifest_path,
            "bulk_summary": bulk_summary,
        }

        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        print(f"  [SAVE] Wrote bulk summary → {summary_path}")

        return summary

    except Exception as exc:

        print(f"  [ERROR] Bulk aggregation failed: {exc}")

        return {
            "generated_at": "",
            "manifest_path": manifest_path,
            "bulk_summary": {
                "machines": [],
                "total_items": 0,
                "total_findings": 0,
            },
        }


# ─────────────────────────────────────────────────────────────
# STAGE 5/6 — ML + XAI
# ─────────────────────────────────────────────────────────────

def run_ml_pipeline():

    _stage(5, "Anomaly Detector + XAI Explainer")

    shap_path = ROOT_DIR / "output" / "shap_explanations.json"

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
    case_context: dict,
    config_override: dict = None
):

    _stage(7, "Report Generator")

    try:

        from src.report_generator.report_generator import (
            generate_report
        )

        print("  [LIVE] Running report generator...")

        return generate_report(
            unified_evidence,
            shap_explanations,
            case_context,
            config_override=config_override
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
        default=[],
        metavar="FILE",
        help=(
            "Artifact files in any order — type is auto-detected from extension/name. "
            "Pass order = priority (#1 runs first). "
            "Example: --evidence memory.dmp capture.pcap disk.img"
        )
    )

    parser.add_argument(
        "--tools",
        nargs="*",
        default=None,
        metavar="TOOL",
        help=(
            "Restrict which forensic tools run. Default: all tools selected by the DTSA. "
            "Valid names: volatility3 tshark tsk_fls regripper plaso email browser. "
            "Example: --tools volatility3 tshark"
        )
    )

    parser.add_argument(
        "--provider",
        default=None,
        metavar="PROVIDER",
        help=(
            "LLM provider to use. Overrides config.yaml. "
            "Valid values: anthropic openai deepseek. "
            "Example: --provider deepseek"
        )
    )

    parser.add_argument(
        "--model",
        default=None,
        metavar="MODEL",
        help=(
            "LLM model to use. Overrides config.yaml. "
            "Example: --model deepseek-chat"
        )
    )

    parser.add_argument(
        "--mock",
        action="store_true"
    )

    parser.add_argument(
        "--bulk-manifest",
        default=None,
        help=("Path to a JSON manifest describing multiple machine raw output locations. "
              "If provided, runs bulk aggregation and exits.")
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

    # Each evidence type maps to a *list* of paths so that supplying more than
    # one artifact of the same kind (e.g. two memory images) analyses all of
    # them rather than silently keeping only the last one.
    mapping = {}

    def _add(key, path):
        mapping.setdefault(key, []).append(path)

    for path in paths:

        lower = path.lower()

        ext = Path(path).suffix.lower()

        # MEMORY
        if (
            ext in [".dmp", ".mem", ".raw", ".vmem"]
            or "memory" in lower
        ):
            _add("memory_dump", path)

        # PCAP
        elif ext in [".pcap", ".pcapng"]:
            _add("pcap", path)

        # DISK IMAGE
        elif ext in [".img", ".dd", ".e01"]:
            _add("disk_image", path)

        # REGISTRY
        elif (
            "system" in lower
            or "ntuser" in lower
            or "software" in lower
            or ext in [".dat", ".hiv"]
        ):
            _add("registry_hive", path)

        # EMAIL
        elif ext in [".eml", ".msg"]:
            _add("email", path)

        # BROWSER
        elif "history" in lower:
            _add("browser", path)

        # LOGS
        elif ext in [".log", ".evtx"]:
            _add("log_files", path)

    return mapping


# ─────────────────────────────────────────────────────────────
# PRE-FLIGHT CHECK
# ─────────────────────────────────────────────────────────────

# Maps the evidence keys produced by _map_evidence_files() → the artifact_type
# enum values used by the classifier / case_context schema. Most keys already
# match; only the email/browser shorthands differ. Used to narrow the
# narrative artifact_types to what was actually provided (issue 1.2).
_EVIDENCE_KEY_TO_ARTIFACT_TYPE = {
    "email":   "email_archive",
    "browser": "browser_history",
}


def _provided_artifact_types(evidence_files: dict) -> list:
    """Translate the mapped evidence-file keys into artifact_type enum values."""
    return sorted({
        _EVIDENCE_KEY_TO_ARTIFACT_TYPE.get(key, key)
        for key in evidence_files
    })


# Maps each forensic tool name → the evidence key it requires
_TOOL_EVIDENCE_MAP = {
    "volatility3": "memory_dump",
    "memprocfs":   "memory_dump",
    "tshark":      "pcap",
    "tsk_fls":     "disk_image",
    "regripper":   "registry_hive",
    "plaso":       "log_files",
    "email":       "email",
    "browser":     "browser",
}

_TOOL_DISPLAY = {
    "volatility3": "Volatility3       (memory analysis)",
    "tshark":      "tshark            (network capture analysis)",
    "tsk_fls":     "The Sleuth Kit    (disk image analysis)",
    "regripper":   "RegRipper         (registry hive analysis)",
    "plaso":       "Plaso             (log / event-log timeline)",
    "email":       "Email analyzer    (email artifact analysis)",
    "browser":     "Browser analyzer  (browser history analysis)",
}

_ACQUIRE_HINT = {
    "memory_dump":    "Acquire a memory dump (.dmp / .mem) using WinPmem, DumpIt, or LiME.",
    "pcap":           "Capture network traffic (.pcap) via Wireshark or tcpdump.",
    "disk_image":     "Acquire a disk image (.img / .dd / .e01) using FTK Imager or dd.",
    "registry_hive":  "Export registry hives (NTUSER.DAT / SYSTEM / SOFTWARE) from the affected host.",
    "log_files":      "Export Windows event logs (.evtx) via Event Viewer or wevtutil.",
    "email":          "Export email artifacts (.eml / .msg) from the affected mail client.",
    "browser":        "Export browser History files from the user profile directory.",
}


def preflight_check(evidence_files: dict, execution_plan: dict):
    """
    Print a pre-flight summary of which tools will run and which will be
    skipped based on the evidence files that were supplied.

    For each skipped tool a one-line acquisition hint is printed so the
    investigator knows exactly what to collect to enable full coverage.
    """
    print("\n" + "─" * 60)
    print("  PRE-FLIGHT CHECK")
    print("─" * 60)

    tools_in_plan = [t["name"] for t in execution_plan.get("tools", [])]

    will_run  = []
    will_skip = []

    for tool in tools_in_plan:
        required_ev = _TOOL_EVIDENCE_MAP.get(tool)
        if required_ev is None or required_ev in evidence_files:
            will_run.append(tool)
        else:
            will_skip.append((tool, required_ev))

    if will_run:
        print("  Tools that WILL run:")
        for t in will_run:
            label = _TOOL_DISPLAY.get(t, t)
            print(f"    [OK]  {label}")

    if will_skip:
        print("  Tools that will be SKIPPED (evidence not provided):")
        for t, ev in will_skip:
            label = _TOOL_DISPLAY.get(t, t)
            hint  = _ACQUIRE_HINT.get(ev, f"Provide a '{ev}' artifact to enable this tool.")
            print(f"    [--]  {label}")
            print(f"          Hint: {hint}")

    print("─" * 60)


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
    print(f"  Tools:    {', '.join(args.tools) if args.tools else 'all (DTSA)'}")
    print(f"  Mock LLM: {args.mock}")
    print(f"  Bulk:     {args.bulk_manifest or 'none'}")
    if args.provider:
        print(f"  Provider: {args.provider}" + (f" / {args.model}" if args.model else ""))

    _ensure_output_dir()

    # If bulk manifest provided, run bulk aggregation and exit early
    if args.bulk_manifest:
        print(f"\n[BULK] Loading manifest: {args.bulk_manifest}")
        try:
            with open(args.bulk_manifest) as f:
                manifest = json.load(f)
        except Exception as exc:
            print(f"  [ERROR] Failed to load bulk manifest: {exc}")
            return

        machine_runs = manifest.get("machines") or manifest

        try:
            sys.path.insert(0, str(ROOT_DIR))
            from src.aggregator.evidence_aggregator import aggregate_bulk_evidence

            summary = aggregate_bulk_evidence(
                machine_runs, output_root=str(ROOT_DIR / "output" / "bulk")
            )
            summary_path = ROOT_DIR / "output" / "bulk_summary.json"
            with open(summary_path, "w") as f:
                json.dump(summary, f, indent=2)
            print(f"  [BULK] Summary written → {summary_path}")
            return
        except Exception as exc:
            print(f"  [ERROR] Bulk aggregation failed: {exc}")
            return

    os.chdir(ROOT_DIR)

    # Build config override from CLI flags
    config_override = None
    if args.provider or args.model or args.mock:
        llm_override = {}
        if args.mock:
            llm_override["mock_mode"] = True
        if args.provider:
            llm_override["provider"] = args.provider
            # Map provider+model into the right model key
            if args.model:
                model_key = f"{args.provider}_model"
                llm_override[model_key] = args.model
        config_override = {"llm": llm_override}

    # Map the supplied evidence files up-front so the classifier can narrow its
    # narrative artifact_types to what was actually provided (issue 1.2) before
    # P2 selects tools from them.
    evidence_files = _map_evidence_files(args.evidence)
    provided_artifact_types = _provided_artifact_types(evidence_files)

    # STAGE 1
    case_context = run_classifier(
        args.report,
        config_override=config_override,
        provided_artifact_types=provided_artifact_types,
    )

    if args.skip_tools:
        print("\n[SKIP] --skip-tools enabled")
        return

    # STAGE 2
    execution_plan = run_tool_selector(case_context)

    # Filter tools if --tools was specified
    if args.tools:
        allowed = set(args.tools)
        execution_plan["tools"] = [
            t for t in execution_plan["tools"] if t["name"] in allowed
        ]
        for i, t in enumerate(execution_plan["tools"], 1):
            t["order"] = i
        print(f"  [FILTER] Restricted to tools: {', '.join(args.tools)}")

    # STAGE 3 (evidence_files already mapped above for the 1.2 narrowing)
    if evidence_files:
        priority_list = [f"#{i + 1} {k}" for i, k in enumerate(evidence_files)]
        print(f"  [PRIORITY] {' -> '.join(priority_list)}")

    # Record which evidence file each tool drew from so the report can attribute
    # findings to their source artifact. Keyed by tool because each tool reads a
    # single evidence type — avoids threading a source_file field through every
    # wrapper and the evidence_item schema.
    case_context["evidence_sources"] = {
        tool: ", ".join(Path(p).name for p in evidence_files[ev_key])
        for tool, ev_key in _TOOL_EVIDENCE_MAP.items()
        if ev_key in evidence_files
    }

    preflight_check(evidence_files, execution_plan)

    raw_outputs = run_orchestrator(execution_plan, evidence_files)

    # STAGE 4
    unified_evidence = run_aggregator(case_context)

    # Issue 1.1 — reconcile the narrative classification against the evidence
    # actually recovered. Leaves classifier_confidence untouched; attaches a
    # reconciled_confidence + divergence flag for the report and audit trail.
    try:
        from src.classifier.evidence_reconciler import reconcile_evidence
        reconciliation = reconcile_evidence(case_context, unified_evidence)
        case_context["evidence_reconciliation"] = reconciliation
        case_context["reconciled_confidence"] = reconciliation["reconciled_confidence"]
        case_context["narrative_evidence_divergence"] = reconciliation["narrative_evidence_divergence"]
        with open(ROOT_DIR / "output" / "evidence_reconciliation.json", "w") as f:
            json.dump(reconciliation, f, indent=2)
        if reconciliation["narrative_evidence_divergence"]:
            print(f"  [RECONCILE] ⚠ narrative <-> evidence divergence — "
                  f"confidence {reconciliation['classifier_confidence']} → "
                  f"{reconciliation['reconciled_confidence']}")
        else:
            print(f"  [RECONCILE] evidence supports '{reconciliation['narrative_case_type']}' "
                  f"(support {reconciliation['evidence_support_score']})")
    except Exception as exc:
        print(f"  [RECONCILE] skipped ({exc})")

    # STAGE 5/6
    shap_explanations = run_ml_pipeline()

    # STAGE 7
    run_report_generator(unified_evidence, shap_explanations, case_context, config_override=config_override)

    # Dev convenience: one HTML page with every output artifact.
    try:
        from src.utils.dev_report import generate_dev_report
        html_path = generate_dev_report(ROOT_DIR / "output")
        print(f"  [DEV] HTML report → {html_path}")
    except Exception as e:
        print(f"  [DEV] HTML report skipped: {e}")

    print("\n" + "=" * 60)
    print("  PIPELINE COMPLETE")
    print("=" * 60)
    print(f"  case_type  : {case_context['case_type']}")
    print(f"  confidence : {case_context['classifier_confidence']}"
          + (f" (reconciled {case_context['reconciled_confidence']})"
             if "reconciled_confidence" in case_context else ""))
    print(f"  artifacts  : {', '.join(case_context['artifact_types'])}")
    print("  output/    : final_report.md")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    args = parse_args()
    if args.gui or (args.report is None and not args.bulk_manifest):
        from src.gui.launcher import AutoForensiqGUI
        app = AutoForensiqGUI()
        app.mainloop()
    else:
        main(args)
