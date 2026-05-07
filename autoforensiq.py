"""
AutoForensiq — Main CLI Entry Point (P1)
=========================================
Usage:
    python autoforensiq.py --report incident.txt
    python autoforensiq.py --report incident.txt --evidence memory.dmp network.pcap disk.img registry.dat

Pipeline stages (stubbed modules become real as the team delivers):
    1. Intent Classifier   (P1) — reads report → case_context.json        ✅ LIVE
    2. Tool Selector       (P2) — reads context → execution_plan.json      ✅ LIVE
    3. Execution Orchestr. (P3) — runs tools   → raw_outputs/             ✅ LIVE
    4. Evidence Aggregator (P4) — normalises   → unified_evidence.json    ✅ LIVE
    5. Anomaly Detector    (P5) — ML scoring   → anomaly_scores.json      ✅ LIVE
    6. XAI Explainer       (P5) — SHAP/LIME    → shap_explanations.json   ✅ LIVE
    7. Report Generator    (P1) — LLM report   → final_report.md          🔄 IN PROGRESS (Burst 2)
"""

import argparse
import json
import sys
import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent

# ── Stage runner helpers ──────────────────────────────────────────────────────

def _stage(num: int, name: str, owner: str):
    print(f"\n{'='*60}")
    print(f"  STAGE {num}: {name}  [{owner}]")
    print(f"{'='*60}")


def _stub(stage_name: str, expected_output: str):
    print(f"  [STUB] {stage_name} not yet integrated.")
    print(f"         Expected output: {expected_output}")
    print(f"         Replace this stub when the module is ready.")


def _load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _ensure_output_dir():
    (ROOT_DIR / "output").mkdir(exist_ok=True)
    (ROOT_DIR / "output" / "raw").mkdir(exist_ok=True)


# ── Stage 1: Intent Classifier ────────────────────────────────────────────────

def run_classifier(report_path: str) -> dict:
    _stage(1, "Intent Classifier", "P1")
    from src.classifier.intent_classifier import classify_file
    import yaml
    cfg_path = ROOT_DIR / "config.yaml"
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)
    output_path = ROOT_DIR / cfg["paths"]["case_context_output"]
    return classify_file(report_path, str(output_path))


# ── Stage 2: Tool Selector (P2) ──────────────────────────────────────────────

def run_tool_selector(case_context: dict) -> dict:
    _stage(2, "Dynamic Tool Selector", "P2")

    out_path = ROOT_DIR / "output" / "execution_plan.json"

    try:
        from src.agents.tool_selector import generate_execution_plan, load_json as _load_ontology
        ontology_path = ROOT_DIR / "src" / "data" / "tool_ontology.json"
        ontology = _load_ontology(str(ontology_path))
        plan = generate_execution_plan(case_context, ontology)
        with open(out_path, "w") as f:
            json.dump(plan, f, indent=2)
        print(f"  [LIVE] Execution plan generated → {out_path}")
        return plan
    except Exception as exc:
        print(f"  [WARN] Tool selector failed ({exc}), falling back to default plan.")
        stub_plan = {
            "tools": [
                {"name": "volatility3", "order": 1, "args": {"image": True}},
                {"name": "tshark",      "order": 2, "args": {"pcap":  True}},
                {"name": "tsk_fls",     "order": 3, "args": {"image": True}},
                {"name": "regripper",   "order": 4, "args": {"hive":  True}},
                {"name": "plaso",       "order": 5, "args": {"source": True}},
            ]
        }
        with open(out_path, "w") as f:
            json.dump(stub_plan, f, indent=2)
        return stub_plan


# ── Stage 3: Execution Orchestrator (P3 stub) ─────────────────────────────────

def run_orchestrator(execution_plan: dict, evidence_files: dict) -> dict:
    _stage(3, "Execution Orchestrator", "P3")

    if not evidence_files:
        _stub("Orchestrator (P3)", "output/raw/<tool>_output.json")
        return {}

    # Try to import P3's real orchestrator if it exists
    try:
        sys.path.insert(0, str(ROOT_DIR))
        from src.orchestrator import run_tools
        print("  [LIVE] Running P3 orchestrator...")
        return run_tools(execution_plan, evidence_files)
    except ImportError:
        _stub("Orchestrator (P3)", "output/raw/<tool>_output.json")
        return {}


# ── Stage 4: Evidence Aggregator (P4) ─────────────────────────────────────────

def run_aggregator(case_context: dict) -> dict:
    _stage(4, "Evidence Aggregator", "P4")

    unified_path = ROOT_DIR / "output" / "unified_evidence.json"
    
    # Check if P4 has already delivered a result
    if unified_path.exists():
        print(f"  [LOADED] Using existing unified_evidence.json")
        return _load_json(str(unified_path))

    # Import and run P4's aggregator
    try:
        sys.path.insert(0, str(ROOT_DIR))
        from src.aggregator.evidence_aggregator import aggregate_evidence
        print("  [LIVE] Running P4 aggregator...")
        return aggregate_evidence(
            case_context=case_context,
            raw_outputs_dir=str(ROOT_DIR / "output" / "raw"),
            output_path=str(unified_path)
        )
    except Exception as exc:
        print(f"  [ERROR] Aggregator failed: {exc}")
        _stub("Evidence Aggregator (P4)", "output/unified_evidence.json")
        return {"evidence_items": [], "generated_at": "", "total_items": 0}


# ── Stages 5 & 6: Anomaly Detector + XAI Explainer (P5 stubs) ────────────────

def run_ml_pipeline() -> dict:
    _stage(5, "Anomaly Detector + XAI Explainer", "P5")

    shap_path = ROOT_DIR / "output" / "shap_explanations.json"
    if shap_path.exists():
        print(f"  [LOADED] Using existing shap_explanations.json")
        return _load_json(str(shap_path))

    try:
        sys.path.insert(0, str(ROOT_DIR))
        from src.ml.pipeline import run_ml_pipeline as _run_p5
        print("  [LIVE] Running P5 ML pipeline...")
        result = _run_p5(
            input_path=str(ROOT_DIR / "output" / "unified_evidence.json"),
            output_path=str(shap_path),
            baseline_path=str(ROOT_DIR / "data" / "baseline_normal.json")
        )
        return result if result else {"explanations": [], "generated_at": ""}
    except Exception as exc:
        print(f"  [ERROR] ML pipeline failed: {exc}")
        _stub("ML Pipeline (P5)", "output/shap_explanations.json")
        return {"explanations": [], "generated_at": ""}


# ── Stage 7: Report Generator (P1 — Burst 2) ─────────────────────────────────

def run_report_generator(unified_evidence: dict, shap_explanations: dict,
                          case_context: dict) -> str:
    _stage(7, "Report Generator", "P1 — Burst 2")

    # Try to import the real report generator if it's been built
    try:
        from src.report_generator.report_generator import generate_report
        print("  [LIVE] Running report generator...")
        return generate_report(unified_evidence, shap_explanations, case_context)
    except ImportError:
        _stub("Report Generator (P1 Burst 2)", "output/final_report.md")
        # Write a placeholder report so the pipeline still produces output
        placeholder = f"""# AutoForensiq — Forensic Report (PLACEHOLDER)

**Case ID:** {case_context.get('case_id', 'N/A')}
**Case Type:** {case_context.get('case_type', 'N/A')}
**Generated:** {case_context.get('generated_at', 'N/A')}

> Report generator (P1 Burst 2) not yet integrated.
> Replace this placeholder once `src/report_generator/report_generator.py` is delivered.

## Incident Summary
{case_context.get('raw_incident_summary', 'N/A')}

## Hypotheses Under Investigation
{chr(10).join(f'- {h}' for h in case_context.get('hypotheses', []))}

## Evidence Sources Analysed
{chr(10).join(f'- {a}' for a in case_context.get('artifact_types', []))}
"""
        report_path = ROOT_DIR / "output" / "final_report.md"
        with open(report_path, "w") as f:
            f.write(placeholder)
        print(f"  [STUB]   Placeholder report written → {report_path}")
        return placeholder


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="AutoForensiq — Autonomous Digital Forensics Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python autoforensiq.py --report incident.txt
  python autoforensiq.py --report incident.txt --evidence memory.dmp network.pcap disk.img
  python autoforensiq.py --report incident.txt --evidence memory.dmp --mock
        """
    )
    parser.add_argument(
        "--report", required=True,
        help="Path to the plain-text incident report"
    )
    parser.add_argument(
        "--evidence", nargs="*", default=[],
        help="Paths to evidence files (memory dump, pcap, disk image, registry hive)"
    )
    parser.add_argument(
        "--mock", action="store_true",
        help="Force mock mode for the LLM classifier (no API key required)"
    )
    parser.add_argument(
        "--skip-tools", action="store_true",
        help="Skip tool execution (Stages 3–6). Useful when only testing the classifier."
    )
    return parser.parse_args()


def _map_evidence_files(paths: list) -> dict:
    """Map raw file paths to evidence type keys based on extension."""
    mapping = {}
    ext_map = {
        ".dmp":      "memory_dump",
        ".mem":      "memory_dump",
        ".pcap":     "pcap",
        ".pcapng":   "pcap",
        ".img":      "disk_image",
        ".dd":       "disk_image",
        ".dat":      "registry_hive",
        ".log":      "log_files",
        ".evtx":     "log_files",
    }
    key_map = {
        "memory_dump":   "memory_dump",
        "pcap":          "pcap",
        "disk_image":    "disk_image",
        "registry_hive": "registry_hive",
        "log_files":     "log_files",
    }
    for path in paths:
        ext  = Path(path).suffix.lower()
        name = Path(path).stem.lower()
        etype = ext_map.get(ext)
        if etype and etype not in mapping:
            mapping[etype] = path
    return mapping


def main():
    args = parse_args()

    print("\n" + "="*60)
    print("  AutoForensiq — Autonomous Forensics Pipeline")
    print("="*60)
    print(f"  Report:   {args.report}")
    print(f"  Evidence: {args.evidence or 'none provided'}")
    print(f"  Mock LLM: {args.mock}")

    _ensure_output_dir()
    os.chdir(ROOT_DIR)

    config_override = {"llm": {"mock_mode": True}} if args.mock else None

    # Stage 1 — Classifier
    case_context = run_classifier(args.report)

    if args.skip_tools:
        print("\n[SKIP] --skip-tools flag set. Stopping after Stage 1.")
        print(f"\n✔  case_context.json written to output/")
        return

    # Stage 2 — Tool Selector
    execution_plan = run_tool_selector(case_context)

    # Stage 3 — Orchestrator
    evidence_files = _map_evidence_files(args.evidence)
    raw_outputs    = run_orchestrator(execution_plan, evidence_files)

    # Stage 4 — Aggregator
    unified_evidence = run_aggregator(case_context)

    # Stages 5+6 — ML + XAI
    shap_explanations = run_ml_pipeline()

    # Stage 7 — Report Generator
    run_report_generator(unified_evidence, shap_explanations, case_context)

    print("\n" + "="*60)
    print("  PIPELINE COMPLETE")
    print("="*60)
    print(f"  case_type  : {case_context['case_type']}")
    print(f"  confidence : {case_context['classifier_confidence']}")
    print(f"  artifacts  : {', '.join(case_context['artifact_types'])}")
    print(f"  output/    : case_context.json · execution_plan.json · final_report.md")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
