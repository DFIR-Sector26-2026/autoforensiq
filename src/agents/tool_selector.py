"""Dynamic Tool Selector Agent.

Reads a structured case context and the forensic tool ontology, then
produces an execution_plan.json compatible with src.orchestrator.WRAPPER_MAP.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
from typing import Any


DEFAULT_ONTOLOGY_PATH = "src/data/tool_ontology.json"
DEFAULT_OUTPUT_PATH = "output/execution_plan.json"

# The selector only needs these fields from P1's case_context.json.
REQUIRED_CONTEXT_FIELDS = ("case_type", "artifact_types")

# Every ontology tool must expose these fields so the selector can decide eligibility, ranking,
# ordering, and final execution_plan args.
REQUIRED_TOOL_FIELDS = (
    "name",
    "input_types",
    "case_relevance",
    "dependencies",
    "default_order",
    "args_template",
)

# Keep aligned with orchestrator.WRAPPER_MAP — unlisted tools get skipped there.
SUPPORTED_WRAPPER_NAMES = {
    "volatility3",
    "tshark",
    "tsk_fls",
    "regripper",
    "plaso",
    "memprocfs",
    # email/browser were once missing here + in the ontology, so the DTSA could never select them
    # (D4).
    "email",
    "browser",
}

# Built-in paths for learning and quick testing. Use with: python3 -m src.agents.tool_selector
# --sample ransomware_all --stdout
SAMPLE_CASE_CONTEXT_PATHS = {
    "ransomware_all": ".selector_test_cases/ransomware_all.json",
    "pcap_only_network_intrusion": ".selector_test_cases/pcap_only_network_intrusion.json",
    "memory_only_malware_execution": ".selector_test_cases/memory_only_malware_execution.json",
    "registry_only_persistence": ".selector_test_cases/registry_only_persistence.json",
    "disk_only_ransomware": ".selector_test_cases/disk_only_ransomware.json",
    "unknown_pcap": ".selector_test_cases/unknown_pcap.json",
}


def load_json(path: str) -> dict[str, Any]:
    """Load a JSON object from disk."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def write_json(path: str, data: dict[str, Any]) -> None:
    """Write a JSON object to disk, creating the parent directory if needed."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def validate_case_context(context: dict[str, Any]) -> None:
    """Validate the minimum selector input contract."""
    missing = []

    for field in REQUIRED_CONTEXT_FIELDS:
        if field not in context:
            missing.append(field)

    if missing:
        missing_fields = ", ".join(missing)
        raise ValueError(f"case_context missing required fields: {missing_fields}")

    case_type = context["case_type"]
    if not isinstance(case_type, str) or not case_type.strip():
        raise ValueError("case_context.case_type must be a non-empty string")

    artifact_types = context["artifact_types"]
    if not isinstance(artifact_types, list) or not artifact_types:
        raise ValueError("case_context.artifact_types must be a non-empty list")

    for artifact_type in artifact_types:
        if not isinstance(artifact_type, str) or not artifact_type.strip():
            raise ValueError("case_context.artifact_types must contain only strings")


def validate_ontology(ontology: dict[str, Any]) -> None:
    """Validate ontology structure and wrapper compatibility."""
    tools = ontology.get("tools")

    if not isinstance(tools, list) or not tools:
        raise ValueError("tool ontology must contain a non-empty 'tools' list")

    seen_names: set[str] = set()

    for index, tool in enumerate(tools):

        if not isinstance(tool, dict):
            raise ValueError(f"ontology tool at index {index} must be an object")

        missing = []
        for field in REQUIRED_TOOL_FIELDS:
            if field not in tool:
                missing.append(field)

        if missing:
            name = tool.get("name", f"index {index}")
            missing_fields = ", ".join(missing)
            raise ValueError(f"ontology tool {name} missing fields: {missing_fields}")

        name = tool["name"]

        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"ontology tool at index {index} has invalid name")

        if name in seen_names:
            raise ValueError(f"duplicate ontology tool name: {name}")
        seen_names.add(name)

        # Catch ontology/orchestrator drift early — P3 owns the wrapper names.
        if name not in SUPPORTED_WRAPPER_NAMES:
            raise ValueError(f"ontology tool '{name}' is not supported by orchestrator")

        if not isinstance(tool["input_types"], list):
            raise ValueError(f"ontology tool '{name}' input_types must be a list")

        if not isinstance(tool["case_relevance"], dict):
            raise ValueError(f"ontology tool '{name}' case_relevance must be an object")

        if not isinstance(tool["dependencies"], list):
            raise ValueError(f"ontology tool '{name}' dependencies must be a list")

        if not isinstance(tool["default_order"], int):
            raise ValueError(f"ontology tool '{name}' default_order must be an integer")

        if not isinstance(tool["args_template"], dict):
            raise ValueError(f"ontology tool '{name}' args_template must be an object")


def tool_matches_artifacts(tool: dict[str, Any], artifact_types: set[str]) -> bool:
    """Return True if the tool can process at least one available artifact."""
    for input_type in tool["input_types"]:
        if input_type in artifact_types:
            return True

    return False


def relevance_score(tool: dict[str, Any], case_type: str) -> float:
    """Return case-specific relevance, falling back to unknown or neutral."""
    relevance = tool.get("case_relevance", {})
    # Unknown case types must not break planning: "unknown" fallback, else 0.5.
    score = relevance.get(case_type, relevance.get("unknown", 0.5))
    try:
        return float(score)
    except (TypeError, ValueError):
        return 0.5


def select_tools(
    context: dict[str, Any],
    ontology: dict[str, Any],
) -> list[dict[str, Any]]:
    """Filter and rank tools using artifact availability and case relevance."""
    validate_case_context(context)
    validate_ontology(ontology)

    artifact_types = set(context["artifact_types"])
    case_type = context["case_type"]

    # Gate by artifact availability so a pcap-only case doesn't select disk/memory tools.
    selected = []

    for tool in ontology["tools"]:
        if tool_matches_artifacts(tool, artifact_types):
            selected.append(copy.deepcopy(tool))

    # Transient sort key only — not written to execution_plan.json.
    for tool in selected:
        tool["_relevance_score"] = relevance_score(tool, case_type)

    selected.sort(key=tool_sort_key)
    return selected


def tool_sort_key(tool: dict[str, Any]) -> tuple[float, int, str]:
    """Sort highest relevance first, then stable ontology order."""
    relevance = -tool["_relevance_score"]
    default_order = tool["default_order"]
    name = tool["name"]

    return relevance, default_order, name


def resolve_dependencies(selected_tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order selected tools so dependencies come first.

    Dependencies that are not selected are ignored. This keeps evidence-directory
    only Plaso runs possible without forcing unavailable disk-image tools.
    """
    by_name = {}
    for tool in selected_tools:
        by_name[tool["name"]] = tool
    ordered: list[dict[str, Any]] = []
    temporary: set[str] = set()
    permanent: set[str] = set()

    def visit(name: str) -> None:
        # DFS-based topological ordering. temporary detects dependency cycles; permanent marks tools
        # already added to the final order.
        if name in permanent:
            return
        if name in temporary:
            raise ValueError(f"cyclic tool dependency detected at '{name}'")

        temporary.add(name)
        tool = by_name[name]
        for dependency in tool.get("dependencies", []):
            # Unselected dependencies are ignored (artifact filtering may have excluded them) —
            # don't invent tools for unavailable evidence.
            if dependency in by_name:
                visit(dependency)

        temporary.remove(name)
        permanent.add(name)
        ordered.append(tool)

    tools_by_default_order = sorted(
        selected_tools,
        key=lambda item: item["default_order"],
    )

    for tool in tools_by_default_order:
        visit(tool["name"])

    return ordered


def build_execution_plan(selected_tools: list[dict[str, Any]]) -> dict[str, Any]:
    """Convert selected ontology tools into orchestrator execution_plan format."""
    ordered_tools = resolve_dependencies(selected_tools)
    plan_tools = []

    for order, tool in enumerate(ordered_tools, start=1):
        # args_template is copied directly from the ontology because the current orchestrator
        # expects args keys like image/pcap/hive/source.
        plan_tools.append(
            {
                "name": tool["name"],
                "order": order,
                "args": copy.deepcopy(tool["args_template"]),
            }
        )

    return {"tools": plan_tools}


def generate_execution_plan(
    case_context: dict[str, Any],
    ontology: dict[str, Any],
) -> dict[str, Any]:
    """Generate an execution plan from case context and ontology."""
    selected_tools = select_tools(case_context, ontology)
    return build_execution_plan(selected_tools)


def load_case_context(args: argparse.Namespace) -> dict[str, Any]:
    """Load case context either from a file or from built-in examples."""
    if args.sample:
        sample_path = SAMPLE_CASE_CONTEXT_PATHS[args.sample]
        return load_json(sample_path)

    return load_json(args.context)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate AutoForensiq execution_plan.json")

    parser.add_argument(
        "--context",
        required=False,
        help="Path to case_context.json from the intent classifier",
    )

    parser.add_argument(
        "--sample",
        help="Use a built-in sample case context instead of --context",
    )

    parser.add_argument(
        "--ontology",
        default=DEFAULT_ONTOLOGY_PATH,
        help=f"Path to tool ontology JSON. Default: {DEFAULT_ONTOLOGY_PATH}",
    )

    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_PATH,
        help=f"Path to write execution plan. Default: {DEFAULT_OUTPUT_PATH}",
    )

    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print generated execution plan to stdout instead of writing a file",
    )

    args = parser.parse_args()

    if not args.context and not args.sample:
        parser.error("provide either --context or --sample")

    if args.context and args.sample:
        parser.error("use only one of --context or --sample")

    return args


def main() -> None:
    args = parse_args()

    context = load_case_context(args)
    ontology = load_json(args.ontology)
    plan = generate_execution_plan(context, ontology)

    # --stdout is useful for tests, shell pipelines, and quick inspection without
    # creating output/execution_plan.json.
    if args.stdout:
        print(json.dumps(plan, indent=2))
        return

    write_json(args.output, plan)
    print(f"[OK] execution plan written to {args.output}")


if __name__ == "__main__":
    main()
