"""
AutoForensiq — Report Generator
"""

import json
import os
import yaml

from datetime import datetime, timezone
from pathlib import Path


# ─────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────

ROOT_DIR = Path(__file__).resolve().parents[2]

CONFIG_PATH = ROOT_DIR / "config.yaml"


# ─────────────────────────────────────────────────────────────
# CONFIG LOADER
# ─────────────────────────────────────────────────────────────

def _load_config():

    if not CONFIG_PATH.exists():

        raise FileNotFoundError(
            f"config.yaml not found at {CONFIG_PATH}"
        )

    with open(CONFIG_PATH) as f:

        return yaml.safe_load(f)


# ─────────────────────────────────────────────────────────────
# SYSTEM PROMPT
# ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """
You are a senior digital forensics analyst.

Write a professional forensic report in Markdown.
"""


# ─────────────────────────────────────────────────────────────
# EXPLANATION SHAPE NORMALISER
# ─────────────────────────────────────────────────────────────

def _iter_explanations(shap_explanations):
    """Yield (artifact_id, explanation) pairs from the P5 output.

    pipeline.py emits `explanations` as a dict keyed by artifact_id; the
    error-fallback path in autoforensiq.py emits an empty list. Support both.
    """
    explanations = shap_explanations.get("explanations", {})

    if isinstance(explanations, dict):
        for aid, exp in explanations.items():
            if isinstance(exp, dict):
                yield aid, exp

    elif isinstance(explanations, list):
        for exp in explanations:
            if isinstance(exp, dict):
                yield exp.get("artifact_id", ""), exp


# ─────────────────────────────────────────────────────────────
# USER PROMPT BUILDER
# ─────────────────────────────────────────────────────────────

def _build_user_prompt(
    unified_evidence,
    shap_explanations,
    case_context
):

    anomaly_lookup = {
        aid: item.get("reason", "")
        for aid, item in _iter_explanations(shap_explanations)
        if item.get("is_anomaly")
    }

    priority_items = [

        e for e in unified_evidence.get(
            "evidence_items",
            []
        )

        if isinstance(e, dict)
        and e.get("severity") in (
            "critical",
            "high"
        )
    ][:20]

    if not priority_items:

        priority_items = unified_evidence.get(
            "evidence_items",
            []
        )[:20]

    for item in priority_items:

        if not isinstance(item, dict):
            continue

        aid = item.get("artifact_id", "")

        if aid in anomaly_lookup:

            item["_shap_reason"] = anomaly_lookup[aid]

    prompt_parts = [

        "## Case Context",

        json.dumps(case_context, indent=2),

        "",

        "## Evidence",

        json.dumps(priority_items, indent=2),

        "",

        "## Tools",

        ", ".join(
            unified_evidence.get(
                "tools_aggregated",
                []
            )
        )
    ]

    return "\n".join(prompt_parts)


# ─────────────────────────────────────────────────────────────
# OPENAI CALLER
# ─────────────────────────────────────────────────────────────

def _call_openai(user_prompt, cfg):

    from openai import OpenAI

    api_key = os.environ.get(
        cfg["llm"].get(
            "openai_api_key_env",
            "OPENAI_API_KEY"
        )
    )

    client = OpenAI(api_key=api_key)

    model = cfg["llm"].get(
        "openai_model",
        "gpt-4o"
    )

    resp = client.chat.completions.create(

        model=model,

        max_tokens=cfg["llm"].get(
            "max_tokens",
            2048
        ),

        temperature=cfg["llm"].get(
            "temperature",
            0.2
        ),

        messages=[

            {
                "role": "system",
                "content": SYSTEM_PROMPT
            },

            {
                "role": "user",
                "content": user_prompt
            }
        ]
    )

    return resp.choices[0].message.content


# ─────────────────────────────────────────────────────────────
# MOCK REPORT BUILDER
# ─────────────────────────────────────────────────────────────

def _mock_report(
    unified_evidence,
    shap_explanations,
    case_context
):

    anomaly_lookup = {
        aid: item.get("reason", "")
        for aid, item in _iter_explanations(shap_explanations)
        if item.get("is_anomaly")
    }

    case_type = case_context.get(
        "case_type",
        "unknown"
    ).replace("_", " ").title()

    confidence = case_context.get(
        "classifier_confidence",
        0.0
    )

    case_id = case_context.get(
        "case_id",
        "N/A"
    )

    summary = case_context.get(
        "raw_incident_summary",
        "No summary available."
    )

    hypotheses = case_context.get(
        "hypotheses",
        []
    )

    tools_ran = unified_evidence.get(
        "tools_aggregated",
        []
    )

    total = unified_evidence.get(
        "total_items",
        0
    )

    n_anomalies = len(anomaly_lookup)

    generated = datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    priority_items = [

        e for e in unified_evidence.get(
            "evidence_items",
            []
        )

        if isinstance(e, dict)
        and e.get("severity") in (
            "critical",
            "high"
        )
    ][:15]

    if not priority_items:

        priority_items = unified_evidence.get(
            "evidence_items",
            []
        )[:10]

    table_rows = [

        "| Severity | Artifact | Tool | Finding | Explanation |",

        "|----------|----------|------|---------|-------------|"
    ]

    for item in priority_items:

        if not isinstance(item, dict):
            continue

        aid = item.get(
            "artifact_id",
            ""
        )

        shap_note = anomaly_lookup.get(
            aid,
            "—"
        )

        row = (

            f"| {item.get('severity','—').upper()} "

            f"| {item.get('evidence_type','—')} "

            f"| {item.get('source_tool','—')} "

            f"| {str(item.get('value','—'))[:60]} "

            f"| {shap_note} |"
        )

        table_rows.append(row)

    findings_table = "\n".join(table_rows)

    hyp_lines = []

    for h in hypotheses:

        hyp_lines.append(

            f"**Hypothesis:** {h} → "
            f"**Verdict:** Inconclusive"
        )

    hyp_section = (

        "\n\n".join(hyp_lines)

        if hyp_lines

        else "_No hypotheses recorded._"
    )

    tool_lines = (

        "\n".join(

            f"- **{t}**: contributed evidence"

            for t in tools_ran
        )

        if tools_ran

        else "_No tool outputs recorded._"
    )

    report = f"""
# Forensic Investigation Report

## Executive Summary

{summary}

Automated analysis identified {n_anomalies} anomalous artifact(s)
from {total} total evidence items across {len(tools_ran)} forensic tool(s).

Immediate analyst review is recommended.

## Case Classification

- **Case Type:** {case_type}
- **Confidence:** {confidence:.0%}
- **Case ID:** {case_id}
- **Generated:** {generated}

## Critical Findings

{findings_table}

## Reconstructed Attack Timeline

Manual analyst review recommended.

## Hypotheses Evaluated

{hyp_section}

## Tools and Evidence Coverage

{tool_lines}

## Audit Trail

A SHA-256 audit log was generated at
`output/audit_log.json`
and can be used to verify evidence integrity.
"""

    return report.strip()


# ─────────────────────────────────────────────────────────────
# MAIN PUBLIC FUNCTION
# ─────────────────────────────────────────────────────────────

def generate_report(
    unified_evidence,
    shap_explanations,
    case_context,
    output_path=None,
    config_override=None
):

    cfg = _load_config()

    if config_override:

        for k, v in config_override.items():

            if (
                isinstance(v, dict)
                and isinstance(cfg.get(k), dict)
            ):

                cfg[k].update(v)

            else:

                cfg[k] = v

    mock_mode = cfg.get(
        "llm",
        {}
    ).get(
        "mock_mode",
        False
    )

    provider = cfg.get(
        "llm",
        {}
    ).get(
        "provider",
        "openai"
    )

    # MOCK MODE
    if mock_mode:

        print(
            "  [MOCK] Building report from data."
        )

        report_text = _mock_report(
            unified_evidence,
            shap_explanations,
            case_context
        )

    else:

        user_prompt = _build_user_prompt(
            unified_evidence,
            shap_explanations,
            case_context
        )

        try:

            print(
                f"  [LIVE] Calling {provider}..."
            )

            report_text = _call_openai(
                user_prompt,
                cfg
            )

        except Exception as exc:

            print(
                f"  [WARN] LLM failed ({exc})"
            )

            print(
                "  [FALLBACK] Using mock report."
            )

            report_text = _mock_report(
                unified_evidence,
                shap_explanations,
                case_context
            )

    # WRITE REPORT
    if output_path is None:

        output_path = str(
            ROOT_DIR
            / "output"
            / "final_report.md"
        )

    Path(output_path).parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(report_text)

    print(
        f"  [DONE] Report written → {output_path}"
    )

    return report_text
