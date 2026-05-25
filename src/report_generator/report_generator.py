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


def _explanation_text(explanation):
    return (
        explanation.get("explain_instance")
        or explanation.get("plain_english")
        or explanation.get("reason")
        or ""
    )


def _score_summary(explanation):
    return {
        "model_score": explanation.get("model_score"),
        "rule_score": explanation.get("rule_score"),
        "final_score": explanation.get(
            "final_score",
            explanation.get("score")
        ),
        "threshold": explanation.get("threshold"),
        "confidence": explanation.get("confidence"),
        "severity": explanation.get("severity"),
    }


def _xai_payload(explanation):
    return {
        "summary": (
            explanation.get("plain_english")
            or explanation.get("reason")
            or _explanation_text(explanation)
        ),
        "explain_instance": _explanation_text(explanation),
        "scores": _score_summary(explanation),
        "top_factors": explanation.get("top_factors", []),
        "baseline_comparison": explanation.get("baseline_comparison", []),
        "machine_context": explanation.get("machine_context", {}),
        "correlation_context": explanation.get("correlation_context", []),
        "case_finding_context": explanation.get("case_finding_context", {}),
        "recommended_review": explanation.get("recommended_review", []),
    }


def _xai_lookup(shap_explanations, only_anomalies=False):
    lookup = {}

    for aid, item in _iter_explanations(shap_explanations):
        if only_anomalies and not item.get("is_anomaly"):
            continue

        lookup[aid] = _xai_payload(item)

    return lookup


def _format_score(value):
    if isinstance(value, (int, float)):
        return f"{value:+.4f}"
    return "N/A"


def _format_percent(value):
    if isinstance(value, (int, float)):
        return f"{value:.0%}"
    return "N/A"


def _format_top_factors(factors):
    if not factors:
        return "_No SHAP factors recorded._"

    lines = []
    for factor in factors[:5]:
        lines.append(
            "- "
            f"{factor.get('feature', 'unknown')}: "
            f"{factor.get('direction', 'unknown impact')} "
            f"(SHAP {_format_score(factor.get('shap_value'))}) — "
            f"{factor.get('meaning', 'No explanation available.')}"
        )

    return "\n".join(lines)


def _format_baseline_comparison(comparisons):
    if not comparisons:
        return "_No baseline comparison recorded._"

    lines = []
    for item in comparisons[:5]:
        lines.append(
            "- "
            f"{item.get('feature', 'unknown')}: "
            f"artifact={item.get('artifact_value', 'N/A')}, "
            f"baseline={item.get('baseline_average', 'N/A')}, "
            f"{item.get('direction', 'differs from baseline')}"
        )

    return "\n".join(lines)


def _format_correlation_context(correlations):
    if not correlations:
        return "_No P4 correlation context recorded._"

    lines = []
    for item in correlations[:5]:
        matches = item.get("matches") or []
        match_text = (
            f" using {', '.join(map(str, matches[:3]))}"
            if matches
            else ""
        )
        lines.append(
            "- "
            f"{item.get('artifact_id', 'unknown artifact')} via "
            f"{item.get('correlation_type', 'correlation')}"
            f"{match_text}"
        )

    return "\n".join(lines)


def _format_recommended_review(actions):
    if not actions:
        return "_No review actions recorded._"

    return "\n".join(f"- {action}" for action in actions[:5])


def _build_explainability_section(shap_explanations, max_items=8):
    items = [
        (aid, exp)
        for aid, exp in _iter_explanations(shap_explanations)
        if exp.get("is_anomaly")
    ]

    if not items:
        return "_No anomalous artifacts were available for XAI analysis._"

    sections = []

    for aid, exp in items[:max_items]:
        scores = _score_summary(exp)
        machine = exp.get("machine_context", {})
        machine_id = machine.get("machine_id") or "unknown"

        sections.append(
            "\n".join([
                f"### Artifact {aid}",
                "",
                f"- **Decision:** Anomalous",
                f"- **Severity:** {scores.get('severity', 'N/A')}",
                f"- **Confidence:** {_format_percent(scores.get('confidence'))}",
                f"- **Model Scope:** {exp.get('model_scope', 'N/A')}",
                f"- **Machine:** {machine_id}",
                f"- **Model Score:** {_format_score(scores.get('model_score'))}",
                f"- **Rule Score:** {_format_score(scores.get('rule_score'))}",
                f"- **Final Score:** {_format_score(scores.get('final_score'))}",
                f"- **Threshold:** {_format_score(scores.get('threshold'))}",
                "",
                "**Explanation**",
                "",
                _explanation_text(exp) or "_No explanation text recorded._",
                "",
                "**Top Contributing Factors**",
                "",
                _format_top_factors(exp.get("top_factors", [])),
                "",
                "**Baseline Comparison**",
                "",
                _format_baseline_comparison(
                    exp.get("baseline_comparison", [])
                ),
                "",
                "**P4 Correlation Context**",
                "",
                _format_correlation_context(
                    exp.get("correlation_context", [])
                ),
                "",
                "**Recommended Review**",
                "",
                _format_recommended_review(
                    exp.get("recommended_review", [])
                ),
            ])
        )

    return "\n\n".join(sections)


# ─────────────────────────────────────────────────────────────
# USER PROMPT BUILDER
# ─────────────────────────────────────────────────────────────

def _build_user_prompt(
    unified_evidence,
    shap_explanations,
    case_context
):

    xai_lookup = _xai_lookup(
        shap_explanations,
        only_anomalies=True
    )

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

        if aid in xai_lookup:

            item["_xai"] = xai_lookup[aid]

    prompt_parts = [

        "## Case Context",

        json.dumps(case_context, indent=2),

        "",

        "## Evidence",

        json.dumps(priority_items, indent=2),

        "",

        "## Explainability Analysis",

        _build_explainability_section(shap_explanations),

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

    xai_lookup = _xai_lookup(
        shap_explanations,
        only_anomalies=True
    )

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

    evidence_items = unified_evidence.get(
        "evidence_items",
        []
    )

    total = unified_evidence.get(
        "total_items",
        len(evidence_items)
    )

    n_anomalies = len(xai_lookup)

    generated = datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    priority_items = [

            e for e in evidence_items

        if isinstance(e, dict)
        and e.get("severity") in (
            "critical",
            "high"
        )
    ][:15]

    if not priority_items:

        priority_items = evidence_items[:10]

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

        xai = xai_lookup.get(aid, {})
        shap_note = xai.get("summary", "—")

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

## Explainability Analysis

{_build_explainability_section(shap_explanations)}

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
