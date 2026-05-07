"""
AutoForensiq — Report Generator (P1 Burst 2)
=============================================
Consumes unified_evidence.json + shap_explanations.json + case_context
and produces a structured Markdown forensic report via LLM.

Supports:
  - Anthropic Claude  (set llm.provider: "anthropic" in config.yaml)
  - OpenAI GPT-4o     (set llm.provider: "openai"    in config.yaml)
  - Mock mode         (set llm.mock_mode: true — builds report from data, no LLM)
"""

import json
import os
import yaml
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────

ROOT_DIR    = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT_DIR / "config.yaml"

# ── Config loader ─────────────────────────────────────────────────────────────

def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"config.yaml not found at {CONFIG_PATH}")
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


# ── Prompt builder ────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior digital forensics analyst writing a formal incident report.

You will be given structured evidence data from an automated forensic pipeline and must produce
a clear, professional Markdown report. The report must be suitable for both technical responders
and non-technical stakeholders (management, legal).

Write the report using EXACTLY this structure — no extra sections, no preamble:

# Forensic Investigation Report

## Executive Summary
2–3 plain-English sentences. No jargon. Describe what happened, what was affected, and the
current status. Suitable for a non-technical executive.

## Case Classification
- **Case Type:** <case_type>
- **Confidence:** <classifier_confidence as %>
- **Case ID:** <case_id>
- **Generated:** <timestamp>

## Critical Findings
A table with columns: | Severity | Artifact | Tool | Finding | Explanation |
Sort rows critical → high → medium → low. Only include anomalous or high/critical items.
Explanation column should use the SHAP reason if the artifact was flagged as anomalous.

## Reconstructed Attack Timeline
A chronological bullet list of events inferred from the evidence. Use timestamps where available.
If timestamps are unavailable, use relative ordering (e.g. "Step 1", "Step 2").

## Hypotheses Evaluated
For each hypothesis provided, state whether the evidence supports, refutes, or is inconclusive.
Format: **Hypothesis:** <text> → **Verdict:** Supported / Refuted / Inconclusive

## Tools and Evidence Coverage
A brief sentence per tool used, summarising what it contributed.

## Audit Trail
State that a SHA-256 audit log was generated at output/audit_log.json and can be used to verify
evidence integrity for legal admissibility.

Rules:
- Write in professional British English.
- Do NOT include any text before the # Forensic Investigation Report heading.
- Do NOT include any text after the ## Audit Trail section.
- Keep the Executive Summary under 80 words.
- The Critical Findings table must have a header row and a separator row."""


def _build_user_prompt(
    unified_evidence: dict,
    shap_explanations: dict,
    case_context: dict,
) -> str:
    """Build the user-turn prompt from the three data sources."""

    # Build anomaly lookup: artifact_id → reason
    anomaly_lookup = {}
    for item in shap_explanations.get("explanations", []):
        if item.get("is_anomaly"):
            anomaly_lookup[item["artifact_id"]] = item.get("reason", "")

    # Collect critical/high evidence items (limit to top 20 to stay within token limits)
    priority_items = [
        e for e in unified_evidence.get("evidence_items", [])
        if e.get("severity") in ("critical", "high")
    ][:20]

    # Fall back to all items if nothing critical/high
    if not priority_items:
        priority_items = unified_evidence.get("evidence_items", [])[:20]

    # Annotate each item with its SHAP reason if flagged
    for item in priority_items:
        aid = item.get("artifact_id", "")
        if aid in anomaly_lookup:
            item["_shap_reason"] = anomaly_lookup[aid]

    prompt_parts = [
        "## Case Context",
        json.dumps(case_context, indent=2),
        "",
        "## Top Evidence Items (sorted by severity)",
        json.dumps(priority_items, indent=2),
        "",
        "## Anomaly Detection Summary",
        f"Total items analysed: {len(unified_evidence.get('evidence_items', []))}",
        f"Anomalies flagged: {sum(1 for e in shap_explanations.get('explanations', []) if e.get('is_anomaly'))}",
        "",
        "## Tools That Ran",
        ", ".join(unified_evidence.get("tools_aggregated", [])) or "None recorded",
    ]

    return "\n".join(prompt_parts)


# ── LLM callers ───────────────────────────────────────────────────────────────

def _call_anthropic(user_prompt: str, cfg: dict) -> str:
    import anthropic
    api_key = os.environ.get(cfg["llm"].get("anthropic_api_key_env", "ANTHROPIC_API_KEY"))
    client  = anthropic.Anthropic(api_key=api_key)
    model   = cfg["llm"].get("anthropic_model", "claude-sonnet-4-6")
    message = client.messages.create(
        model=model,
        max_tokens=cfg["llm"].get("max_tokens", 2048),
        temperature=cfg["llm"].get("temperature", 0.2),
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return message.content[0].text


def _call_openai(user_prompt: str, cfg: dict) -> str:
    from openai import OpenAI
    api_key = os.environ.get(cfg["llm"].get("openai_api_key_env", "OPENAI_API_KEY"))
    client  = OpenAI(api_key=api_key)
    model   = cfg["llm"].get("openai_model", "gpt-4o")
    resp = client.chat.completions.create(
        model=model,
        max_tokens=cfg["llm"].get("max_tokens", 2048),
        temperature=cfg["llm"].get("temperature", 0.2),
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt},
        ],
    )
    return resp.choices[0].message.content


# ── Mock report builder ───────────────────────────────────────────────────────

def _mock_report(
    unified_evidence: dict,
    shap_explanations: dict,
    case_context: dict,
) -> str:
    """Build a structured Markdown report from data alone — no LLM required."""

    anomaly_lookup = {}
    for item in shap_explanations.get("explanations", []):
        if item.get("is_anomaly"):
            anomaly_lookup[item["artifact_id"]] = item.get("reason", "")

    case_type  = case_context.get("case_type", "unknown").replace("_", " ").title()
    confidence = case_context.get("classifier_confidence", 0.0)
    case_id    = case_context.get("case_id", "N/A")
    summary    = case_context.get("raw_incident_summary", "No summary available.")
    hypotheses = case_context.get("hypotheses", [])
    tools_ran  = unified_evidence.get("tools_aggregated", [])
    total      = unified_evidence.get("total_items", 0)
    n_anomalies = sum(1 for e in shap_explanations.get("explanations", []) if e.get("is_anomaly"))
    generated  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Critical findings table
    priority_items = [
        e for e in unified_evidence.get("evidence_items", [])
        if e.get("severity") in ("critical", "high")
    ][:15]

    if not priority_items:
        priority_items = unified_evidence.get("evidence_items", [])[:10]

    table_rows = ["| Severity | Artifact | Tool | Finding | Explanation |",
                  "|----------|----------|------|---------|-------------|"]
    for item in priority_items:
        aid        = item.get("artifact_id", "")
        shap_note  = anomaly_lookup.get(aid, "—")
        row = (
            f"| {item.get('severity','—').upper()} "
            f"| {item.get('evidence_type','—')} "
            f"| {item.get('source_tool','—')} "
            f"| {str(item.get('value','—'))[:60]} "
            f"| {shap_note} |"
        )
        table_rows.append(row)

    findings_table = "\n".join(table_rows)

    # Hypotheses section
    hyp_lines = []
    for h in hypotheses:
        hyp_lines.append(f"**Hypothesis:** {h} → **Verdict:** Inconclusive (manual review required)")
    hyp_section = "\n\n".join(hyp_lines) if hyp_lines else "_No hypotheses recorded._"

    # Tools section
    tool_lines = "\n".join(f"- **{t}**: contributed evidence items to unified_evidence.json" for t in tools_ran) \
                 if tools_ran else "_No tool outputs recorded._"

    report = f"""# Forensic Investigation Report

## Executive Summary
{summary} Automated analysis identified {n_anomalies} anomalous artifact(s) from {total} total evidence items across {len(tools_ran)} forensic tool(s). Immediate analyst review is recommended for all critical and high severity findings.

## Case Classification
- **Case Type:** {case_type}
- **Confidence:** {confidence:.0%}
- **Case ID:** {case_id}
- **Generated:** {generated}

## Critical Findings

{findings_table}

## Reconstructed Attack Timeline
_Timeline reconstruction requires manual analyst review of the evidence items in output/unified_evidence.json, cross-referenced with the audit log at output/audit_log.json._

## Hypotheses Evaluated

{hyp_section}

## Tools and Evidence Coverage

{tool_lines}

## Audit Trail
A SHA-256 audit log was generated at `output/audit_log.json` and records the hash of every evidence file before and after each tool invocation. This log can be used to verify evidence integrity for legal admissibility purposes.
"""
    return report.strip()


# ── Main public function ──────────────────────────────────────────────────────

def generate_report(
    unified_evidence: dict,
    shap_explanations: dict,
    case_context: dict,
    output_path: str | None = None,
    config_override: dict | None = None,
) -> str:
    """
    Generate a Markdown forensic report from pipeline outputs.

    Args:
        unified_evidence:  Parsed output of evidence_aggregator (unified_evidence.json)
        shap_explanations: Parsed output of ml pipeline (shap_explanations.json)
        case_context:      Parsed output of intent classifier (case_context.json)
        output_path:       Where to write final_report.md (default: output/final_report.md)
        config_override:   Dict to override specific config values (e.g. {"llm": {"mock_mode": True}})

    Returns:
        The report as a Markdown string.
    """
    cfg = _load_config()
    if config_override:
        for k, v in config_override.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v

    mock_mode = cfg.get("llm", {}).get("mock_mode", False)
    provider  = cfg.get("llm", {}).get("provider", "anthropic")

    if mock_mode:
        print("  [MOCK] Building report from data (no LLM call).")
        report_text = _mock_report(unified_evidence, shap_explanations, case_context)
    else:
        user_prompt = _build_user_prompt(unified_evidence, shap_explanations, case_context)
        try:
            if provider == "openai":
                print(f"  [LIVE] Calling OpenAI ({cfg['llm'].get('openai_model', 'gpt-4o')})...")
                report_text = _call_openai(user_prompt, cfg)
            else:
                print(f"  [LIVE] Calling Anthropic ({cfg['llm'].get('anthropic_model', 'claude-sonnet-4-6')})...")
                report_text = _call_anthropic(user_prompt, cfg)
        except Exception as exc:
            print(f"  [WARN] LLM call failed ({exc}). Falling back to mock report.")
            report_text = _mock_report(unified_evidence, shap_explanations, case_context)

    # Write to disk
    if output_path is None:
        output_path = str(ROOT_DIR / "output" / "final_report.md")

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(f"  [DONE] Report written → {output_path}")
    return report_text
