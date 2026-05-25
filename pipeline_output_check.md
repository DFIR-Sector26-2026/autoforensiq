# AutoForensiq Pipeline Output Check

## What Was Checked

This check looked at the current files inside `output/` and compared the ML/XAI output with what the final report generator expects.

No pipeline run was performed during this check.

## Current Output Files

The current `output/` directory contains:

```text
output/shap_explanations.json
```

The following expected pipeline files are currently missing:

```text
output/unified_evidence.json
output/final_report.md
```

## Unified Evidence Status

`output/unified_evidence.json` does not currently exist.

Result:

```text
unified_evidence.json exists: False
unified evidence items: 0
```

This means the current saved SHAP output cannot be cross-checked against a saved unified evidence file in `output/`.

## SHAP Explanation Status

`output/shap_explanations.json` does exist.

The saved SHAP output contains:

```text
scored items: 10
anomalies: 8
normal items: 2
```

The first scored artifact IDs are:

```text
EVT-001
EVT-002
EVT-003
EVT-004
EVT-005
```

The SHAP summary reports these model scopes:

```json
{
  "process": {
    "evidence_records": 4,
    "baseline_scope": "process",
    "baseline_records_used": 2
  },
  "network": {
    "evidence_records": 3,
    "baseline_scope": "network",
    "baseline_records_used": 3
  },
  "file": {
    "evidence_records": 3,
    "baseline_scope": "all",
    "baseline_records_used": 5
  }
}
```

## Main Problem Found

The ML/XAI output has anomaly results, but the report generator is not reading them correctly.

The SHAP file stores explanations as a dictionary:

```json
{
  "explanations": {
    "EVT-001": {
      "is_anomaly": true
    },
    "EVT-002": {
      "is_anomaly": true
    }
  }
}
```

But the report generator expects `explanations` to be a list.

In `src/report_generator/report_generator.py`, the code does:

```python
explanations = shap_explanations.get(
    "explanations",
    []
)

if not isinstance(explanations, list):
    explanations = []
```

Because the real SHAP output is a dictionary, the report generator replaces it with an empty list.

That causes this incorrect report result:

```text
Automated analysis identified 0 anomalous artifact(s)
```

Even though the SHAP file actually contains:

```text
8 anomalies out of 10 scored items
```

## Current Diagnosis

The issue is not that ML scoring is producing zero anomalies.

The issue is:

```text
SHAP explanations are generated as a dict.
Report generator expects a list.
Report generator discards the SHAP explanations.
Final report counts 0 anomalies.
```

## Explanation Quality Issue

The current SHAP output includes useful structured fields:

```json
{
  "top_factors": [],
  "baseline_comparison": [],
  "recommended_review": []
}
```

But the final explanation still reads too much like key-value data.

The project should include a stronger per-artifact explain instance written in full analyst-facing sentences.

## Better Explain Instance Example

For a suspicious network artifact such as `EVT-002`, the explanation should look more like:

```text
Artifact EVT-002 was classified as anomalous because the network connection used port 4444, a known command-and-control port, and the artifact text contained C2-related indicators. Compared with the normal network baseline, this artifact differs strongly because normal baseline traffic did not include known C2 ports or C2 keywords. The final score was -0.95, which is below the anomaly threshold of -0.10, with 100% confidence. An analyst should verify the destination IP reputation, inspect related network sessions, and correlate this connection with process activity on the source host.
```

## Recommended Fixes

1. Make the report generator handle SHAP explanations stored as a dictionary.

2. Count anomalies from:

```python
shap_explanations["explanations"].values()
```

instead of assuming `explanations` is a list.

3. Connect `unified_evidence.json` and `shap_explanations.json` by matching:

```text
artifact_id
```

4. Add a full prose `explain_instance` field per artifact.

5. Update the final report so it uses:

```text
plain_english
technical_explanation
baseline_comparison
top_factors
recommended_review
```

instead of only short key-value-style SHAP notes.

## Bottom Line

The ML/XAI stage is producing anomaly scores.

The current saved SHAP file says:

```text
10 items scored
8 anomalies found
```

The final report shows zero anomalies because the report generator is not correctly reading the SHAP output format.

