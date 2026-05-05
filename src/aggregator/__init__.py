"""Evidence Aggregator Agent (P4)

Reads raw outputs from forensic tools (P3), normalizes, deduplicates,
and produces a consolidated unified_evidence.json for downstream analysis.

Module exports:
  - aggregate_evidence(case_context, raw_outputs_dir, output_path)
"""
