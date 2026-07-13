"""Grow data/baseline_normal.json from a pipeline run over KNOWN-BENIGN evidence (5.3): keeps only
unflagged low-severity items (no ioc_match, no *_status), deduped and capped per ML scope."""

import json
import sys
from pathlib import Path

from src.ml.anomaly_detector import RULE_BOOSTS
from src.ml.feature_engineering import extract_features
from src.ml.pipeline import _model_scope

BASELINE_FIELDS = ("artifact_id", "source_tool", "evidence_type", "timestamp",
                   "value", "severity", "confidence", "linked_artifacts")
# Per-run, per-scope ceiling so one chatty tool can't drown the other scopes.
CAP_PER_SCOPE = 300


def _is_benign_record(item: dict) -> bool:
    """Conservative filter: only items the rule path saw NOTHING wrong with may enter the
    baseline — a planted IOC in a 'benign' sample must not get labeled normal."""
    if str(item.get("severity", "")).lower() != "low":
        return False
    if item.get("ioc_match"):
        return False
    if str(item.get("evidence_type", "")).endswith("_status"):
        return False
    # A record lighting any rule-penalized feature is never certifiably benign — it would teach
    # the detector that rule-punished deviations are normal (the rundll32/cmd.exe poisoning).
    features = extract_features(item)
    if any(features[i] for i in RULE_BOOSTS):
        return False
    return bool(str(item.get("value", "")).strip())


def _normalize(item: dict) -> dict:
    rec = {k: item.get(k, "") for k in BASELINE_FIELDS}
    rec["linked_artifacts"] = []  # links point into the source case, meaningless in a baseline
    return rec


def harvest_baseline(unified_path: str, baseline_path: str,
                     cap_per_scope: int = CAP_PER_SCOPE) -> dict:
    """Append benign records from `unified_path` to `baseline_path`; returns per-scope counts of
    newly added records. Dedupes against the existing baseline by (tool, type, value)."""
    unified = json.loads(Path(unified_path).read_text())
    items = unified.get("evidence_items", [])

    baseline_file = Path(baseline_path)
    baseline = json.loads(baseline_file.read_text()) if baseline_file.exists() else []
    seen = {(r.get("source_tool"), r.get("evidence_type"), r.get("value")) for r in baseline}

    added = {}
    for item in items:
        if not isinstance(item, dict) or not _is_benign_record(item):
            continue
        key = (item.get("source_tool"), item.get("evidence_type"), item.get("value"))
        if key in seen:
            continue
        scope = _model_scope(item)
        if added.get(scope, 0) >= cap_per_scope:
            continue
        seen.add(key)
        baseline.append(_normalize(item))
        added[scope] = added.get(scope, 0) + 1

    if added:
        with baseline_file.open("w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2)
            f.write("\n")
    return added


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[2]
    unified = sys.argv[1] if len(sys.argv) > 1 else str(root / "output" / "unified_evidence.json")
    baseline = sys.argv[2] if len(sys.argv) > 2 else str(root / "data" / "baseline_normal.json")
    counts = harvest_baseline(unified, baseline)
    total = sum(counts.values())
    print(f"added {total} baseline record(s): "
          + (", ".join(f"{s}={n}" for s, n in sorted(counts.items())) or "nothing new"))
