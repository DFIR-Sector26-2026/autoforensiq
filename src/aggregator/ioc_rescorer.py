"""
IOC Re-scorer — post-aggregation severity correction (P4 helper)

Wrappers assign severity once, using only their own narrow heuristics, so known
malware indicators (e.g. tasksche.exe, @WanaDecryptor@) can slip through as
`low`. This module re-scores each evidence item against:

  * a static IOC catalog (src/data/ioc_patterns.json), and
  * case-specific IOCs derived from case_context (affected_systems IPs, etc.)

Severity is only ever BOOSTED, never downgraded — a wrapper that already flagged
something critical keeps that rating. Matches are recorded on the item under a
new optional `ioc_match` field.

Used by evidence_aggregator.aggregate_evidence() between dedup and sort.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[2]
_DEFAULT_CATALOG_PATH = ROOT_DIR / "src" / "data" / "ioc_patterns.json"

# Shared severity ranking (mirrors evidence_aggregator.SEVERITY_ORDER).
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Numeric tokens 2–5 digits long, used to extract candidate ports from a value.
_PORT_TOKEN_RE = re.compile(r"\b(\d{2,5})\b")


def load_ioc_catalog(path: str | Path = _DEFAULT_CATALOG_PATH) -> dict[str, Any]:
    """Load the IOC catalog JSON. Returns {} if missing (no-op, defensive)."""
    p = Path(path)
    if not p.exists():
        print(f"  [WARN] IOC catalog not found: {p} — re-scoring disabled")
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:  # noqa: BLE001 - never let catalog errors break aggregation
        print(f"  [WARN] Failed to load IOC catalog ({e}) — re-scoring disabled")
        return {}


def build_case_iocs(case_context: dict) -> list[dict]:
    """Turn case-specific data into IOC rules (affected_systems IPs, etc.)."""
    if not isinstance(case_context, dict):
        return []
    rules: list[dict] = []
    for ip in case_context.get("affected_systems", []) or []:
        ip = str(ip).strip().lower()
        if ip:
            rules.append({
                "id": f"case_ip_{ip}",
                "match": [ip],
                "severity": "high",
                "category": "case_affected_system",
            })
    return rules


def _build_indicator_list(catalog: dict, case_context: dict) -> list[dict]:
    """Combine static catalog indicators + port/keyword groups + case IOCs into
    a single flat list of {id, match, severity, category} rules."""
    indicators: list[dict] = list(catalog.get("indicators", []))

    c2 = catalog.get("c2_ports") or {}
    if c2.get("ports"):
        indicators.append({
            "id": "c2_port",
            "ports": [int(p) for p in c2["ports"]],
            "severity": c2.get("severity", "high"),
            "category": "c2_channel",
        })

    exfil = catalog.get("exfil_keywords") or {}
    if exfil.get("keywords"):
        indicators.append({
            "id": "data_exfiltration",
            "match": [str(k).lower() for k in exfil["keywords"]],
            "severity": exfil.get("severity", "high"),
            "category": "exfiltration",
        })

    indicators.extend(build_case_iocs(case_context))
    return indicators


def rescore_item(item: dict, indicators: list[dict]) -> tuple[dict, list[str]]:
    """Re-score one evidence item against the indicator list.

    Returns (item, matched_ids). Boosts item['severity'] up to the highest
    matched severity floor (never downgrades) and records matches in
    item['ioc_match'].
    """
    if not isinstance(item, dict):
        return item, []

    haystack = f"{item.get('value', '')} {item.get('evidence_type', '')}".lower()
    ports_in_value = {int(t) for t in _PORT_TOKEN_RE.findall(haystack)}

    matched_ids: list[str] = []
    best_rank = 0
    best_severity: str | None = None

    for rule in indicators:
        hit = False
        if "ports" in rule:
            hit = bool(ports_in_value.intersection(rule["ports"]))
        else:
            hit = any(sub in haystack for sub in rule.get("match", []))

        if not hit:
            continue

        matched_ids.append(rule.get("id", rule.get("category", "ioc")))
        rank = SEVERITY_ORDER.get(rule.get("severity", "low"), 0)
        if rank > best_rank:
            best_rank = rank
            best_severity = rule.get("severity")

    if not matched_ids:
        return item, []

    current_rank = SEVERITY_ORDER.get(item.get("severity", "low"), 0)
    if best_severity and best_rank > current_rank:
        item["severity"] = best_severity

    # Record matches (de-duplicated, order-preserving) for report transparency.
    existing = item.get("ioc_match", []) if isinstance(item.get("ioc_match"), list) else []
    item["ioc_match"] = list(dict.fromkeys(existing + matched_ids))
    return item, matched_ids


def rescore_items(
    items: list[dict],
    catalog: dict,
    case_context: dict,
) -> tuple[list[dict], int]:
    """Apply IOC re-scoring to every item. Returns (items, n_boosted)."""
    indicators = _build_indicator_list(catalog or {}, case_context or {})
    if not indicators:
        return items, 0

    n_boosted = 0
    for item in items:
        before = item.get("severity") if isinstance(item, dict) else None
        rescore_item(item, indicators)
        after = item.get("severity") if isinstance(item, dict) else None
        if before != after:
            n_boosted += 1

    return items, n_boosted
