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

# A dotted-quad IPv4 token (matched whole, so a bad "1.2.3.4" never substring-
# hits inside "11.2.3.40"). Octet-range validation is loose on purpose — the
# reputation match is an equality test against the catalog list, not a parser.
_IP_TOKEN_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# A hostname / domain token: one or more dot-separated labels ending in an
# alphabetic TLD (≥2). The alphabetic-TLD requirement means an IPv4 literal is
# never mis-extracted as a host. Used for reputation matching (issue 4.2).
_HOST_TOKEN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE
)


def _is_ip(token: str) -> bool:
    return bool(_IP_TOKEN_RE.fullmatch(token.strip()))


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


def _build_reputation_rule(catalog: dict, case_context: dict) -> dict | None:
    """Build a single host/IP reputation rule (issue 4.2).

    Merges the static `bad_hosts` catalog entry with per-case known-bad
    indicators (`case_context.known_bad_hosts`, domains or IPs). Returns a rule
    of shape {id, category, hosts:set, ips:set, severity} or None if empty.
    Domains are lowercased and trailing-dot stripped; matching is host-aware
    (see `_match_reputation`), not substring.
    """
    bad = catalog.get("bad_hosts") or {}
    severity = bad.get("severity", "high")

    domains: set[str] = {
        str(d).strip().lower().rstrip(".")
        for d in (bad.get("domains") or [])
        if str(d).strip()
    }
    ips: set[str] = {str(i).strip() for i in (bad.get("ips") or []) if str(i).strip()}

    # Per-case known-bad hosts: classify each entry as IP or domain.
    for raw in (case_context or {}).get("known_bad_hosts", []) or []:
        token = str(raw).strip()
        if not token:
            continue
        if _is_ip(token):
            ips.add(token)
        else:
            domains.add(token.lower().rstrip("."))

    if not domains and not ips:
        return None
    return {
        "id": "bad_host_reputation",
        "category": "reputation",
        "hosts": domains,
        "ips": ips,
        "severity": severity,
    }


def _match_reputation(rule: dict, hosts: set[str], ips: set[str]) -> str | None:
    """Return the specific bad host/IP that matched, or None.

    Domains match on exact host or subdomain (`host == bad` or
    `host.endswith("." + bad)`); IPs match on exact token equality.
    """
    for ip in ips:
        if ip in rule.get("ips", ()):
            return ip
    bad_domains = rule.get("hosts", ())
    for host in hosts:
        for bad in bad_domains:
            if host == bad or host.endswith("." + bad):
                return bad
    return None


def _build_indicator_list(catalog: dict, case_context: dict) -> list[dict]:
    """Combine static catalog indicators + port/keyword groups + case IOCs into
    a single flat list of {id, match, severity, category} rules."""
    indicators: list[dict] = list(catalog.get("indicators", []))

    reputation = _build_reputation_rule(catalog, case_context)
    if reputation:
        indicators.append(reputation)

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

    value = str(item.get("value", ""))
    haystack = f"{value} {item.get('evidence_type', '')}".lower()
    ports_in_value = {int(t) for t in _PORT_TOKEN_RE.findall(haystack)}
    # Host / IP literals are extracted lazily — only when a reputation rule is
    # present — since most catalogs/items never need them.
    hosts_in_value: set[str] | None = None
    ips_in_value: set[str] | None = None

    matched_ids: list[str] = []
    best_rank = 0
    best_severity: str | None = None

    for rule in indicators:
        match_id = rule.get("id", rule.get("category", "ioc"))

        if "ports" in rule:
            hit = bool(ports_in_value.intersection(rule["ports"]))
        elif "hosts" in rule or "ips" in rule:
            if hosts_in_value is None:
                hosts_in_value = {h.lower().rstrip(".") for h in _HOST_TOKEN_RE.findall(value)}
                ips_in_value = set(_IP_TOKEN_RE.findall(value))
            matched_host = _match_reputation(rule, hosts_in_value, ips_in_value)
            hit = matched_host is not None
            if hit:
                # Record the specific bad host/IP for report transparency.
                match_id = f"bad_host:{matched_host}"
        else:
            hit = any(sub in haystack for sub in rule.get("match", []))

        if not hit:
            continue

        matched_ids.append(match_id)
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
