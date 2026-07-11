"""Opt-in ThreatFox enrichment (PF-1b): attributes flagged IOCs to malware families (abuse.ch DB
only, never attacker infra); off by default (--ti-enrich), annotation-only, cached, offline-safe."""

import json
import os
import re
import urllib.request
from pathlib import Path

from src.data.threat_intel import is_lan_ipv4

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
AUTH_KEY_ENV = "ABUSECH_AUTH_KEY"
DEFAULT_CACHE_PATH = Path.home() / ".cache" / "autoforensiq" / "threatfox_cache.json"
# Politeness cap: distinct new (uncached) indicators queried per run.
MAX_QUERIES_PER_RUN = 25

_ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_BTC_RE = re.compile(
    r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{8,87})\b")


def _candidate_indicators(items) -> dict:
    """indicator → carrying items, from already-flagged (ioc_match + critical/high) items only —
    attribution never widens detection. LAN IPs are victims, not indicators."""
    candidates = {}
    for it in items:
        if not isinstance(it, dict) or not it.get("ioc_match"):
            continue
        if str(it.get("severity", "")).lower() not in ("critical", "high"):
            continue
        value = str(it.get("value", ""))
        tokens = _ONION_RE.findall(value) + _BTC_RE.findall(value)
        tokens += [ip for ip in _IPV4_RE.findall(value) if not is_lan_ipv4(ip)]
        for tok in tokens:
            candidates.setdefault(tok.lower(), []).append(it)
    return candidates


def _load_cache(path: Path) -> dict:
    try:
        with path.open() as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_cache(path: Path, cache: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w") as f:
            json.dump(cache, f, indent=1)
    except OSError:
        pass  # a cache write failure must never fail the pipeline


def _query_threatfox(indicator: str, auth_key: str, timeout: float):
    """One search_ioc lookup. Returns {family, confidence, threat_type} or None (no entry).
    Network/HTTP errors propagate to the caller, which aborts the whole enrichment pass."""
    req = urllib.request.Request(
        THREATFOX_API,
        data=json.dumps({"query": "search_ioc", "search_term": indicator}).encode(),
        headers={"Auth-Key": auth_key, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.load(resp)
    if payload.get("query_status") != "ok" or not payload.get("data"):
        return None
    best = max(payload["data"], key=lambda d: d.get("confidence_level") or 0)
    return {
        "family": best.get("malware_printable") or best.get("malware") or "unknown",
        "confidence": best.get("confidence_level"),
        "threat_type": best.get("threat_type"),
    }


def enrich_items(items, cache_path: Path = None, timeout: float = 8.0,
                 _query=_query_threatfox) -> int:
    """Annotate flagged items with ThreatFox family attribution; returns items annotated. Missing
    key or first network error → silent 0. `_query` is injectable so tests never touch the net."""
    auth_key = os.environ.get(AUTH_KEY_ENV)
    if not auth_key:
        print(f"  [TI] {AUTH_KEY_ENV} not set — skipping ThreatFox enrichment "
              "(register at auth.abuse.ch)")
        return 0

    candidates = _candidate_indicators(items)
    if not candidates:
        return 0

    cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE_PATH
    cache = _load_cache(cache_path)
    queries = 0
    annotated = 0

    for indicator, carrying in sorted(candidates.items()):
        if indicator in cache:
            result = cache[indicator]
        else:
            if queries >= MAX_QUERIES_PER_RUN:
                continue
            try:
                result = _query(indicator, auth_key, timeout)
            except Exception as exc:
                print(f"  [TI] ThreatFox unreachable ({exc}) — degrading to offline catalog")
                break
            queries += 1
            cache[indicator] = result  # misses are cached too (deterministic re-runs)

        if not result:
            continue
        tag = f"ti:{result['family']}"
        for it in carrying:
            if tag not in it["ioc_match"]:
                it["ioc_match"].append(tag)
            it.setdefault("ti_attribution", []).append({
                "indicator": indicator,
                "family": result["family"],
                "confidence": result.get("confidence"),
                "threat_type": result.get("threat_type"),
                "source": "ThreatFox",
            })
            annotated += 1

    if queries:
        _save_cache(cache_path, cache)
    return annotated


def enrich_unified(unified_evidence: dict, output_path: str = None, **kwargs) -> int:
    """Enrich a unified-evidence dict in place; rewrite `output_path` when anything changed so
    the ML and report stages (which re-read the file) see the annotations."""
    n = enrich_items(unified_evidence.get("evidence_items", []), **kwargs)
    if n and output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(unified_evidence, f, indent=2)
            f.write("\n")
    return n
