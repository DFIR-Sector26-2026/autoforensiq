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

from src.data.threat_intel import C2_PORTS_HIGH, C2_PORTS_WATCH, LATERAL_MOVEMENT_PORTS

ROOT_DIR = Path(__file__).resolve().parents[2]
_DEFAULT_CATALOG_PATH = ROOT_DIR / "src" / "data" / "ioc_patterns.json"

# Shared severity ranking (mirrors evidence_aggregator.SEVERITY_ORDER).
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Structural-summary evidence types: derived roll-ups whose value embeds items
# that are ALSO emitted (and scored) individually. `process_tree` embeds the
# whole process list as text — the same processes are emitted as `process` items
# and suspicious lineages as `process_relation` items. Re-scoring the tree's text
# against the catalog would match those embedded names again and double-count the
# malware as a second critical finding (issue 4.4), so these types are excluded
# from IOC matching and keep the structural severity the wrapper assigned.
_STRUCTURAL_SUMMARY_TYPES = {"process_tree"}

# String-derived domain evidence (e.g. a `suspicious_domain` scraped from memory
# strings) is only a *finding* if the host was actually contacted. Without a
# matching network/DNS/HTTP item it stays a visible indicator (keeps its
# `ioc_match` tag) but is NOT severity-boosted, so an EDR / threat-intel feed
# resident in memory can't manufacture a CRITICAL verdict from ransomware
# families no host ever talked to (B-2).
_CORROBORATION_REQUIRED_TYPES = {"suspicious_domain"}

# Evidence types that prove the subject actually contacted a host — the
# corroboration source for the gate above.
_NETWORK_CONTACT_TYPES = {
    "network_connection", "dns_query", "http_request", "http_body",
}

# Candidate ports, extracted only from genuine port grammar (issue 4.1-r). A bare
# 2–5 digit token is NOT a port — a byte count ("442 bytes"), packet count, or PID
# would otherwise read as a critical C2 port. We accept a number only when it sits
# after a host/IP colon (`…215.18:4444`) or an explicit port keyword
# (`port 4444`, `dport=4444`, `dst port 4444`). The colon is anchored to a
# preceding address character so a literal ":4444" still works but a bare number
# never matches.
_PORT_TOKEN_RE = re.compile(
    r"(?:(?<=[\w.]):|\b(?:dst\s+)?d?port\b[\s:=]{0,3})(\d{2,5})\b",
    re.IGNORECASE,
)

# A Run/RunOnce/Winlogon key is persistence only when it points at a *suspicious*
# target: a staging directory, a remote URL, or a non-.exe autostart (Run keys
# normally launch a plain .exe, so a .dll/.bat/.ps1 there is the anomaly). A bare
# key path, or a legit app autostarting its own .exe, is not a finding.
_PERSISTENCE_TARGET_RE = re.compile(
    r"\\(?:temp|appdata|programdata)\\"
    r"|\\users\\public\\"
    r"|https?://"
    r"|\.(?:dll|bat|cmd|ps1|vbs|js|jar|scr|hta)\b",
    re.IGNORECASE,
)

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


def _has_remote_peer(value: str) -> bool:
    """True when a connection value names two distinct real endpoints — i.e. an
    actual session with a remote peer, not a listening socket. Listeners read
    `0.0.0.0:3389 -> 0.0.0.0:0` / `:::5985 -> :::0` (at most one real IP), while
    an established pair carries both hosts (`172.16.4.9:3389 -> 172.16.5.26:...`).
    Gate for the lateral-movement port tier (B-6): every Windows host listens on
    RDP/WinRM itself, so the bare listener must not match."""
    ips = {ip for ip in _IP_TOKEN_RE.findall(value) if ip != "0.0.0.0"}
    return len(ips) >= 2


def _persistence_actionable(item: dict, value: str) -> bool:
    """True when a persistence_runkey match is a genuine finding, not a bare key
    path. `schtasks`/`reg add` are persistence *actions* and stand alone; a
    Run/Winlogon *key* reference qualifies only when it's a registry item that
    points at a suspicious target (staging dir / URL / non-.exe autostart)."""
    v = value.lower()
    if "schtasks" in v or "reg add" in v:
        return True
    return (item.get("evidence_type") == "registry_key"
            and bool(_PERSISTENCE_TARGET_RE.search(value)))


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

    # C2 ports come from the shared catalog (issue D1), tiered: high-confidence
    # ports floor at critical; dual-use watch ports (IRC/8888/9999/old trojans)
    # only at medium, so a Jupyter or IRC connection isn't escalated to a
    # critical C2 finding. Keeping the high-tier id "c2_port" preserves the
    # existing match label.
    if C2_PORTS_HIGH:
        indicators.append({
            "id": "c2_port",
            "ports": sorted(C2_PORTS_HIGH),
            "severity": "critical",
            "category": "c2_channel",
        })
    if C2_PORTS_WATCH:
        indicators.append({
            "id": "c2_port_watch",
            "ports": sorted(C2_PORTS_WATCH),
            "severity": "medium",
            "category": "c2_channel",
        })
    # Remote-interactive admin channels (WinRM/RDP/VNC) — the lateral-movement
    # backbone of an internal LOTL intrusion (B-6). Medium watch signal, and only
    # for a session with a real remote peer: every Windows host listens on
    # 3389/5985 itself, so a bare listening socket must not match.
    if LATERAL_MOVEMENT_PORTS:
        indicators.append({
            "id": "lateral_movement_port",
            "ports": sorted(LATERAL_MOVEMENT_PORTS),
            "severity": "medium",
            "category": "lateral_movement",
            "requires_remote_peer": True,
        })

    exfil = catalog.get("exfil_keywords") or {}
    if exfil.get("keywords"):
        indicators.append({
            "id": "data_exfiltration",
            "match": [str(k).lower() for k in exfil["keywords"]],
            "severity": exfil.get("severity", "high"),
            "category": "exfiltration",
        })

    # NOTE (issue B2): the affected-system IPs from case_context are the *victim*
    # hosts, not threat indicators — they appear in essentially every artifact, so
    # treating them as a high-severity IOC wrongly escalated benign victim traffic
    # (e.g. the invoice DNS lookup and the :445 lateral-probe both jumped to high).
    # Victim-host correlation is already handled by the aggregator's `same_ip`
    # signal, so case-IPs are intentionally NOT added to the IOC indicator list.
    return indicators


def _norm_host(host: str) -> str:
    """Lowercase, strip a trailing dot and a leading `www.` so the `www.`-prefixed
    memory copy of a host and the bare form seen in a pcap collapse to one key
    (mirrors evidence_aggregator._normalize_host)."""
    host = host.strip().rstrip(".").lower()
    return host[len("www."):] if host.startswith("www.") else host


def _corroborated_hosts(items: list[dict]) -> set[str]:
    """Hosts (domains + IP literals) the subject actually contacted, harvested
    from network/DNS/HTTP items. A string-only domain IOC is a finding only if it
    appears here (B-2)."""
    hosts: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or item.get("evidence_type") not in _NETWORK_CONTACT_TYPES:
            continue
        value = str(item.get("value", ""))
        hosts.update(_norm_host(h) for h in _HOST_TOKEN_RE.findall(value))
        hosts.update(_IP_TOKEN_RE.findall(value))
    return hosts


def _domain_corroborated(value: str, corroborated: set[str]) -> bool:
    """True if any domain in `value` was contacted — exact host or subdomain of a
    contacted host (`host == c` or `host.endswith("." + c)`), matching the
    reputation rule's host-aware semantics."""
    for raw in _HOST_TOKEN_RE.findall(value):
        h = _norm_host(raw)
        if any(h == c or h.endswith("." + c) for c in corroborated):
            return True
    return False


def rescore_item(
    item: dict,
    indicators: list[dict],
    corroborated_hosts: set[str] | None = None,
) -> tuple[dict, list[str]]:
    """Re-score one evidence item against the indicator list.

    Returns (item, matched_ids). Boosts item['severity'] up to the highest
    matched severity floor (never downgrades) and records matches in
    item['ioc_match']. When `corroborated_hosts` is given, a string-derived
    domain IOC whose host was never contacted keeps its match tag but is not
    boosted (B-2).
    """
    if not isinstance(item, dict):
        return item, []

    # Structural roll-ups (process_tree) embed indicators already scored on their
    # own items; don't re-score them or the malware double-counts (issue 4.4).
    if item.get("evidence_type") in _STRUCTURAL_SUMMARY_TYPES:
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
            if hit and rule.get("requires_remote_peer") and not _has_remote_peer(value):
                hit = False
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

        # The code_injection rule re-matches the malfind wrapper's OWN output
        # ("rwx", "injected_code"), but the wrapper already graded those items with
        # full context (RWX+PE -> critical, bare RWX -> high, JIT/AV -> medium,
        # corroboration). Re-scoring them let the naive rule override that grading
        # (it re-elevated Defender's down-ranked RWX back to high). Skip it for
        # injected_code items — like process_tree, they're already scored on their
        # own item. Genuine injections keep their wrapper severity (never
        # downgraded) and the ioc_engine "Process injection detected" IOC; the rule
        # stays active for non-injected_code items (a "process hollowing" /
        # "reflective" mention in a commandline or string still elevates).
        if rule.get("id") == "code_injection" and item.get("evidence_type") == "injected_code":
            continue

        matched_ids.append(match_id)
        # Persistence via a Run/RunOnce/Winlogon key elevates only when the key
        # points at a suspicious target; a bare key path is on every Windows host.
        # Keep the tag (above), skip the boost (fixes the bare-Run-key FP flood).
        if rule.get("id") == "persistence_runkey" and not _persistence_actionable(item, value):
            continue
        rank = SEVERITY_ORDER.get(rule.get("severity", "low"), 0)
        if rank > best_rank:
            best_rank = rank
            best_severity = rule.get("severity")

    if not matched_ids:
        return item, []

    # B-2: an uncorroborated string-derived domain keeps its match tag (below)
    # but must not drive the verdict, so skip the severity boost. A corroborated
    # one — the same domain also seen in a real connection/DNS — escalates
    # normally, becoming a genuine finding.
    boost_allowed = not (
        corroborated_hosts is not None
        and item.get("evidence_type") in _CORROBORATION_REQUIRED_TYPES
        and not _domain_corroborated(value, corroborated_hosts)
    )

    current_rank = SEVERITY_ORDER.get(item.get("severity", "low"), 0)
    if boost_allowed and best_severity and best_rank > current_rank:
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

    corroborated = _corroborated_hosts(items)
    n_boosted = 0
    for item in items:
        before = item.get("severity") if isinstance(item, dict) else None
        rescore_item(item, indicators, corroborated)
        after = item.get("severity") if isinstance(item, dict) else None
        if before != after:
            n_boosted += 1

    return items, n_boosted
