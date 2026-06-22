"""Test suite for the Evidence Aggregator (P4)."""

import json
import pytest
import tempfile
from pathlib import Path
from src.aggregator.evidence_aggregator import (
    deduplicate_items,
    sort_evidence_items,
    build_indices,
    aggregate_evidence,
    enrich_evidence_items,
    build_correlations,
    reconcile_memprocfs_processes,
)
from autoforensiq import run_bulk_aggregation


def test_deduplicate_removes_duplicates():
    """Test that duplicate artifact IDs are removed."""
    items = [
        {"artifact_id": "item_1", "source_tool": "tool_a", "value": "test1"},
        {"artifact_id": "item_2", "source_tool": "tool_b", "value": "test2"},
        {"artifact_id": "item_1", "source_tool": "tool_c", "value": "test1_dup"},  # dup
    ]
    deduplicated, removed = deduplicate_items(items)
    assert len(deduplicated) == 2
    assert removed == 1
    assert deduplicated[0]["artifact_id"] == "item_1"
    assert deduplicated[0]["source_tool"] == "tool_a"  # keeps first


def test_sort_by_severity_and_confidence():
    """Test that items are sorted by severity then confidence."""
    items = [
        {"artifact_id": "a", "severity": "low", "confidence": 0.9, "source_tool": "tool"},
        {"artifact_id": "b", "severity": "critical", "confidence": 0.5, "source_tool": "tool"},
        {"artifact_id": "c", "severity": "high", "confidence": 0.95, "source_tool": "tool"},
    ]
    sorted_items = sort_evidence_items(items)
    # Should be: critical (b), high (c), low (a)
    assert sorted_items[0]["artifact_id"] == "b"
    assert sorted_items[1]["artifact_id"] == "c"
    assert sorted_items[2]["artifact_id"] == "a"


def test_sort_rule_match_outranks_heuristic_within_tier():
    """Within the same severity, a rule-based ioc_match item must sort above a
    pure-heuristic item even if the heuristic has higher confidence (4.1)."""
    items = [
        {"artifact_id": "heuristic", "severity": "high", "confidence": 0.9,
         "source_tool": "tshark"},
        {"artifact_id": "rule", "severity": "high", "confidence": 0.6,
         "source_tool": "tshark", "ioc_match": ["c2_port"]},
    ]
    sorted_items = sort_evidence_items(items)
    assert sorted_items[0]["artifact_id"] == "rule"
    assert sorted_items[1]["artifact_id"] == "heuristic"


def test_catalog_matches_wannacry_network_iocs():
    """The IOC catalog must match the WannaCry killswitch / .onion C2 / BTC
    ransom wallets so they get an ioc_match (→ become Key Findings) and are
    escalated. Regression for 3.3-I (network IOCs were absent from the catalog).
    """
    from src.aggregator.ioc_rescorer import load_ioc_catalog, rescore_items
    cat = load_ioc_catalog()
    items = [
        {"artifact_id": "dom_1", "evidence_type": "suspicious_domain",
         "value": "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
         "severity": "medium", "source_tool": "volatility3"},
        {"artifact_id": "onion_1", "evidence_type": "suspicious_domain",
         "value": "gx7ekbenv2riucmf.onion", "severity": "high",
         "source_tool": "volatility3"},
        # case-sensitive base58 address — catalog matches case-insensitively
        {"artifact_id": "btc_1", "evidence_type": "suspicious_crypto",
         "value": "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw", "severity": "high",
         "source_tool": "volatility3"},
    ]
    rescore_items(items, cat, {})
    by_id = {i["artifact_id"]: i for i in items}
    # killswitch: gains a match and is escalated medium -> high
    assert by_id["dom_1"]["ioc_match"] == ["wannacry_killswitch"]
    assert by_id["dom_1"]["severity"] == "high"
    # any .onion matches the general Tor-hidden-service rule (high floor)
    assert by_id["onion_1"]["ioc_match"] == ["tor_hidden_service"]
    assert by_id["onion_1"]["severity"] == "high"
    # BTC ransom wallet matches the curated named-intel rule and escalates
    assert by_id["btc_1"]["ioc_match"] == ["wannacry_ransom_wallet"]
    assert by_id["btc_1"]["severity"] == "critical"

    # The .onion rule is general, not a WannaCry enumeration: an arbitrary
    # (non-WannaCry) hidden service must match too.
    novel = [{"artifact_id": "onion_2", "evidence_type": "suspicious_domain",
              "value": "abcdef0123456789deadbeef.onion", "severity": "medium",
              "source_tool": "volatility3"}]
    rescore_items(novel, cat, {})
    assert novel[0]["ioc_match"] == ["tor_hidden_service"]
    assert novel[0]["severity"] == "high"


def test_affected_system_ip_does_not_escalate_benign_traffic():
    """Issue B2: affected_systems holds the *victim* host, which appears in
    nearly every artifact. It must NOT be treated as a severity-raising IOC, or
    benign victim traffic (a plain DNS lookup, an internal SMB probe) is wrongly
    escalated. Victim-host correlation is the aggregator's `same_ip` job."""
    from src.aggregator.ioc_rescorer import load_ioc_catalog, rescore_items
    cat = load_ioc_catalog()
    ctx = {"affected_systems": ["10.10.14.22"]}
    items = [
        {"artifact_id": "dns_b", "evidence_type": "dns_query", "source_tool": "tshark",
         "value": "DNS query from 10.10.14.22 -> invoice-secure-download.xyz", "severity": "low"},
        {"artifact_id": "smb_b", "evidence_type": "network_connection", "source_tool": "tshark",
         "value": "TCP 10.10.14.22 -> 10.10.14.45:445 (303 bytes)", "severity": "low"},
    ]
    rescore_items(items, cat, ctx)
    for it in items:
        assert it["severity"] == "low", it
        assert not any("case_ip" in m for m in it.get("ioc_match", []))


def test_wnry_component_files_tagged_high_not_critical():
    """Issue B4: WannaCry's .wnry component/resource files are strong
    corroborating evidence — they gain a `wannacry_payload` match and are floored
    at high, but NOT critical (that's the dropper/decryptor). '.wnry' must not
    collide with the '.wncry' encrypted-victim rule."""
    from src.aggregator.ioc_rescorer import load_ioc_catalog, rescore_items
    cat = load_ioc_catalog()
    items = [
        {"artifact_id": "f1", "evidence_type": "file_artifact", "source_tool": "volatility3",
         "value": "\\Intel\\xyz\\c.wnry", "severity": "medium"},
        {"artifact_id": "f2", "evidence_type": "file_artifact", "source_tool": "tsk_fls",
         "value": "Suspicious file: /Windows/Temp/u.wnry", "severity": "medium"},
    ]
    rescore_items(items, cat, {})
    for it in items:
        assert it["severity"] == "high", it
        assert "wannacry_payload" in it["ioc_match"]
    # an encrypted-victim file (.wncry) still hits the decryptor rule -> critical,
    # and must NOT be mislabelled as the high payload rule.
    enc = [{"artifact_id": "e", "evidence_type": "file_artifact", "source_tool": "volatility3",
            "value": "photo.jpg.wncry", "severity": "medium"}]
    rescore_items(enc, cat, {})
    assert enc[0]["severity"] == "critical"
    assert "wannacry_payload" not in enc[0]["ioc_match"]


def test_c2_port_not_matched_from_byte_or_packet_count():
    """Issue 4.1-r: a candidate C2 port must come from real port grammar (a
    host:port colon or a `port`/`dport` keyword), not any bare 2–5 digit token.
    A byte count that happens to equal a catalog port ('4444 bytes') or a PID
    must NOT escalate the item to critical."""
    from src.aggregator.ioc_rescorer import load_ioc_catalog, rescore_items
    cat = load_ioc_catalog()
    items = [
        # real C2 port after the colon -> critical
        {"artifact_id": "n1", "evidence_type": "network_connection", "severity": "low",
         "value": "TCP 10.10.14.22 -> 165.245.215.18:4444 (442 bytes, 5 packets)"},
        # byte count equal to a catalog port, no port grammar -> must stay low
        # (value kept free of exfil keywords so only the port path is exercised)
        {"artifact_id": "n2", "evidence_type": "network_connection", "severity": "low",
         "value": "TCP session transferred 4444 bytes in 9999 frames"},
        # the 'port' keyword form still matches
        {"artifact_id": "n3", "evidence_type": "suspicious_port", "severity": "low",
         "value": "Traffic on suspicious port 4444: 10.10.14.22 -> 165.245.215.18"},
    ]
    rescore_items(items, cat, {})
    by_id = {i["artifact_id"]: i for i in items}
    assert by_id["n1"]["severity"] == "critical"
    assert "c2_port" in by_id["n1"]["ioc_match"]
    assert by_id["n2"]["severity"] == "low"
    assert "c2_port" not in by_id["n2"].get("ioc_match", [])
    assert by_id["n3"]["severity"] == "critical"
    assert "c2_port" in by_id["n3"]["ioc_match"]


def test_c2_port_tiers_high_vs_watch():
    """Issue D1: the centralised C2-port catalog is tiered. A high-confidence
    port (4444) floors at critical under id 'c2_port'; a dual-use watch port
    (8888) only floors at medium under id 'c2_port_watch', so a Jupyter/IRC-style
    connection is surfaced without being escalated to a critical C2 finding."""
    from src.data.threat_intel import c2_port_severity
    assert c2_port_severity(4444) == "high"
    assert c2_port_severity("8888") == "medium"      # accepts digit strings
    assert c2_port_severity(2222) is None            # dropped: usually legitimate
    assert c2_port_severity(443) is None

    from src.aggregator.ioc_rescorer import load_ioc_catalog, rescore_items
    cat = load_ioc_catalog()
    items = [
        {"artifact_id": "hi", "evidence_type": "network_connection", "severity": "low",
         "value": "TCP 10.0.0.5 -> 9.9.9.9:4444 beacon"},
        {"artifact_id": "watch", "evidence_type": "network_connection", "severity": "low",
         "value": "TCP 10.0.0.5 -> 9.9.9.9:8888 session"},
    ]
    rescore_items(items, cat, {})
    by_id = {i["artifact_id"]: i for i in items}
    assert by_id["hi"]["severity"] == "critical"
    assert "c2_port" in by_id["hi"]["ioc_match"]
    # watch-tier port is noted at medium, NOT escalated to critical
    assert by_id["watch"]["severity"] == "medium"
    assert "c2_port_watch" in by_id["watch"]["ioc_match"]


def test_same_pid_requires_information_adding_evidence():
    """Issue 4.7: a same_pid group confined to the process-identity types
    (process row + command line + tree position, one tool) is the same fact
    restated, not corroboration — it fires for every System/svchost PID. It must
    be suppressed unless the PID also appears in information-adding evidence
    (injected_code / network / file) or across >= 2 tools."""
    items = [
        # PID 4 (System): only process + cmdline from one tool -> SUPPRESSED
        {"artifact_id": "proc_4", "evidence_type": "process", "source_tool": "volatility3",
         "severity": "low", "value": "System (PID:4)"},
        {"artifact_id": "cmdline_4", "evidence_type": "commandline", "source_tool": "volatility3",
         "severity": "low", "value": "System (PID:4)"},
        # PID 596 (csrss): process + injected_code -> KEPT (injection adds info)
        {"artifact_id": "proc_596", "evidence_type": "process", "source_tool": "volatility3",
         "severity": "medium", "value": "csrss.exe (PID:596)"},
        {"artifact_id": "malfind_596", "evidence_type": "injected_code", "source_tool": "volatility3",
         "severity": "high", "value": "Injected memory regions detected in csrss.exe (PID:596)"},
    ]
    enriched, signals = enrich_evidence_items(items, {"case_id": "X"})
    annotated, findings = build_correlations(enriched, signals)
    same_pid = {f["signal"] for f in findings if f["correlation_type"] == "same_pid"}
    assert "596" in same_pid, "injected PID must survive (process + injected_code)"
    assert "4" not in same_pid, "System PID 4 (process+cmdline only) must be suppressed"


def test_bad_host_reputation_catalog_matches_network_values():
    """Issue 4.2: the bad_hosts reputation list must boost+tag the low/medium
    network items pointing at known-bad infrastructure (domain AND IP), which
    the heuristics miss. Seeded from the bundled macOS infostealer C2.
    """
    from src.aggregator.ioc_rescorer import load_ioc_catalog, rescore_items
    cat = load_ioc_catalog()
    items = [
        # readable low-entropy C2 domain — DNS heuristic leaves it 'low' (3.2)
        {"artifact_id": "dns_rc", "evidence_type": "dns_query", "severity": "low",
         "value": "DNS query from 10.5.11.101 → rapid-craft567.com (label entropy: 3.52)"},
        # C2 IP beacon — was 'medium' with no ioc_match
        {"artifact_id": "http_contact", "evidence_type": "http_request", "severity": "medium",
         "value": "HTTP 10.5.11.101 → 165.245.215.18/contact"},
        # subdomain of the bad domain must also match
        {"artifact_id": "dns_sub", "evidence_type": "dns_query", "severity": "low",
         "value": "DNS query from 10.5.11.101 → cdn.rapid-craft567.com (e)"},
    ]
    rescore_items(items, cat, {})
    by_id = {i["artifact_id"]: i for i in items}
    assert by_id["dns_rc"]["severity"] == "high"
    assert by_id["dns_rc"]["ioc_match"] == ["bad_host:rapid-craft567.com"]
    assert by_id["http_contact"]["severity"] == "high"
    assert by_id["http_contact"]["ioc_match"] == ["bad_host:165.245.215.18"]
    assert by_id["dns_sub"]["ioc_match"] == ["bad_host:rapid-craft567.com"]


def test_bad_host_reputation_is_host_aware_not_substring():
    """A bad IP/domain must match a whole host token, never a substring — so a
    benign host that merely contains the bad string is left alone.
    """
    from src.aggregator.ioc_rescorer import load_ioc_catalog, rescore_items
    cat = load_ioc_catalog()
    items = [
        # 1165.245.215.180 contains the bad 165.245.215.18 as a substring
        {"artifact_id": "ip_substr", "evidence_type": "network_connection", "severity": "low",
         "value": "TCP 10.0.0.1 → 1165.245.215.180:443 (10 bytes, 1 packets)"},
        # lookalike domain, not the bad domain and not a subdomain of it
        {"artifact_id": "dom_look", "evidence_type": "dns_query", "severity": "low",
         "value": "DNS query from 10.0.0.1 → notrapid-craft567.com.evil.test (e)"},
    ]
    rescore_items(items, cat, {})
    by_id = {i["artifact_id"]: i for i in items}
    assert by_id["ip_substr"]["severity"] == "low"
    assert by_id["ip_substr"].get("ioc_match", []) == []
    assert by_id["dom_look"]["severity"] == "low"


def test_process_tree_is_not_double_scored():
    """Issue 4.4: a process_tree is a structural roll-up whose text embeds the
    same processes emitted (and IOC-scored) as `process` / `process_relation`
    items. The rescorer must NOT re-score it, or the malware double-counts as a
    second critical finding with a bogus ioc_match.
    """
    from src.aggregator.ioc_rescorer import load_ioc_catalog, rescore_items
    cat = load_ioc_catalog()
    tree_value = "explorer.exe (1636)\n  tasksche.exe (1940)\n    @WanaDecryptor@ (740)"
    items = [
        {"artifact_id": "proc_1940_tasksche_exe", "evidence_type": "process",
         "severity": "low", "value": "tasksche.exe (PID:1940 PPID:1636)"},
        {"artifact_id": "process_tree_1636", "evidence_type": "process_tree",
         "severity": "medium", "value": tree_value},
    ]
    rescore_items(items, cat, {})
    by_id = {i["artifact_id"]: i for i in items}
    # The process itself is scored once.
    assert by_id["proc_1940_tasksche_exe"]["severity"] == "critical"
    assert by_id["proc_1940_tasksche_exe"]["ioc_match"] == ["wannacry_dropper"]
    # The tree stays a structural-medium summary — not escalated, no ioc_match.
    assert by_id["process_tree_1636"]["severity"] == "medium"
    assert by_id["process_tree_1636"].get("ioc_match", []) == []


def test_case_specific_known_bad_hosts_are_matched():
    """Issue 4.2: per-case known-bad domains/IPs (case_context.known_bad_hosts)
    fold into the reputation match on top of the static catalog.
    """
    from src.aggregator.ioc_rescorer import load_ioc_catalog, rescore_items
    cat = load_ioc_catalog()
    ctx = {"case_id": "c1", "known_bad_hosts": ["evil-c2.example", "203.0.113.9"]}
    items = [
        {"artifact_id": "dns_case", "evidence_type": "dns_query", "severity": "low",
         "value": "DNS query from 10.0.0.5 → evil-c2.example (e)"},
        {"artifact_id": "conn_case", "evidence_type": "network_connection", "severity": "low",
         "value": "TCP 10.0.0.5 → 203.0.113.9:8080 (5 bytes, 1 packets)"},
    ]
    rescore_items(items, cat, ctx)
    by_id = {i["artifact_id"]: i for i in items}
    assert by_id["dns_case"]["severity"] == "high"
    assert by_id["dns_case"]["ioc_match"] == ["bad_host:evil-c2.example"]
    assert by_id["conn_case"]["ioc_match"] == ["bad_host:203.0.113.9"]


def test_build_indices():
    """Test that indices group items correctly."""
    items = [
        {"artifact_id": "a", "evidence_type": "process", "source_tool": "vol"},
        {"artifact_id": "b", "evidence_type": "network", "source_tool": "tshark"},
        {"artifact_id": "c", "evidence_type": "process", "source_tool": "vol"},
    ]
    indices = build_indices(items)
    
    assert len(indices["by_type"]["process"]) == 2
    assert len(indices["by_type"]["network"]) == 1
    assert len(indices["by_tool"]["vol"]) == 2
    assert len(indices["by_tool"]["tshark"]) == 1


def test_aggregate_evidence_with_empty_tools():
    """Test aggregation with no raw outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        case_context = {"case_id": "test_case_123"}
        output_path = str(Path(tmpdir) / "unified.json")
        result = aggregate_evidence(
            case_context=case_context,
            raw_outputs_dir=tmpdir,
            output_path=output_path
        )
        
        assert result["case_id"] == "test_case_123"
        assert result["total_items"] == 0
        assert result["tools_aggregated"] == []
        assert result["evidence_items"] == []


def test_aggregate_evidence_preserves_provenance():
    """Test that tool provenance is maintained in output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create sample raw outputs
        raw_dir = Path(tmpdir) / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        
        vol_output = {
            "tool": "volatility3",
            "items": [
                {"artifact_id": "proc_1", "source_tool": "volatility3",
                 "evidence_type": "process", "value": "test.exe", 
                 "severity": "high", "confidence": 0.9, 
                 "timestamp": "", "linked_artifacts": []}
            ]
        }
        tshark_output = {
            "tool": "tshark",
            "items": [
                {"artifact_id": "conn_1", "source_tool": "tshark",
                 "evidence_type": "network", "value": "1.2.3.4:80",
                 "severity": "low", "confidence": 0.8,
                 "timestamp": "", "linked_artifacts": ["proc_1"]}
            ]
        }
        
        with (raw_dir / "volatility_output.json").open("w") as f:
            json.dump(vol_output, f)
        with (raw_dir / "tshark_output.json").open("w") as f:
            json.dump(tshark_output, f)
        
        case_context = {"case_id": "test_case_456"}
        result = aggregate_evidence(
            case_context=case_context,
            raw_outputs_dir=str(raw_dir),
            output_path=str(Path(tmpdir) / "unified.json")
        )
        
        assert result["total_items"] == 2
        assert "volatility3" in result["tools_aggregated"]
        assert "tshark" in result["tools_aggregated"]
        assert len(result["evidence_by_tool"]["volatility3"]) == 1
        assert len(result["evidence_by_tool"]["tshark"]) == 1
        
        # Check that provenance is maintained
        for item in result["evidence_items"]:
            assert item["source_tool"] in ["volatility3", "tshark"]


def test_aggregate_evidence_builds_correlations_and_exfiltration():
    """Test that cross-tool correlations and the exfiltration rule are emitted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        raw_dir = Path(tmpdir) / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        vol_output = {
            "tool": "volatility3",
            "items": [
                {
                    "artifact_id": "proc_4321_powershell_exe",
                    "source_tool": "volatility3",
                    "evidence_type": "process",
                    "value": "powershell.exe (PID:4321 PPID:100)",
                    "severity": "high",
                    "confidence": 0.9,
                    "timestamp": "2026-05-08T12:00:00Z",
                    "linked_artifacts": [],
                },
                {
                    # Independent corroboration for PID 4321. The same_pid
                    # correlation must rest on genuinely separate observations
                    # (process + cmdline), NOT on the process_tree summary, which
                    # is now excluded from correlation-signal extraction.
                    "artifact_id": "cmdline_4321",
                    "source_tool": "volatility3",
                    "evidence_type": "commandline",
                    "value": "powershell.exe -enc <...> (PID:4321)",
                    "severity": "high",
                    "confidence": 0.88,
                    "timestamp": "2026-05-08T12:00:00Z",
                    "linked_artifacts": [],
                },
                {
                    "artifact_id": "proc_tree_4321",
                    "source_tool": "volatility3",
                    "evidence_type": "process_tree",
                    "value": "Suspicious parent-child: powershell.exe (PID:4321) under PPID:100",
                    "severity": "high",
                    "confidence": 0.85,
                    "timestamp": "2026-05-08T12:00:00Z",
                    "linked_artifacts": [],
                },
            ],
        }
        tshark_output = {
            "tool": "tshark",
            "items": [
                {
                    "artifact_id": "net_4321_4444",
                    "source_tool": "tshark",
                    "evidence_type": "network_connection",
                    # PID in the value, matching the real netstat wrapper output, so
                    # the same_pid group spans an information-adding type (4.7).
                    "value": "TCP 10.0.0.5 → 185.220.101.47:4444 (1500000 bytes, 12 packets) (PID:4321)",
                    "severity": "high",
                    "confidence": 0.8,
                    "timestamp": "2026-05-08T12:05:00Z",
                    "linked_artifacts": ["proc_4321_powershell_exe"],
                },
            ],
        }
        tsk_output = {
            "tool": "tsk_fls",
            "items": [
                {
                    "artifact_id": "timeline_payload",
                    "source_tool": "tsk_fls",
                    "evidence_type": "timeline_event",
                    "value": "[2026-05-08T12:01:00Z] modified → C:/Users/admin/AppData/Temp/payload.exe",
                    "severity": "medium",
                    "confidence": 0.7,
                    "timestamp": "2026-05-08T12:01:00Z",
                    "linked_artifacts": [],
                },
                {
                    "artifact_id": "file_payload",
                    "source_tool": "tsk_fls",
                    "evidence_type": "file_artifact",
                    "value": "Suspicious file: C:/Users/admin/AppData/Temp/payload.exe",
                    "severity": "medium",
                    "confidence": 0.75,
                    "timestamp": "2026-05-08T12:01:00Z",
                    "linked_artifacts": [],
                },
            ],
        }

        with (raw_dir / "volatility_output.json").open("w") as f:
            json.dump(vol_output, f)
        with (raw_dir / "tshark_output.json").open("w") as f:
            json.dump(tshark_output, f)
        with (raw_dir / "tsk_output.json").open("w") as f:
            json.dump(tsk_output, f)

        case_context = {
            "case_id": "test_case_789",
            "affected_systems": ["WIN-ACCT-033"],
        }
        result = aggregate_evidence(
            case_context=case_context,
            raw_outputs_dir=str(raw_dir),
            output_path=str(Path(tmpdir) / "unified.json")
        )

        assert result["total_items"] == 6
        assert result["evidence_by_machine"]["WIN-ACCT-033"]
        same_pid = [f for f in result["findings"] if f["correlation_type"] == "same_pid"]
        assert same_pid
        # The process_tree aggregate must never anchor a same_pid correlation —
        # it summarises every PID in a subtree, so anchoring on it is wrong.
        assert all(f.get("item") != "proc_tree_4321" for f in same_pid)
        assert any(f["correlation_type"] == "exfiltration" for f in result["exfiltration_findings"])
        assert any(item.get("correlations") for item in result["evidence_items"])
        exfil = next(f for f in result["exfiltration_findings"] if f["correlation_type"] == "exfiltration")
        assert exfil["file"].endswith("payload.exe")
        assert exfil["destination"] == "185.220.101.47:4444"
        assert exfil["bytes_transferred"] == 1500000


def test_exfiltration_temporal_match_is_labelled_honestly():
    """Issue 5.1: a plain TCP connection never names the transferred file, so the
    exfil finding rests on temporal proximity only. It must be marked
    match_type='temporal' and must NOT claim the file path 'matched' disk/
    timeline evidence (the old finding text over-stated what was checked)."""
    from src.aggregator.evidence_aggregator import (
        enrich_evidence_items, _build_exfiltration_findings,
    )
    items = [
        {"artifact_id": "net1", "source_tool": "tshark",
         "evidence_type": "network_connection",
         "value": "TCP 10.0.0.5 -> 9.9.9.9:4444 (1500000 bytes, 12 packets)",
         "severity": "high", "confidence": 0.8,
         "timestamp": "2026-05-08T12:05:00Z", "linked_artifacts": []},
        {"artifact_id": "file1", "source_tool": "tsk_fls",
         "evidence_type": "file_artifact",
         "value": "Suspicious file: C:/Users/admin/AppData/Temp/payload.exe",
         "severity": "medium", "confidence": 0.75,
         "timestamp": "2026-05-08T12:01:00Z", "linked_artifacts": []},
    ]
    enriched, signals = enrich_evidence_items(items, {"case_id": "c"})
    findings = _build_exfiltration_findings(enriched, signals)
    assert len(findings) == 1
    f = findings[0]
    assert f["match_type"] == "temporal"
    assert f["file"].endswith("payload.exe")
    assert not any("matched disk/timeline" in c for c in f["what_confirmed_it"])
    assert any("Temporal correlation only" in c for c in f["what_confirmed_it"])


def test_exfiltration_filename_match_is_strong():
    """When the connection value DOES name the file (shared file key), it is a
    filename match: the stronger claim and a higher confidence than temporal."""
    from src.aggregator.evidence_aggregator import (
        enrich_evidence_items, _build_exfiltration_findings,
    )
    items = [
        {"artifact_id": "net1", "source_tool": "tshark",
         "evidence_type": "network_connection",
         "value": "TCP 10.0.0.5 -> 9.9.9.9:443 POST /upload/payload.exe (1500000 bytes)",
         "severity": "high", "confidence": 0.8,
         "timestamp": "2026-05-08T12:05:00Z", "linked_artifacts": []},
        {"artifact_id": "file1", "source_tool": "tsk_fls",
         "evidence_type": "file_artifact",
         "value": "Suspicious file: C:/Users/admin/AppData/Temp/payload.exe",
         "severity": "medium", "confidence": 0.75,
         "timestamp": "2026-05-08T12:01:00Z", "linked_artifacts": []},
    ]
    enriched, signals = enrich_evidence_items(items, {"case_id": "c"})
    findings = _build_exfiltration_findings(enriched, signals)
    assert len(findings) == 1
    assert findings[0]["match_type"] == "filename"
    assert any("file name matched" in c for c in findings[0]["what_confirmed_it"])


def test_run_bulk_aggregation_writes_summary():
    """Test that the CLI bulk helper aggregates multiple machine bundles."""
    with tempfile.TemporaryDirectory() as tmpdir:
        machine_a_raw = Path(tmpdir) / "machine_a" / "raw"
        machine_b_raw = Path(tmpdir) / "machine_b" / "raw"
        output_root = Path(tmpdir) / "bulk_output"
        summary_path = Path(tmpdir) / "bulk_summary.json"
        machine_a_raw.mkdir(parents=True, exist_ok=True)
        machine_b_raw.mkdir(parents=True, exist_ok=True)

        shared_item = {
            "artifact_id": "proc_shared",
            "source_tool": "volatility3",
            "evidence_type": "process",
            "value": "powershell.exe (PID:9001 PPID:100)",
            "severity": "high",
            "confidence": 0.9,
            "timestamp": "2026-05-08T12:00:00Z",
            "linked_artifacts": [],
        }

        with (machine_a_raw / "volatility_output.json").open("w") as f:
            json.dump({"tool": "volatility3", "items": [shared_item]}, f)

        with (machine_b_raw / "volatility_output.json").open("w") as f:
            json.dump({"tool": "volatility3", "items": [shared_item]}, f)

        manifest = {
            "output_root": str(output_root),
            "summary_path": str(summary_path),
            "machines": [
                {
                    "machine_name": "machine_a",
                    "raw_outputs_dir": str(machine_a_raw),
                    "case_context": {"case_id": "case-a", "affected_systems": ["machine-a"]},
                },
                {
                    "machine_name": "machine_b",
                    "raw_outputs_dir": str(machine_b_raw),
                    "case_context": {"case_id": "case-b", "affected_systems": ["machine-b"]},
                },
            ],
        }

        manifest_path = Path(tmpdir) / "bulk_manifest.json"
        with manifest_path.open("w") as f:
            json.dump(manifest, f)

        result = run_bulk_aggregation(str(manifest_path))

        assert summary_path.exists()
        assert result["bulk_summary"]["total_items"] == 2
        assert len(result["bulk_summary"]["machines"]) == 2
        assert result["bulk_summary"]["machines"][0]["findings"] >= 0


def test_process_tree_does_not_contaminate_correlations():
    """The process_tree aggregate names every PID in a subtree. It must not
    join (nor anchor) PID correlation groups, and correlations must not be
    duplicated on the anchor item (regression for the double-listing bug where
    the anchor id appeared twice in a finding's `artifacts`)."""
    items = [
        {"artifact_id": "process_tree_1636", "evidence_type": "process_tree",
         "source_tool": "volatility3", "severity": "medium",
         "value": "explorer.exe (1636) -> tasksche.exe (1940) -> @WanaDecryptor@ (740)"},
        {"artifact_id": "proc_1940_tasksche_exe", "evidence_type": "process",
         "source_tool": "volatility3", "severity": "high",
         "value": "tasksche.exe (PID:1940)"},
        {"artifact_id": "cmdline_1940", "evidence_type": "commandline",
         "source_tool": "volatility3", "severity": "medium",
         "value": "C:/Intel/tasksche.exe (PID:1940)"},
        # An information-adding item (a network beacon from the same PID, from a
        # different tool) so PID 1940 legitimately forms a same_pid group under
        # the 4.7 rule — otherwise process+cmdline alone is suppressed as noise.
        {"artifact_id": "net_1940", "evidence_type": "network_connection",
         "source_tool": "tshark", "severity": "high",
         "value": "TCP beacon to 165.245.215.18:4444 (PID:1940)"},
    ]
    enriched, signals = enrich_evidence_items(items, {"case_id": "X"})
    annotated, findings = build_correlations(enriched, signals)

    # the tree participates in no correlation
    tree = next(i for i in annotated if i["artifact_id"] == "process_tree_1636")
    assert tree.get("correlations") == []

    same_pid = [f for f in findings if f["correlation_type"] == "same_pid"]
    assert same_pid, "PID 1940 should correlate via process + cmdline + network"
    # never anchored on the tree
    assert all(f.get("item") != "process_tree_1636" for f in same_pid)

    # no duplicate correlation entries on any item
    for item in annotated:
        entries = [json.dumps(c, sort_keys=True) for c in item.get("correlations", [])]
        assert len(entries) == len(set(entries)), f"duplicate on {item['artifact_id']}"


def test_domain_correlation_links_pcap_dns_to_memory_string():
    """Issue B1 / P4-DOMAIN: a memory-recovered `suspicious_domain` carries no
    IP/path/PID, so before the domain signal it had zero correlation keys and
    the killswitch was never tied to the pcap DNS query. The new `same_domain`
    signal links them, normalising the `www.` prefix the memory copy carries."""
    items = [
        {"artifact_id": "dns_ks", "evidence_type": "dns_query", "source_tool": "tshark",
         "severity": "high", "timestamp": "1781000001.0",
         "value": "DNS query from 10.10.14.22 → evil-killswitch.com (label entropy: 3.9)"},
        {"artifact_id": "dom_ks", "evidence_type": "suspicious_domain", "source_tool": "volatility3",
         "severity": "high", "value": "www.evil-killswitch.com"},
        # An http path with a dotted filename must NOT register the file as a domain.
        {"artifact_id": "http_drop", "evidence_type": "http_request", "source_tool": "tshark",
         "severity": "medium", "value": "HTTP 10.10.14.22 → drop-host.xyz/tasksche.exe"},
        # A process item is not domain-bearing — its dotted name is not a domain.
        {"artifact_id": "proc_t", "evidence_type": "process", "source_tool": "volatility3",
         "severity": "high", "value": "tasksche.exe (PID:1940 PPID:1636)"},
        # Two benign www/non-www copies of one host in the SAME memory image must
        # NOT correlate — single tool, single type is near-zero signal (4.7).
        {"artifact_id": "dom_b1", "evidence_type": "suspicious_domain", "source_tool": "volatility3",
         "severity": "low", "value": "msdn.com"},
        {"artifact_id": "dom_b2", "evidence_type": "suspicious_domain", "source_tool": "volatility3",
         "severity": "low", "value": "www.msdn.com"},
    ]
    enriched, signals = enrich_evidence_items(items, {"case_id": "X"})
    annotated, findings = build_correlations(enriched, signals)

    same_domain = [f for f in findings if f["correlation_type"] == "same_domain"]
    ks = [f for f in same_domain if "evil-killswitch.com" in f["finding"]]
    assert len(ks) == 1, "killswitch must correlate across pcap dns and memory string"
    assert set(ks[0]["artifacts"]) == {"dns_ks", "dom_ks"}
    # the benign single-tool/single-type memory pair is suppressed
    assert not any("msdn.com" in f["finding"] for f in same_domain)

    # the http filename is not a domain, and the process is not domain-bearing
    assert signals["http_drop"]["domains"] == ["drop-host.xyz"]
    assert signals["proc_t"]["domains"] == []
    # both endpoints now carry the correlation
    by_id = {i["artifact_id"]: i for i in annotated}
    for endpoint in ("dns_ks", "dom_ks"):
        types = [c["correlation_type"] for c in by_id[endpoint]["correlations"]]
        assert "same_domain" in types


def test_wrapper_linked_artifacts_become_correlations():
    """Issue 4.6: a process_relation's value names process NAMES, not PIDs, so
    same_pid can't tie it to the concrete process items — only the wrapper's
    explicit linked_artifacts can. Those links must be propagated as a
    `linked_artifact` finding, resolving the proc_<pid> -> proc_<pid>_<name>
    prefix, so the lineage IOC is connected to its parent/child processes.
    """
    items = [
        {"artifact_id": "proc_1636_explorer_exe", "evidence_type": "process",
         "source_tool": "volatility3", "severity": "low",
         "value": "explorer.exe (PID:1636 PPID:1600)", "linked_artifacts": []},
        {"artifact_id": "proc_1940_tasksche_exe", "evidence_type": "process",
         "source_tool": "volatility3", "severity": "high",
         "value": "tasksche.exe (PID:1940 PPID:1636)", "linked_artifacts": []},
        {"artifact_id": "relation_1636_1940", "evidence_type": "process_relation",
         "source_tool": "volatility3", "severity": "critical",
         "value": "Suspicious parent-child relationship: explorer.exe -> tasksche.exe",
         "linked_artifacts": ["proc_1636", "proc_1940"]},
    ]
    enriched, signals = enrich_evidence_items(items, {"case_id": "X"})
    annotated, findings = build_correlations(enriched, signals)

    linked = [f for f in findings if f["correlation_type"] == "linked_artifact"]
    assert len(linked) == 1
    assert set(linked[0]["artifacts"]) == {
        "relation_1636_1940", "proc_1636_explorer_exe", "proc_1940_tasksche_exe",
    }
    # both the parent and child process items now carry the correlation
    by_id = {i["artifact_id"]: i for i in annotated}
    for pid_item in ("proc_1636_explorer_exe", "proc_1940_tasksche_exe", "relation_1636_1940"):
        types = [c["correlation_type"] for c in by_id[pid_item]["correlations"]]
        assert "linked_artifact" in types


def test_linked_artifact_skipped_when_signal_finding_covers_it():
    """A link already fully covered by a signal finding (e.g. injected_code and
    its process share an extractable PID -> same_pid) must NOT be duplicated as a
    separate linked_artifact finding.
    """
    items = [
        {"artifact_id": "malfind_596", "evidence_type": "injected_code",
         "source_tool": "volatility3", "severity": "high",
         "value": "Injected memory regions detected in csrss.exe (PID:596).",
         "linked_artifacts": ["proc_596"]},
        {"artifact_id": "proc_596_csrss_exe", "evidence_type": "process",
         "source_tool": "volatility3", "severity": "low",
         "value": "csrss.exe (PID:596 PPID:500)", "linked_artifacts": []},
    ]
    enriched, signals = enrich_evidence_items(items, {"case_id": "X"})
    _, findings = build_correlations(enriched, signals)
    types = {f["correlation_type"] for f in findings}
    assert "same_pid" in types
    assert "linked_artifact" not in types


def test_linked_target_prefix_does_not_overmatch():
    """proc_59 must not resolve to proc_596_* (boundary-aware prefix)."""
    from src.aggregator.evidence_aggregator import _resolve_linked_target
    by_id = {
        "proc_596_csrss_exe": {"artifact_id": "proc_596_csrss_exe"},
        "proc_59_foo_exe": {"artifact_id": "proc_59_foo_exe"},
    }
    assert [i["artifact_id"] for i in _resolve_linked_target("proc_59", by_id)] == ["proc_59_foo_exe"]
    assert [i["artifact_id"] for i in _resolve_linked_target("proc_596", by_id)] == ["proc_596_csrss_exe"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# ─────────────────────────────────────────────────────────────
# MemProcFS process de-duplication against Volatility (issue D6)
# ─────────────────────────────────────────────────────────────

def _vol(pid, ppid, name="svchost.exe"):
    return {"evidence_type": "process", "source_tool": "volatility3",
            "value": f"{name} (PID:{pid} PPID:{ppid})", "artifact_id": f"proc_{pid}"}


def _mpfs(pid, ppid, name="svchost.exe"):
    return {"evidence_type": "memprocfs_process", "source_tool": "memprocfs",
            "value": f"{name} (PID {pid}, PPID {ppid})",
            "artifact_id": f"memprocfs_proc_{pid}"}


def test_reconcile_drops_memprocfs_duplicate_by_pid():
    # When Volatility already lists a PID, the MemProcFS copy is noise — drop it.
    items = [_vol(880, 1944), _vol(1944, 600), _mpfs(880, 1944)]
    kept, removed = reconcile_memprocfs_processes(items)
    assert removed == 1
    assert not any(i["evidence_type"] == "memprocfs_process" for i in kept)
    # Volatility's own items are untouched.
    assert sum(1 for i in kept if i["evidence_type"] == "process") == 2


def test_reconcile_keeps_memprocfs_pid_unique_to_it():
    # A PID only MemProcFS saw (e.g. a hidden/terminated proc Volatility missed)
    # must be preserved — reconciliation only removes true duplicates.
    items = [_vol(880, 1944), _mpfs(880, 1944), _mpfs(4242, 880, "secret.exe")]
    kept, removed = reconcile_memprocfs_processes(items)
    assert removed == 1
    survivors = {i["artifact_id"] for i in kept}
    assert "memprocfs_proc_4242" in survivors
    assert "memprocfs_proc_880" not in survivors


def test_reconcile_keeps_all_memprocfs_when_volatility_absent():
    # If Volatility produced no process list, MemProcFS is the only process
    # source and must be kept intact as the fallback.
    items = [_mpfs(880, 1944), _mpfs(4242, 880)]
    kept, removed = reconcile_memprocfs_processes(items)
    assert removed == 0
    assert len(kept) == 2


def test_reconcile_does_not_confuse_ppid_with_pid():
    # The MemProcFS proc whose PPID equals a Volatility PID, but whose own PID is
    # unique, must NOT be dropped (parent pid is not the process pid).
    items = [_vol(1944, 600), _mpfs(7777, 1944)]  # mpfs PID 7777, PPID 1944
    kept, removed = reconcile_memprocfs_processes(items)
    assert removed == 0
    assert any(i["artifact_id"] == "memprocfs_proc_7777" for i in kept)
