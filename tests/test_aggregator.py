"""Test suite for the Evidence Aggregator (P4)."""

import json
import os
import pytest
import tempfile
from pathlib import Path
from src.aggregator.evidence_aggregator import (
    deduplicate_items,
    sort_evidence_items,
    build_indices,
    aggregate_evidence,
    load_raw_outputs,
    enrich_evidence_items,
    build_correlations,
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
                    "value": "TCP 10.0.0.5 → 185.220.101.47:4444 (1500000 bytes, 12 packets)",
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


    def test_aggregate_evidence_builds_correlations_and_exfiltration():
        """Test that correlations and exfiltration findings are generated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            raw_dir = Path(tmpdir) / "raw"
            raw_dir.mkdir(parents=True, exist_ok=True)

            vol_output = {
                "tool": "volatility3",
                "items": [
                    {"artifact_id": "proc_10", "source_tool": "volatility3",
                     "evidence_type": "process", "value": "svchost.exe (pid:10)",
                     "severity": "medium", "confidence": 0.7, "timestamp": "2023-01-01T10:00:00Z", "linked_artifacts": []},
                    {"artifact_id": "file_a", "source_tool": "volatility3",
                     "evidence_type": "file", "value": "C:\\Users\\user\\secrets.txt", 
                     "severity": "low", "confidence": 0.6, "timestamp": "2023-01-01T09:59:00Z", "linked_artifacts": []}
                ]
            }

            tshark_output = {
                "tool": "tshark",
                "items": [
                    {"artifact_id": "conn_1", "source_tool": "tshark",
                     "evidence_type": "network_connection", "value": "1.2.3.4:4444", 
                     "severity": "high", "confidence": 0.9, "timestamp": "1672560000", "linked_artifacts": []}
                ]
            }

            with (raw_dir / "volatility_output.json").open("w") as f:
                json.dump(vol_output, f)
            with (raw_dir / "tshark_output.json").open("w") as f:
                json.dump(tshark_output, f)

            case_context = {"case_id": "case_exf", "affected_systems": ["host-1"]}
            result = aggregate_evidence(
                case_context=case_context,
                raw_outputs_dir=str(raw_dir),
                output_path=str(Path(tmpdir) / "unified.json")
            )

            # Should have at least one finding and possibly exfiltration finding
            assert isinstance(result.get("findings"), list)
            assert isinstance(result.get("exfiltration_findings"), list)


    def test_run_bulk_aggregation_writes_summary():
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create two machine raw dirs
            machines = {
                "hostA": {"raw_outputs_dir": str(Path(tmpdir) / "hostA_raw"), "case_context": {"case_id": "hostA"}},
                "hostB": {"raw_outputs_dir": str(Path(tmpdir) / "hostB_raw"), "case_context": {"case_id": "hostB"}}
            }
            Path(machines["hostA"]["raw_outputs_dir"]).mkdir(parents=True)
            Path(machines["hostB"]["raw_outputs_dir"]).mkdir(parents=True)

            # Add a small tshark output for hostA
            tshark_output = {"tool": "tshark", "items": []}
            with (Path(machines["hostA"]["raw_outputs_dir"]) / "tshark_output.json").open("w") as f:
                json.dump(tshark_output, f)

            sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
            from src.aggregator.evidence_aggregator import aggregate_bulk_evidence

            summary = aggregate_bulk_evidence(machines, output_root=str(Path(tmpdir) / "bulk_out"))
            assert summary["machines"]


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
    ]
    enriched, signals = enrich_evidence_items(items, {"case_id": "X"})
    annotated, findings = build_correlations(enriched, signals)

    # the tree participates in no correlation
    tree = next(i for i in annotated if i["artifact_id"] == "process_tree_1636")
    assert tree.get("correlations") == []

    same_pid = [f for f in findings if f["correlation_type"] == "same_pid"]
    assert same_pid, "PID 1940 should still correlate via process + cmdline"
    # never anchored on the tree
    assert all(f.get("item") != "process_tree_1636" for f in same_pid)

    # no duplicate correlation entries on any item
    for item in annotated:
        entries = [json.dumps(c, sort_keys=True) for c in item.get("correlations", [])]
        assert len(entries) == len(set(entries)), f"duplicate on {item['artifact_id']}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
