"""Tests for report table rendering robustness under multi-tool input.

Covers the Process Tree builder (flat-item PID/PPID hierarchy, prune-to-flagged,
severity + source-file rendering, no cross-type leakage) and the markdown cell
sanitizer used by the IOC / MITRE / Critical Findings tables.
"""

import json
from pathlib import Path

from src.report_generator.report_generator import (
    MITRE_BY_CASE,
    RECOMMENDATIONS_BY_CASE,
    _build_correlated_findings,
    _build_dashboard_summary,
    _build_evidence_coverage,
    _build_ioc_report,
    _build_ml_only_section,
    _build_process_tree,
    _evidence_techniques,
    _extract_iocs,
    _finding_sort_key,
    _indicators_cell,
    _item_indicators,
    _md_cell,
    _mock_report,
    _parse_flat_pids,
    _truncate,
)


def _proc(pid, ppid, name, severity="low", **extra):
    item = {
        "evidence_type": "process",
        "source_tool": "volatility3",
        "value": f"{name} (PID:{pid} PPID:{ppid})",
        "severity": severity,
        "artifact_id": f"proc_{pid}_{name.replace('.', '_')}",
    }
    item.update(extra)
    return item


def test_md_cell_escapes_pipes_and_collapses_newlines():
    assert _md_cell("a | b") == "a \\| b"
    assert _md_cell("line1\nline2\r\nline3") == "line1 line2 line3"
    assert _md_cell("   spaced   out  ") == "spaced out"
    assert _md_cell("") == "-"
    assert _md_cell(None) == "-"


def test_parse_flat_pids_does_not_confuse_pid_with_ppid():
    # PPID appearing before PID must not bleed into the PID match.
    assert _parse_flat_pids("svchost.exe (PPID 1636, PID 1940)") == ("1940", "1636")
    assert _parse_flat_pids("tasksche.exe (PID:1940 PPID:1636)") == ("1940", "1636")
    # Only a PPID present -> PID stays None (no false match inside "ppid").
    assert _parse_flat_pids("orphan (PPID:1636)") == (None, "1636")


def test_process_tree_ignores_non_process_artifacts():
    items = [
        {"evidence_type": "file_artifact", "source_tool": "tsk_fls",
         "value": "Suspicious file: /tmp/pulse-ubuntu/pid", "severity": "high",
         "artifact_id": "file_1"},
        {"evidence_type": "network_connection", "source_tool": "volatility3",
         "value": "1.2.3.4:4444 [ESTABLISHED] PID:1940", "severity": "high",
         "artifact_id": "net_1"},
        _proc(1940, 1636, "tasksche.exe", severity="critical"),
    ]
    tree = _build_process_tree(items, anomaly_ids=set())
    assert "tasksche.exe" in tree
    # The file and network artifacts must not appear as process rows.
    assert "pulse-ubuntu" not in tree
    assert "1.2.3.4" not in tree


def test_process_tree_hierarchy_severity_and_source_file():
    items = [
        _proc(1636, 1608, "explorer.exe", severity="low"),
        _proc(1940, 1636, "tasksche.exe", severity="critical",
              ioc_match=["wannacry_dropper"]),
    ]
    tree = _build_process_tree(items, anomaly_ids=set(),
                               tool_sources={"volatility3": "memdump.raw"})
    lines = tree.splitlines()
    parent = next(l for l in lines if "explorer.exe" in l)
    child = next(l for l in lines if "tasksche.exe" in l)
    # Child indented under parent, correct PID/PPID.
    assert child.index("tasksche.exe") > parent.index("explorer.exe")
    assert "PID 1940" in child and "PPID 1636" in child
    # Severity word per row (no [!]/[ ] glyph); benign ancestor retained.
    assert "CRITICAL" in child
    assert "LOW" in parent
    assert "[!]" not in tree and "[ ]" not in tree
    # Source-file column resolves from tool_sources.
    assert "memdump.raw" in child


def test_process_tree_prunes_benign_keeps_ancestors():
    items = [
        _proc(1636, 1608, "explorer.exe", severity="low"),
        _proc(1940, 1636, "tasksche.exe", severity="critical"),
        _proc(5000, 1636, "notepad.exe", severity="low"),  # benign sibling
    ]
    tree = _build_process_tree(items, anomaly_ids=set())
    assert "tasksche.exe" in tree     # flagged
    assert "explorer.exe" in tree     # ancestor of a flagged node -> kept
    assert "notepad.exe" not in tree  # benign, no flagged descendant -> pruned


def test_process_relation_flags_low_severity_child():
    items = [
        _proc(1636, 1608, "explorer.exe", severity="low"),
        _proc(1900, 1636, "winword.exe", severity="low"),
        _proc(2000, 1900, "powershell.exe", severity="low"),  # low on its own
        _proc(7000, 1636, "calc.exe", severity="low"),         # unrelated benign
        {"evidence_type": "process_relation", "source_tool": "volatility3",
         "value": "Suspicious parent-child relationship: winword.exe -> powershell.exe",
         "severity": "critical", "artifact_id": "relation_1900_2000",
         "linked_artifacts": ["proc_1900", "proc_2000"]},
    ]
    tree = _build_process_tree(items, anomaly_ids=set())
    assert "powershell.exe" in tree  # flagged via process_relation despite low sev
    assert "winword.exe" in tree     # ancestor kept
    assert "calc.exe" not in tree    # unrelated benign pruned


def test_process_tree_no_flagged_processes_sentinel():
    items = [
        _proc(1636, 1608, "explorer.exe", severity="low"),
        _proc(5000, 1636, "notepad.exe", severity="low"),
    ]
    out = _build_process_tree(items, anomaly_ids=set())
    assert out.startswith("_No flagged processes")


def test_extract_iocs_skips_aggregate_process_items():
    # A process_tree summary and a process_relation re-list benign names; their
    # critical severity + ioc_match must NOT be stamped onto those names as files.
    items = [
        {"evidence_type": "process_tree", "source_tool": "volatility3",
         "value": "explorer.exe (PID:1636)\n  ctfmon.exe (PID:1700)\n  tasksche.exe (PID:1940)",
         "severity": "critical", "ioc_match": ["wannacry_dropper"],
         "artifact_id": "process_tree_1636"},
        {"evidence_type": "process_relation", "source_tool": "volatility3",
         "value": "Suspicious parent-child relationship: explorer.exe -> tasksche.exe",
         "severity": "critical", "artifact_id": "relation_1636_1940"},
        # Discrete items remain the authoritative source for file IOCs.
        {"evidence_type": "process", "source_tool": "volatility3",
         "value": "tasksche.exe (PID:1940 PPID:1636)", "severity": "critical",
         "ioc_match": ["wannacry_dropper"], "artifact_id": "proc_1940"},
    ]
    iocs = _extract_iocs(items)
    files = {r["indicator"]: r for r in iocs if r["type"] == "Suspicious File"}
    # Benign names that appeared only inside the aggregates are not listed.
    assert "explorer.exe" not in files
    assert "ctfmon.exe" not in files
    # The real indicator survives via its discrete process item.
    assert "tasksche.exe" in files
    assert files["tasksche.exe"]["severity"] == "critical"


def test_extract_iocs_skips_low_severity_files_without_match():
    # A benign low-severity process with no ioc_match is not an indicator.
    items = [
        {"evidence_type": "process", "source_tool": "volatility3",
         "value": "explorer.exe (PID:1636 PPID:1608)", "severity": "low",
         "confidence": 0.9, "artifact_id": "proc_1636"},
        # High severity -> kept.
        {"evidence_type": "process", "source_tool": "volatility3",
         "value": "tasksche.exe (PID:1940 PPID:1636)", "severity": "high",
         "artifact_id": "proc_1940"},
        # Low severity but a catalog match -> kept.
        {"evidence_type": "file_artifact", "source_tool": "tsk_fls",
         "value": "@WanaDecryptor@.exe", "severity": "low",
         "ioc_match": ["wannacry_decryptor"], "artifact_id": "file_9"},
    ]
    files = {r["indicator"] for r in _extract_iocs(items)
             if r["type"] == "Suspicious File"}
    assert "explorer.exe" not in files          # low + no match -> dropped
    assert "tasksche.exe" in files               # high severity -> kept
    assert "@WanaDecryptor@.exe" in files        # low but ioc_match -> kept


def test_extract_iocs_rejects_impossible_ip_octets():
    # The IP regex matches \d{1,3} per octet, so out-of-range dotted-quads
    # (999.999.999.999, 256.0.0.1) must not be emitted as external IP IOCs.
    items = [
        {"evidence_type": "network_connection", "source_tool": "volatility3",
         "value": "TCP 10.0.0.5:1100 -> 185.62.1.2:4444 ; junk 999.999.999.999 256.0.0.1",
         "severity": "high", "artifact_id": "net_1"},
    ]
    ips = {r["indicator"] for r in _extract_iocs(items) if r["type"] == "IP Address"}
    assert ips == {"185.62.1.2"}                 # only the real external IP
    assert "999.999.999.999" not in ips
    assert "256.0.0.1" not in ips
    assert "10.0.0.5" not in ips                  # internal, still filtered


def test_item_indicators_extracts_extensionless_flagged_name():
    # A flagged binary with no file extension must still surface as an IOC.
    wd = {"evidence_type": "ioc", "source_tool": "ioc_engine",
          "value": "Suspicious process detected: @WanaDecryptor@",
          "severity": "critical", "ioc_match": ["wannacry_decryptor"],
          "artifact_id": "ioc_wd"}
    assert ("Suspicious File", "@WanaDecryptor@") in _item_indicators(wd)
    # Free-text with no bare name must NOT become a fake file IOC.
    inj = {"evidence_type": "ioc", "source_tool": "ioc_engine",
           "value": "Process injection detected", "severity": "critical",
           "artifact_id": "ioc_inj"}
    assert not any(t == "Suspicious File" for t, _ in _item_indicators(inj))


def test_item_indicators_surfaces_string_sweep_iocs():
    # String-sweep C2 / crypto / registry IOCs carry the bare indicator as their
    # value (no "→" arrow) and must still reach the report's indicators table.
    dom = {"evidence_type": "suspicious_domain", "source_tool": "volatility3",
           "value": "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
           "severity": "high", "artifact_id": "dom_1"}
    assert ("Domain", "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com") in \
        _item_indicators(dom)

    onion = {"evidence_type": "suspicious_domain", "source_tool": "volatility3",
             "value": "gx7ekbenv2riucmf.onion", "severity": "high",
             "artifact_id": "ioc_onion"}
    assert ("Onion Address", "gx7ekbenv2riucmf.onion") in _item_indicators(onion)

    btc = {"evidence_type": "suspicious_crypto", "source_tool": "volatility3",
           "value": "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94", "severity": "high",
           "artifact_id": "btc_1"}
    assert ("Crypto Wallet", "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94") in \
        _item_indicators(btc)

    # A non-legacy-BTC wallet (e.g. bech32 / ETH) the regex can't match must
    # still surface via the bare-value fallback, not be silently dropped.
    bech32 = {"evidence_type": "suspicious_crypto", "source_tool": "volatility3",
              "value": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
              "severity": "high", "artifact_id": "btc_2"}
    assert ("Crypto Wallet", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") in \
        _item_indicators(bech32)

    reg = {"evidence_type": "registry_key", "source_tool": "volatility3",
           "value": "\\Registry\\Machine\\SOFTWARE\\WanaCrypt0r",
           "severity": "medium", "artifact_id": "reg_1"}
    assert ("Registry Key", "\\Registry\\Machine\\SOFTWARE\\WanaCrypt0r") in \
        _item_indicators(reg)


def test_item_indicators_extracts_url_and_host_from_timeline_event():
    # plaso timeline_event values embed the URL inline (no "→" arrow); before the branch existed,
    # plaso-only runs (ubnist1 E01) reported ioc_count 0 despite 177 URL-bearing events.
    ev = {"evidence_type": "timeline_event", "source_tool": "plaso",
          "value": "[12/28/2008 21:30:03] [Firefox History] "
                   "http://hraunfoss.fcc.gov/edocs_public/attachmatch/FCC-08-281A1.doc "
                   "(FCC-08-281A1.doc) [count: 0] Host: hraunfoss.fcc.gov visited from: "
                   "http://www.fcc.gov/ (www.fcc.gov) Transition: DOWNLOAD",
          "severity": "medium", "artifact_id": "tl_1"}
    inds = _item_indicators(ev)
    assert ("URL", "http://hraunfoss.fcc.gov/edocs_public/attachmatch/FCC-08-281A1.doc") in inds
    assert ("Domain", "hraunfoss.fcc.gov") in inds

    # events without an embedded URL/host (e.g. filesystem timestamps) yield nothing
    fs = {"evidence_type": "timeline_event", "source_tool": "plaso",
          "value": "[12/28/2008 21:30:03] [FILE] atime /home/ubuntu/Desktop/report.doc",
          "severity": "low", "artifact_id": "tl_2"}
    assert _item_indicators(fs) == []


def test_finding_sort_key_ranks_ioc_bearing_above_indicatorless():
    # Within the same severity tier, an item carrying a concrete IOC (a .onion
    # C2 here) must sort ahead of an indicator-less item (a ransom-note language
    # file with no extractable indicator and no catalog match), so it isn't cut
    # by KEY_FINDINGS_CAP (issue 3.3-I).
    onion = {"evidence_type": "suspicious_domain", "value": "gx7ekbenv2riucmf.onion",
             "severity": "high", "artifact_id": "onion_1"}
    wnry = {"evidence_type": "file_artifact",
            "value": "\\Intel\\ivecuqmanpnirkt615\\msg\\m_russian.wnry",
            "severity": "high", "artifact_id": "file_wnry"}
    assert not _item_indicators(wnry) and not wnry.get("ioc_match")  # truly indicator-less
    assert _finding_sort_key(onion) < _finding_sort_key(wnry)
    # Severity still dominates the tie-break: a critical indicator-less item
    # outranks a high IOC-bearing one.
    crit_blank = {**wnry, "severity": "critical", "artifact_id": "file_crit"}
    assert _finding_sort_key(crit_blank) < _finding_sort_key(onion)


def test_item_indicators_extracts_atoms_per_item():
    net = {"evidence_type": "network_connection", "source_tool": "volatility3",
           "value": "TCP 10.0.0.5:1100 -> 185.62.1.2:4444 [EST] PID:1940",
           "severity": "high", "artifact_id": "net_1"}
    inds = dict(_item_indicators(net))
    assert inds.get("IP Address") == "185.62.1.2"  # external only; 10.x dropped


def test_indicators_cell_renders_atoms_and_match_badge():
    item = {"evidence_type": "injected_code", "source_tool": "volatility3",
            "value": "Injected memory regions detected in tasksche.exe (PID:1940)",
            "severity": "critical", "ioc_match": ["wannacry_dropper"],
            "artifact_id": "malfind_1940"}
    cell = _indicators_cell(item)
    assert "`tasksche.exe` (Suspicious File)" in cell
    assert "**IOC: wannacry_dropper**" in cell
    # Match badge follows inline via " · " (no raw <br> HTML, portable markdown).
    assert "(Suspicious File) · **IOC: wannacry_dropper**" in cell
    assert "<br>" not in cell


def test_indicators_cell_empty_for_plain_finding():
    # A process_relation carries no atomic indicator and no match -> "-".
    item = {"evidence_type": "process_relation", "source_tool": "volatility3",
            "value": "Suspicious parent-child relationship: explorer.exe -> tasksche.exe",
            "severity": "critical", "artifact_id": "relation_1636_1940"}
    assert _indicators_cell(item) == "-"


def test_extract_iocs_tracks_tools_and_artifact_ids():
    items = [
        {"evidence_type": "network_connection", "source_tool": "volatility3",
         "value": "TCP 10.0.0.5:1100 -> 185.62.1.2:4444 [EST]", "severity": "high",
         "artifact_id": "net_1"},
        {"evidence_type": "network_connection", "source_tool": "tshark",
         "value": "185.62.1.2:4444 C2 beacon", "severity": "critical",
         "artifact_id": "pcap_9"},
    ]
    rec = next(r for r in _extract_iocs(items) if r["indicator"] == "185.62.1.2")
    assert rec["tools"] == {"volatility3", "tshark"}
    assert rec["artifact_ids"] == {"net_1", "pcap_9"}
    # Highest severity across contributing items is retained.
    assert rec["severity"] == "critical"


def test_build_ioc_report_lists_indicators_with_provenance():
    items = [
        {"evidence_type": "process", "source_tool": "volatility3",
         "value": "tasksche.exe (PID:1940 PPID:1636)", "severity": "critical",
         "ioc_match": ["wannacry_dropper"], "artifact_id": "proc_1940"},
        {"evidence_type": "network_connection", "source_tool": "tshark",
         "value": "TCP 10.0.0.5:1100 -> 185.62.1.2:4444 [EST]", "severity": "high",
         "artifact_id": "net_1"},
    ]
    md = _build_ioc_report(
        items,
        tool_sources={"volatility3": "wannacry.raw", "tshark": "capture.pcap"},
        anomaly_lookup={"proc_1940": "Artifact proc_1940 flagged: ransomware dropper"},
    )
    assert "# AutoForensiq — Indicators of Compromise" in md
    assert "`tasksche.exe`" in md and "`185.62.1.2`" in md
    # Provenance: tool · source file resolved.
    assert "volatility3 · wannacry.raw" in md
    assert "tshark · capture.pcap" in md
    # IOC-catalog match and per-indicator XAI surfaced.
    assert "wannacry_dropper" in md
    assert "ransomware dropper" in md
    # Critical indicator sorts above the high one.
    assert md.index("tasksche.exe") < md.index("185.62.1.2")


def test_build_ioc_report_empty_sentinel():
    md = _build_ioc_report([])
    assert "# AutoForensiq — Indicators of Compromise" in md
    assert "_No indicators of compromise extracted from evidence._" in md


def _kf_section(report_md):
    """Extract just the '## Key Findings' section body from a mock report."""
    block = report_md.split("## Key Findings", 1)[1]
    return block.split("\n## ", 1)[0]


def test_key_findings_suppresses_empty_derived_rows():
    items = [
        # Rich injection finding: indicator + match + (XAI via artifact_id).
        {"evidence_type": "injected_code", "source_tool": "volatility3",
         "value": "Injected memory regions detected in csrss.exe (PID:596)",
         "severity": "critical", "ioc_match": ["code_injection"],
         "artifact_id": "malfind_596"},
        # ioc_engine echo: critical but no indicator, no match, no XAI -> drop.
        {"evidence_type": "ioc", "source_tool": "ioc_engine",
         "value": "Process injection detected", "severity": "critical",
         "artifact_id": "ioc_injection_malfind_596",
         "linked_artifacts": ["malfind_596"]},
    ]
    ue = {"evidence_items": items, "total_items": len(items),
          "tools_aggregated": ["volatility3", "ioc_engine"]}
    shap = {"explanations": {"malfind_596": {"is_anomaly": True,
            "reason": "Injected RWX region in csrss.exe"}}}
    report = _mock_report(ue, shap, {"case_type": "ransomware"})
    kf = _kf_section(report)
    assert "csrss.exe" in kf                      # rich finding kept
    assert "Process injection detected" not in kf  # all-dashes echo dropped


def test_process_tree_empty_when_no_processes():
    items = [{"evidence_type": "dns_query", "value": "evil.com",
              "artifact_id": "dns_1", "source_tool": "tshark"}]
    assert _build_process_tree(items, anomaly_ids=set()) == \
        "_No process artifacts in evidence._"


def test_process_tree_raises_severity_on_repeat_observation():
    # Same PID seen first as low (e.g. pslist) then high (IOC-rescored copy).
    # The merge must keep the highest severity so the process stays flagged and
    # is not pruned out of the tree.
    items = [
        _proc(1940, 1636, "tasksche.exe", severity="low"),
        _proc(1940, 1636, "tasksche.exe", severity="high",
              ioc_match=["wannacry_dropper"]),
    ]
    tree = _build_process_tree(items, anomaly_ids=set())
    assert "tasksche.exe" in tree     # survives the prune-to-flagged step
    assert "HIGH" in tree             # highest severity wins, not first-seen low


# ─────────────────────────────────────────────────────────────
# Evidence-coverage table
# ─────────────────────────────────────────────────────────────

def test_coverage_marks_memprocfs_memory_dump_analysed():
    """memprocfs covers the memory_dump type even when volatility3 yields nothing."""
    table = _build_evidence_coverage(["memprocfs", "ioc_engine"])
    mem_row = next(r for r in table.splitlines() if r.startswith("| Memory Dump"))
    assert "Analysed" in mem_row
    assert "memprocfs" in mem_row
    # No garbled doubled status prefixes anywhere in the table.
    assert "NOT Not provided" not in table
    assert "OK Analysed" not in table


def test_coverage_lists_all_tools_for_shared_type():
    """A type backed by multiple tools attributes every tool that ran."""
    table = _build_evidence_coverage(["volatility3", "memprocfs"])
    mem_row = next(r for r in table.splitlines() if r.startswith("| Memory Dump"))
    assert "memprocfs" in mem_row and "volatility3" in mem_row


def test_coverage_uncovered_type_marked_not_provided():
    table = _build_evidence_coverage(["memprocfs"])
    pcap_row = next(r for r in table.splitlines() if r.startswith("| Pcap"))
    assert "Not provided" in pcap_row and "| - |" in pcap_row


def test_key_findings_includes_host_timestamp_and_friendly_type():
    items = [
        {"evidence_type": "memprocfs_process", "source_tool": "memprocfs",
         "value": "tasksche.exe (PID 1940, PPID 1636)", "severity": "high",
         "ioc_match": ["wannacry_dropper"], "artifact_id": "memprocfs_proc_1940",
         "machine_id": "10.0.0.7", "timestamp": "2026-06-03T14:32:01Z"},
    ]
    ue = {"evidence_items": items, "total_items": len(items),
          "tools_aggregated": ["memprocfs"]}
    report = _mock_report(ue, {"explanations": {}}, {"case_type": "ransomware"})
    kf = _kf_section(report)
    header = next(l for l in kf.splitlines() if l.startswith("| Severity"))
    assert "Host" in header and "Timestamp" in header
    row = next(l for l in kf.splitlines() if "tasksche.exe" in l)
    assert "10.0.0.7" in row                       # host column populated
    assert "2026-06-03T14:32:01Z" in row           # timestamp column populated
    assert "Process" in row                        # friendly label, not memprocfs_process
    assert "memprocfs_process" not in row          # internal type not leaked


def test_key_findings_empty_host_and_timestamp_render_dash():
    items = [
        {"evidence_type": "ioc", "source_tool": "ioc_engine",
         "value": "Suspicious process detected: cmd.exe", "severity": "high",
         "artifact_id": "ioc_1"},  # no machine_id, no timestamp
    ]
    ue = {"evidence_items": items, "total_items": len(items),
          "tools_aggregated": ["ioc_engine"]}
    report = _mock_report(ue, {"explanations": {}}, {"case_type": "ransomware"})
    row = next(l for l in _kf_section(report).splitlines() if "cmd.exe" in l)
    cells = [c.strip() for c in row.split("|")]
    # Layout: ['', Severity, Host, Timestamp, Type, Finding, Indicators, Src, XAI, '']
    assert cells[2] == "-"   # Host
    assert cells[3] == "-"   # Timestamp
    assert cells[4] == "IOC Match"


# ─────────────────────────────────────────────────────────────
# dev_report HTML inline rendering
# ─────────────────────────────────────────────────────────────

def test_dev_report_inline_renders_br_but_escapes_other_html():
    from src.utils.dev_report import _inline
    out = _inline("`csrss.exe` (Suspicious File)<br>**IOC: code_injection**")
    assert "<br>" in out                       # explicit line break honoured
    assert "<code>csrss.exe</code>" in out
    assert "<strong>IOC: code_injection</strong>" in out
    # All other raw HTML stays escaped (no passthrough / XSS).
    assert _inline("<script>x</script>") == "&lt;script&gt;x&lt;/script&gt;"


def test_dev_report_inline_italic_respects_word_boundaries():
    from src.utils.dev_report import _inline
    # _italic_ at word boundaries becomes <em>.
    assert _inline("_see the file._") == "<em>see the file.</em>"
    # Intraword underscores (catalog match names, paths) are NOT italicised.
    assert _inline("wannacry_dropper and code_injection") == \
        "wannacry_dropper and code_injection"
    # Emphasis spanning a code span keeps the code intact.
    assert _inline("_detail in `ioc_report.md`._") == \
        "<em>detail in <code>ioc_report.md</code>.</em>"


# ─────────────────────────────────────────────────────────────
# XAI explanation truncation
# ─────────────────────────────────────────────────────────────

def test_truncate_breaks_on_word_boundary():
    text = ("Artifact was flagged because its strongest anomaly drivers were "
            "the process privilege level and an unusual parent")
    out = _truncate(text, 80)
    assert out.endswith("…")
    assert len(out) <= 81                      # <= limit + the ellipsis char
    assert "  " not in out
    # The last visible word is whole — no dangling partial token before the …
    assert text.startswith(out[:-1])           # out (minus …) is a clean prefix
    assert out[:-1].split()[-1] in text.split()


def test_truncate_passes_short_text_and_sentinel():
    assert _truncate("short note", 80) == "short note"
    assert _truncate("-", 80) == "-"


def test_truncate_hard_cuts_a_long_unbroken_token():
    token = "a" * 120
    out = _truncate(token, 80)
    assert out == "a" * 80 + "…"


def test_build_ioc_report_truncates_long_xai_on_word_boundary():
    items = [
        {"evidence_type": "process", "source_tool": "volatility3",
         "value": "tasksche.exe (PID:1940 PPID:1636)", "severity": "critical",
         "ioc_match": ["wannacry_dropper"], "artifact_id": "proc_1940"},
    ]
    long_note = ("Artifact proc_1940 was flagged because its strongest anomaly "
                 "drivers were the process injection score and the suspicious "
                 "parent-child relationship observed in memory")
    md = _build_ioc_report(items, anomaly_lookup={"proc_1940": long_note})
    xai_row = next(l for l in md.splitlines() if "tasksche.exe" in l)
    xai_cell = xai_row.split("|")[-2].strip()
    assert xai_cell.endswith("…")
    assert long_note.startswith(xai_cell[:-1])   # clean word-boundary prefix


# ─────────────────────────────────────────────────────────────
# IOC report presentation filter (issue D3 — surface elevated, fold low mass)
# ─────────────────────────────────────────────────────────────

def test_ioc_report_surfaces_elevated_low_domain():
    # A domain emitted `low` by the wrapper but elevated to Critical downstream
    # (P5 / reputation, via severity_lookup) must appear in the main table; an
    # un-elevated low domain must be folded out of it (but stay in the doc).
    items = [
        {"evidence_type": "suspicious_domain", "source_tool": "volatility3",
         "value": "beaconads.com", "severity": "low", "confidence": 0.45,
         "artifact_id": "dom_1"},
        {"evidence_type": "suspicious_domain", "source_tool": "volatility3",
         "value": "across.com", "severity": "low", "confidence": 0.20,
         "artifact_id": "dom_2"},
    ]
    md = _build_ioc_report(items, severity_lookup={"dom_1": "critical"})
    main = md.split("#### Folded")[0]
    assert "`beaconads.com`" in main          # elevated -> surfaced
    assert "`across.com`" not in main         # un-elevated low -> folded out of table
    assert "`across.com`" in md               # ...but NOT dropped (folded sample)
    assert "#### Folded" in md


def test_ioc_report_folds_low_severity_mass_with_cap():
    # The low-severity string-sweep mass is folded into a capped sample, not
    # rendered as hundreds of rows — and the full count is reported.
    items = [
        {"evidence_type": "suspicious_domain", "source_tool": "volatility3",
         "value": f"noise{i}.com", "severity": "low", "confidence": 0.20,
         "artifact_id": f"dom_{i}"}
        for i in range(120)
    ]
    md = _build_ioc_report(items)
    assert "120" in md                                   # full folded count reported
    assert "#### Folded" in md
    sample_row_count = md.split("#### Folded", 1)[1].count("\n| `")
    assert sample_row_count <= 50                        # sample is capped


def test_ioc_report_folded_sample_orders_anchored_before_bare():
    # Within the folded sample, anchored (URL-context, conf>=0.45) domains rank
    # above bare ones, and the tier is labelled.
    items = [
        {"evidence_type": "suspicious_domain", "source_tool": "volatility3",
         "value": "bare-token.ru", "severity": "low", "confidence": 0.20,
         "artifact_id": "d1"},
        {"evidence_type": "suspicious_domain", "source_tool": "volatility3",
         "value": "anchored-host.io", "severity": "low", "confidence": 0.45,
         "artifact_id": "d2"},
    ]
    fold = _build_ioc_report(items).split("#### Folded", 1)[1]
    assert fold.index("anchored-host.io") < fold.index("bare-token.ru")
    assert "anchored" in fold and "bare" in fold


# ─────────────────────────────────────────────────────────────
# Overall severity: rule/IOC evidence is primary, P5 is a tie-breaker (5.3)
# ─────────────────────────────────────────────────────────────

def _ue(items):
    return {"evidence_items": items, "total_items": len(items),
            "tools_aggregated": sorted({e["source_tool"] for e in items})}


def _item(sev, aid="x1", etype="file_artifact", **extra):
    item = {"evidence_type": etype, "source_tool": "tsk_fls",
            "value": f"artifact {aid}", "severity": sev, "artifact_id": aid}
    item.update(extra)
    return item


def test_overall_severity_is_driven_by_evidence_not_anomaly_count():
    # A critical-IOC case with ZERO P5 anomalies must still read CRITICAL — the
    # old formula (high if n_anomalies>=3 ...) both capped at HIGH and ignored the
    # rule/IOC severities entirely (issue 5.3).
    items = [_item("critical", "f1", ioc_match=["wannacry_dropper"]),
             _item("high", "f2"), _item("low", "f3")]
    report = _mock_report(_ue(items), {"explanations": {}}, {"case_type": "ransomware"})
    assert "Overall case severity: **CRITICAL**" in report


def test_p5_breaks_tie_only_at_the_medium_high_margin():
    # Highest evidence severity is medium. With no anomaly it stays MEDIUM; one
    # independent P5 anomaly nudges it to HIGH (the tie-breaker), nothing more.
    items = [_item("medium", "f1"), _item("low", "f2")]
    quiet = _mock_report(_ue(items), {"explanations": {}}, {"case_type": "malware_infection"})
    assert "Overall case severity: **MEDIUM**" in quiet

    shap = {"explanations": {"f1": {"is_anomaly": True, "reason": "outlier"}}}
    nudged = _mock_report(_ue(items), shap, {"case_type": "malware_infection"})
    assert "Overall case severity: **HIGH**" in nudged


def test_p5_cannot_override_or_manufacture_severity():
    # P5 silence does not downgrade a critical case...
    crit = [_item("critical", "f1", ioc_match=["c2_port"])]
    r1 = _mock_report(_ue(crit), {"explanations": {}}, {"case_type": "ransomware"})
    assert "Overall case severity: **CRITICAL**" in r1

    # ...and P5 anomalies on an otherwise-low case do not manufacture a higher
    # headline (the tie-breaker only spans medium<->high).
    low = [_item("low", "f1"), _item("low", "f2")]
    shap = {"explanations": {"f1": {"is_anomaly": True}, "f2": {"is_anomaly": True}}}
    r2 = _mock_report(_ue(low), shap, {"case_type": "unknown"})
    assert "Overall case severity: **LOW**" in r2


# ─────────────────────────────────────────────────────────────
# ML-only callout: P5's genuinely independent flags (5.3)
# ─────────────────────────────────────────────────────────────

def test_ml_only_section_lists_anomalies_without_rule_match():
    # A low-severity item with no IOC match, flagged anomalous by P5, is the kind
    # of independent signal the section exists to surface.
    items = [_item("low", "d1", etype="suspicious_domain", value="oddhost.example")]
    section = _build_ml_only_section(
        items, anomaly_ids={"d1"}, anomaly_lookup={"d1": "statistical outlier"},
        tool_sources={})
    assert "oddhost.example" in section
    assert "**1** artifact" in section
    assert "statistical outlier" in section


def test_ml_only_section_excludes_rule_caught_anomalies():
    # Items the rules already elevated (critical / IOC match) are NOT ML-only,
    # even when also flagged anomalous — they belong in Key Findings, not here.
    items = [
        _item("critical", "c1", ioc_match=["c2_port"]),   # rule-caught
        _item("low", "i1", ioc_match=["wannacry_payload"]),  # low but IOC-matched
    ]
    section = _build_ml_only_section(
        items, anomaly_ids={"c1", "i1"}, anomaly_lookup={"c1": "x", "i1": "y"},
        tool_sources={})
    assert "No artifacts were flagged" in section  # rule-caught items excluded
    assert "artifact c1" not in section and "artifact i1" not in section


def test_ml_only_section_empty_when_no_independent_anomalies():
    items = [_item("high", "h1")]
    section = _build_ml_only_section(
        items, anomaly_ids=set(), anomaly_lookup={}, tool_sources={})
    assert "No artifacts were flagged by anomaly detection" in section


def test_dashboard_summary_mirrors_report_headline_and_mitre():
    # The dashboard sidecar must agree with the report it ships beside: same
    # severity counts, same overall-severity tie-breaker, same MITRE table.
    items = [_item("critical", "f1", ioc_match=["wannacry_dropper"]),
             _item("high", "f2"), _item("medium", "f3"), _item("low", "f4")]
    ue = _ue(items)
    ue["evidence_by_tool"] = {"tsk_fls": items}
    dash = _build_dashboard_summary(ue, {"case_type": "ransomware"}, {"explanations": {}})

    assert dash["summary"]["total_items"] == 4
    assert dash["summary"]["severity_distribution"] == {
        "critical": 1, "high": 1, "medium": 1, "low": 1}
    assert dash["summary"]["critical_count"] == 1
    # critical evidence + zero anomalies still reads critical (5.3 tie-breaker)
    assert dash["summary"]["overall_severity"] == "critical"
    assert [m["id"] for m in dash["mitre"]] == ["T1486", "T1204", "T1547", "T1083"]
    assert dash["by_tool"] == {"tsk_fls": 4}


def test_dashboard_summary_anomaly_breaks_medium_tie():
    # No critical/high evidence, one medium item, and a P5 anomaly → nudged HIGH.
    items = [_item("medium", "m1")]
    shap = {"explanations": {"m1": {"is_anomaly": True, "summary": "unusual"}}}
    dash = _build_dashboard_summary(_ue(items), {"case_type": "malware_infection"}, shap)
    assert dash["summary"]["overall_severity"] == "high"


def test_evidence_techniques_map_flagged_stealer_stages():
    # macOS case gap: stage=credentials / stage=wallets URLs justified T1555/T1657
    # but the static case table couldn't know that. Flagged (critical/high) items
    # now map with the item value as the basis; low-severity items never map.
    items = [
        {"value": "http://94.232.249.129/api/metrics/run?uid=1&stage=credentials",
         "severity": "critical"},
        {"value": "http://94.232.249.129/api/metrics/run?uid=1&stage=wallets",
         "severity": "critical"},
        {"value": "credential note in an unflagged item", "severity": "low"},
    ]
    rows = _evidence_techniques(items)
    assert {tid for tid, _, _, _ in rows} == {"T1555", "T1657"}
    basis = next(b for tid, _, _, b in rows if tid == "T1555")
    assert "stage=credentials" in basis


def test_dashboard_mitre_includes_evidence_derived_techniques():
    items = [_item("critical", "u1", etype="http_request",
                   value="http://x/api/metrics/run?stage=wallets")]
    dash = _build_dashboard_summary(_ue(items), {"case_type": "data_exfiltration"}, {})
    by_id = {row["id"]: row for row in dash["mitre"]}
    assert "T1657" in by_id
    assert "stage=wallets" in by_id["T1657"]["basis"]
    # Static case-table techniques are kept alongside.
    assert "T1041" in by_id


def test_case_tables_cover_every_schema_case_type():
    # D3 regression: keys once mismatched the classifier's case types ("malware" vs
    # "malware_infection") and silently fell through to "unknown" — pin both tables to the enum.
    schema = json.loads(
        (Path(__file__).parent.parent / "src/schemas/case_context_schema.json").read_text())
    case_types = set(schema["properties"]["case_type"]["enum"])
    assert set(MITRE_BY_CASE) == case_types
    assert set(RECOMMENDATIONS_BY_CASE) == case_types


def test_ioc_sources_cell_lists_artifact_id_pointers():
    # Wishlist (IOC drill-down): each surfaced IOC row points at its contributing
    # artifact_ids per tool, capped at 3 with a +N more counter.
    items = [
        {"artifact_id": f"proc_{n}", "source_tool": "volatility3",
         "evidence_type": "process", "value": f"tasksche.exe (PID:{n})",
         "severity": "critical", "ioc_match": ["wannacry_dropper"]}
        for n in (1, 2, 3, 4, 5)
    ]
    out = _build_ioc_report(items, tool_sources={"volatility3": "memory.raw"})
    row = next(l for l in out.splitlines() if "tasksche.exe" in l)
    assert "volatility3 · memory.raw: proc_1, proc_2, proc_3 +2 more" in row


def test_correlated_findings_table_strong_types_and_folded_timestamps():
    # Strong correlations (linked_artifact/same_pid/same_file) render confidence-sorted; the noisy
    # same_timestamp co-occurrences fold to a one-line count instead of flooding the table.
    findings = [
        {"correlation_type": "same_pid", "confidence": 0.87,
         "finding": "PID 596 observed across multiple artifacts",
         "artifacts": ["a", "b", "c"], "source_tools": ["volatility3"]},
        {"correlation_type": "linked_artifact", "confidence": 0.99,
         "finding": "Tool-declared link across 5 artifacts",
         "artifacts": ["a", "b", "c", "d", "e"],
         "source_tools": ["ioc_engine", "volatility3"]},
        {"correlation_type": "same_timestamp", "confidence": 0.96,
         "finding": "Shared timestamp bucket", "artifacts": ["x", "y"],
         "source_tools": ["plaso"]},
    ]
    out = _build_correlated_findings(findings)
    rows = [l for l in out.splitlines() if l.startswith("|") and "%" in l]
    assert "99%" in rows[0] and "87%" in rows[1]   # confidence-sorted, strong types only
    assert "ioc_engine, volatility3" in rows[0]
    assert "Shared timestamp bucket" not in out
    assert "1 same-timestamp co-occurrence(s) omitted" in out


def test_correlated_findings_empty_sentinel():
    assert "_No cross-artifact correlations detected._" in _build_correlated_findings([])
