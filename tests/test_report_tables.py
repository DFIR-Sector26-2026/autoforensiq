"""Tests for report table rendering robustness under multi-tool input.

Covers the Process Tree builder (flat-item PID/PPID hierarchy, prune-to-flagged,
severity + source-file rendering, no cross-type leakage) and the markdown cell
sanitizer used by the IOC / MITRE / Critical Findings tables.
"""

from src.report_generator.report_generator import (
    _build_evidence_coverage,
    _build_ioc_report,
    _build_process_tree,
    _extract_iocs,
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
    # Match badge sits on its own (indented) line within the cell.
    assert "(Suspicious File)<br>&nbsp;**IOC: wannacry_dropper**" in cell


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
