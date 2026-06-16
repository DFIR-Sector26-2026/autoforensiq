import os
import json
import pytest
from src.utils.audit_log import sha256_file, log_action
from src.wrappers.base_wrapper import BaseWrapper
from src.wrappers.volatility_wrapper import VolatilityWrapper


# ─────────────────────────────────────────────────────────────
# Volatility invocation regression (issue D1 — venv-aware command)
# ─────────────────────────────────────────────────────────────

def test_volatility_command_candidates_prefers_venv_shim(monkeypatch, tmp_path):
    # D1: the pipeline runs as `venv/bin/python autoforensiq.py`, so the venv is
    # not on PATH. The wrapper must try the venv's own `vol` shim (resolved from
    # the running interpreter's directory) FIRST, not a bare `vol` that won't
    # resolve. We fake an interpreter whose sibling `vol` exists.
    import sys as _sys
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_python = fake_bin / "python"
    fake_python.write_text("")
    fake_vol = fake_bin / "vol"
    fake_vol.write_text("")

    monkeypatch.setattr(_sys, "executable", str(fake_python))
    # Run from a dir with no ./venv so only the absolute shim is contributed.
    monkeypatch.chdir(tmp_path)

    candidates = VolatilityWrapper._volatility_command_candidates()

    # The venv shim (absolute) is first and points at the interpreter's sibling.
    assert candidates[0] == [str(fake_vol)]
    # Bare-PATH fallbacks remain available but come after the venv shim.
    assert ["vol"] in candidates
    assert candidates.index([str(fake_vol)]) < candidates.index(["vol"])


def test_volatility_command_candidates_falls_back_without_venv(monkeypatch, tmp_path):
    # With no venv shim next to the interpreter and no ./venv, only the global
    # fallbacks remain — but the list is never empty (the wrapper still tries).
    import sys as _sys
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_python = fake_bin / "python"
    fake_python.write_text("")  # no sibling `vol`

    monkeypatch.setattr(_sys, "executable", str(fake_python))
    monkeypatch.chdir(tmp_path)

    candidates = VolatilityWrapper._volatility_command_candidates()
    assert ["vol"] in candidates
    assert ["python3", "-m", "volatility3"] in candidates
    # No spurious venv shim was added.
    assert all(c not in ([str(fake_bin / "vol")],) for c in candidates)


# ─────────────────────────────────────────────────────────────
# Volatility parser regression tests (issues 3.1 / 3.3)
# ─────────────────────────────────────────────────────────────

def test_parse_malfind():
    wrapper = VolatilityWrapper()

    mock_output = """
Volatility 3 Framework 2.4.0
PID    Process    Start VPN    End VPN    Tag    Protection    CommitCharge    PrivateMemory    FileOutput    Disasm
4    System    0x10000    0x11000    VadS    PAGE_EXECUTE_READWRITE    1    1    -
0x10000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
0x10010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
    """

    items = wrapper._parse("windows.malfind", mock_output)

    assert len(items) == 1
    assert items[0]["severity"] == "critical"
    assert "RWX region and embedded PE/shellcode detected" in items[0]["value"]
    assert items[0]["evidence_type"] == "injected_code"


# Real windows.malfind output from wannacry.raw (csrss/winlogon WannaCry
# injections). The hexdump continuation lines contain no MZ, and several start
# with all-decimal bytes ("08 00 ...") that must NOT be misparsed as PID rows.
WANNACRY_MALFIND = """
Volatility 3 Framework 2.28.0

PID	Process	Start VPN	End VPN	Tag	Protection	CommitCharge	PrivateMemory	File output	Notes	Hexdump	Disasm

596	csrss.exe	0x7f6f0000	0x7f7effff	Vad 	PAGE_EXECUTE_READWRITE	0	0	Disabled	N/A
c8 00 00 00 8b 01 00 00 ff ee ff ee 08 70 00 00 .............p..
08 00 00 00 00 fe 00 00 00 00 10 00 00 20 00 00 ............. ..
00 02 00 00 00 20 00 00 8d 01 00 00 ff ef fd 7f ..... ..........
620	winlogon.exe	0x21400000	0x21403fff	VadS	PAGE_EXECUTE_READWRITE	4	1	Disabled	N/A
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00 00 00 00 28 00 28 00 01 00 00 00 00 00 00 00 ....(.(.........
"""


def test_parse_malfind_core_system_process_kept_high():
    # csrss/winlogon are core system processes that never legitimately host
    # RWX — the genuine WannaCry injections must stay high, not down-ranked.
    wrapper = VolatilityWrapper()
    items = wrapper._parse("windows.malfind", WANNACRY_MALFIND)

    # Exactly two real processes — no phantom rows from hexdump lines.
    assert len(items) == 2
    by_pid = {it["value"].split("PID:")[1].split(")")[0]: it for it in items}
    assert set(by_pid) == {"596", "620"}
    assert by_pid["596"]["severity"] == "high"
    assert by_pid["620"]["severity"] == "high"
    # No fabricated process names like "00" / "02" leaking from the hexdump.
    for it in items:
        assert "csrss.exe" in it["value"] or "winlogon.exe" in it["value"]


def test_parse_malfind_ignores_hexdump_decimal_lines():
    # A bare hexdump (no PID rows) must yield zero items, proving decimal-led
    # byte lines like "08 00 ..." are not treated as PID rows.
    wrapper = VolatilityWrapper()
    hexdump_only = """
08 00 00 00 00 fe 00 00 00 00 10 00 00 20 00 00 ............. ..
00 02 00 00 00 20 00 00 8d 01 00 00 ff ef fd 7f ..... ..........
"""
    assert wrapper._parse("windows.malfind", hexdump_only) == []


def test_parse_malfind_jit_process_downranked():
    # RWX in a JIT-capable process (chrome) with no PE signature is a common
    # benign false positive → down-ranked to medium.
    wrapper = VolatilityWrapper()
    chrome = """
PID	Process	Start VPN	End VPN	Tag	Protection	CommitCharge	PrivateMemory	File output	Notes
1234	chrome.exe	0x1000	0x2000	VadS	PAGE_EXECUTE_READWRITE	4	1	Disabled	N/A
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
"""
    items = wrapper._parse_malfind([l for l in chrome.splitlines() if l.strip()])
    assert len(items) == 1
    assert items[0]["severity"] == "medium"
    assert "down-ranked" in items[0]["value"]


def test_parse_malfind_corroborated_pid_escapes_downrank():
    # The same chrome hit, but corroborated by another IOC on that PID, keeps
    # its original (high) severity.
    wrapper = VolatilityWrapper()
    chrome = """
PID	Process	Start VPN	End VPN	Tag	Protection	CommitCharge	PrivateMemory	File output	Notes
1234	chrome.exe	0x1000	0x2000	VadS	PAGE_EXECUTE_READWRITE	4	1	Disabled	N/A
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
"""
    lines = [l for l in chrome.splitlines() if l.strip()]
    items = wrapper._parse_malfind(lines, corroborated_pids={"1234"})
    assert len(items) == 1
    assert items[0]["severity"] == "high"
    assert "Corroborated by another IOC" in items[0]["value"]


def test_collect_corroborated_pids():
    # Only behavioral IOCs (suspicious cmdline / C2 connection) at high/critical
    # corroborate. A benign low-severity item and a name-based process listing
    # must NOT, or the down-rank would never apply.
    wrapper = VolatilityWrapper()
    items = [
        # suspicious cmdline (PID in artifact_id) -> corroborates 1234
        {"artifact_id": "cmdline_1234", "evidence_type": "commandline",
         "value": "powershell -enc ...", "severity": "high"},
        # C2 connection (PID in value) -> corroborates 620
        {"artifact_id": "netstat_620_x", "evidence_type": "network_connection",
         "value": "TCP 10.0.0.5:49200 -> 9.9.9.9:443 (PID:620)", "severity": "high"},
        # benign low cmdline -> must NOT corroborate
        {"artifact_id": "cmdline_999", "evidence_type": "commandline",
         "value": "C:\\Windows\\explorer.exe", "severity": "low"},
        # pslist name-heuristic high -> must NOT corroborate (excluded type)
        {"artifact_id": "proc_4242_evil_exe", "evidence_type": "process",
         "value": "evil.exe (PID:4242 PPID:1)", "severity": "high"},
    ]
    pids = wrapper._collect_corroborated_pids(items)
    assert pids == {"1234", "620"}


def test_dedupe_items_collapses_repeats_keeping_strongest():
    # Regression for 3.3-F: the string sweep runs over two corpora, so the same
    # IOC can be emitted twice. Identical (type, value) items collapse to one,
    # keeping the highest severity/confidence; distinct items are untouched.
    wrapper = VolatilityWrapper()
    items = [
        {"artifact_id": "dom_1", "evidence_type": "suspicious_domain",
         "value": "evil.com", "severity": "medium", "confidence": 0.80},
        {"artifact_id": "dom_2", "evidence_type": "suspicious_domain",
         "value": "evil.com", "severity": "high", "confidence": 0.95},
        # same value, different type -> kept separate
        {"artifact_id": "reg_1", "evidence_type": "registry_key",
         "value": "evil.com", "severity": "medium", "confidence": 0.88},
        # distinct domain -> kept
        {"artifact_id": "dom_3", "evidence_type": "suspicious_domain",
         "value": "other.net", "severity": "medium", "confidence": 0.80},
    ]
    out = wrapper._dedupe_items(items)

    assert len(out) == 3
    dom = next(i for i in out if i["evidence_type"] == "suspicious_domain"
               and i["value"] == "evil.com")
    assert dom["severity"] == "high"  # strongest of the two duplicates kept
    assert any(i["evidence_type"] == "registry_key" for i in out)
    assert any(i["value"] == "other.net" for i in out)


def test_dedupe_items_keeps_distinct_linked_artifacts():
    # Items whose value omits the PID (process_relation: "parent -> child") must
    # NOT collapse across distinct PID pairs — linked_artifacts is in the key.
    wrapper = VolatilityWrapper()
    items = [
        {"artifact_id": "relation_8_100", "evidence_type": "process_relation",
         "value": "Suspicious parent-child relationship: services.exe -> svchost.exe",
         "severity": "critical", "confidence": 0.92,
         "linked_artifacts": ["proc_8", "proc_100"]},
        {"artifact_id": "relation_8_200", "evidence_type": "process_relation",
         "value": "Suspicious parent-child relationship: services.exe -> svchost.exe",
         "severity": "critical", "confidence": 0.92,
         "linked_artifacts": ["proc_8", "proc_200"]},
    ]
    out = wrapper._dedupe_items(items)
    # Same value/type but different linked PIDs -> both retained.
    assert len(out) == 2


def test_memprocfs_find_pagefile(tmp_path, monkeypatch):
    # Regression for 3.5-A: the API retry must only fire with a real pagefile
    # (used as `-pagefile0 <path>`); a bare `-pagefile` is invalid. _find_pagefile
    # resolves an env override or a sibling pagefile.sys, else None.
    from src.wrappers.memprocfs_wrapper import MemProcFSWrapper
    w = MemProcFSWrapper()

    img = tmp_path / "mem.raw"
    img.write_bytes(b"x")

    monkeypatch.delenv("MEMPROCFS_PAGEFILE", raising=False)
    assert w._find_pagefile(str(img)) is None          # nothing available

    sibling = tmp_path / "pagefile.sys"
    sibling.write_bytes(b"x")
    assert w._find_pagefile(str(img)) == str(sibling)   # sibling found

    override = tmp_path / "explicit.sys"
    override.write_bytes(b"x")
    monkeypatch.setenv("MEMPROCFS_PAGEFILE", str(override))
    assert w._find_pagefile(str(img)) == str(override)  # env var wins


def test_parse_filescan():
    wrapper = VolatilityWrapper()

    mock_output = """
Volatility 3 Framework 2.4.0
0x000000001000    \\Device\\HarddiskVolume2\\Intel\\ivecuqmanpnirkt615\\tasksche.exe
0x000000002000    \\Device\\HarddiskVolume2\\Windows\\System32\\kernel32.dll
0x000000003000    \\Device\\HarddiskVolume2\\Users\\Public\\malware.exe
    """

    items = wrapper._parse("windows.filescan", mock_output)

    assert len(items) == 2
    assert "tasksche.exe" in items[0]["value"]
    assert "malware.exe" in items[1]["value"]


def test_parse_filescan_preserves_spaced_paths():
    # Regression for 3.3-A: filescan paths contain single spaces (the rows are
    # "Offset<TAB>Name"). Splitting on every space truncated the path and lost
    # the staging-path marker, silently dropping the payload.
    wrapper = VolatilityWrapper()

    mock_output = "\n".join([
        "Volatility 3 Framework 2.28.0",
        "Offset\tName",
        "0x1000\t\\Device\\HarddiskVolume2\\Users\\Public\\My Tools\\payload.exe",
        "0x2000\t\\Device\\HarddiskVolume2\\Windows\\System32\\kernel32.dll",
    ])

    items = wrapper._parse("windows.filescan", mock_output)
    values = [it["value"] for it in items]

    # The spaced path is recovered with its marker (\Users\Public\) intact,
    # not truncated to "Tools\payload.exe"; the benign system dll is skipped.
    assert len(items) == 1
    assert "Users\\Public\\My Tools\\payload.exe" in values[0]


def test_parse_filescan_recovers_ransomware_payloads():
    # Regression for 3.3-B: ransomware extensions and named payloads are strong
    # IOCs on their own and must be recovered (as high) regardless of path —
    # the staging-marker gate alone misses .WNCRY victim files in a Pictures
    # folder and named droppers outside staging dirs.
    wrapper = VolatilityWrapper()

    mock_output = "\n".join([
        "Volatility 3 Framework 2.28.0",
        "Offset\tName",
        # encrypted victim file in a non-staging path
        "0x1000\t\\Documents and Settings\\All Users\\Default Pictures\\chess.bmp.WNCRY",
        # named dropper / execution evidence outside any staging marker
        "0x2000\t\\WINDOWS\\Prefetch\\@WANADECRYPTOR@.EXE-06F053F5.pf",
        # benign system binary with no marker — must still be skipped
        "0x3000\t\\Windows\\System32\\kernel32.dll",
    ])

    items = wrapper._parse("windows.filescan", mock_output)
    by_value = {it["value"]: it for it in items}

    assert len(items) == 2
    wncry = next(v for v in by_value if v.endswith(".WNCRY"))
    pf = next(v for v in by_value if v.endswith(".pf"))
    assert by_value[wncry]["severity"] == "high"
    assert by_value[pf]["severity"] == "high"
    assert not any("kernel32.dll" in v for v in by_value)


def test_parse_filescan_random_staging_dir_is_high():
    # Regression for 3.3-C: a non-payload file in a randomly-named staging
    # directory is a malware hallmark and must rank high, not medium — and the
    # detector must not be hard-coded to WannaCry's \Intel\ (it also covers
    # \ProgramData\<random>\). A single generic location marker (\Temp\) stays
    # medium, and benign named subfolders under those parents are not promoted.
    wrapper = VolatilityWrapper()

    mock_output = "\n".join([
        "Volatility 3 Framework 2.28.0",
        "Offset\tName",
        # random staging dir under Intel — high
        "0x1000\t\\Device\\HarddiskVolume2\\Intel\\ivecuqmanpnirkt615\\config.dat",
        # random staging dir under ProgramData (not Intel) — generalised, high
        "0x2000\t\\Device\\HarddiskVolume2\\ProgramData\\ab12cd34ef56gh\\loader.dat",
        # generic temp location, single marker, not random-named — stays medium
        "0x3000\t\\Device\\HarddiskVolume2\\Windows\\Temp\\note.dat",
        # benign NAMED subfolder under a staging parent — flagged by the \intel\
        # marker but NOT promoted to high (it isn't a random-named dir).
        "0x4000\t\\Device\\HarddiskVolume2\\Intel\\Logs\\install.log",
    ])

    items = wrapper._parse("windows.filescan", mock_output)
    by_value = {it["value"]: it for it in items}

    intel = next(v for v in by_value if "ivecuqmanpnirkt615" in v)
    pdata = next(v for v in by_value if "ab12cd34ef56gh" in v)
    temp = next(v for v in by_value if "Temp" in v)
    logs = next(v for v in by_value if "install.log" in v)
    assert by_value[intel]["severity"] == "high"
    assert by_value[pdata]["severity"] == "high"
    assert by_value[temp]["severity"] == "medium"
    assert by_value[logs]["severity"] == "medium"  # named dir not promoted


def test_extract_strings():
    wrapper = VolatilityWrapper()

    corpus = """
    http://www.suspicious-domain-123.com/payload
    random_hex_string_that_looks_like_btc_but_invalid: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    real_onion: exp1234567890abcdef.onion
    HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware
    ignore_this_file.dll
    1234567890abcdef1234567890abcdef1234.exe
    """

    items = wrapper._extract_strings(corpus)

    types = [item["evidence_type"] for item in items]
    values = [item["value"] for item in items]

    assert "suspicious_domain" in types
    assert "www.suspicious-domain-123.com" in values
    assert "exp1234567890abcdef.onion" in values
    assert "registry_key" in types
    assert "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware" in values
    assert "suspicious_crypto" in types
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in values
    assert "ignore_this_file.dll" not in values


def test_extract_strings_domain_tld_recall_and_denoise():
    # Regression for 3.3-E: country-code / .gov / .edu C2 domains must be
    # recovered (the old tiny allowlist dropped them), while filename noise and
    # TLD/extension collisions stay filtered.
    wrapper = VolatilityWrapper()
    corpus = "\n".join([
        "c2-panel.example.de",        # ccTLD domain -> recovered
        "exfil.agency.gov",           # .gov -> recovered
        "login.university.edu",       # .edu -> recovered
        "ntoskrnl.exe",               # not a TLD -> dropped
        "symbols.pdb",                # not a TLD -> dropped
        "l3codecx.ax",                # DirectShow filter (ext==ccTLD) -> dropped
        "main.py",                    # script ext == ccTLD, 2 labels -> dropped
        "panel.c2.pl",                # ambiguous TLD but sub-domained -> recovered
        "t.com",                      # 1-char SLD junk -> dropped
    ])
    domains = {
        it["value"] for it in wrapper._extract_strings(corpus)
        if it["evidence_type"] == "suspicious_domain"
    }

    assert "c2-panel.example.de" in domains
    assert "exfil.agency.gov" in domains
    assert "login.university.edu" in domains
    assert "panel.c2.pl" in domains
    for noise in ("ntoskrnl.exe", "symbols.pdb", "l3codecx.ax", "main.py", "t.com"):
        assert noise not in domains


def test_extract_strings_denoises_prefetch_and_email():
    # Prefetch filenames (.pf) and gibberish .nc must not leak as domains, and
    # the email regex must reject filename/binary noise while keeping real ones.
    wrapper = VolatilityWrapper()
    corpus = "\n".join([
        "TASKDL.EXE-01687054.pf",                  # Prefetch -> not a domain
        "8xm6vk3sh.nc",                            # gibberish ccTLD -> dropped
        "@WANADECRYPTOR@.EXE-06F053F5.pf",         # not an email (empty label)
        "5@0.FF",                                  # not an email (bogus TLD)
        "J.@L.IN",                                 # not an email (1-char SLD)
        "server-certs@thawte.com",                 # real email -> kept
    ])
    items = wrapper._extract_strings(corpus)
    domains = {i["value"] for i in items if i["evidence_type"] == "suspicious_domain"}
    emails = {i["value"] for i in items if i["evidence_type"] == "email_address"}

    assert not any(d.endswith(".pf") for d in domains)
    assert not any(d.endswith(".nc") for d in domains)
    assert "server-certs@thawte.com" in emails
    for junk in ("5@0.ff", "j.@l.in"):
        assert junk not in {e.lower() for e in emails}
    assert not any(".pf" in e.lower() for e in emails)


# ─────────────────────────────────────────────────────────────
# Audit log
# ─────────────────────────────────────────────────────────────

def test_audit_log_creates_entry(tmp_path):
    import src.utils.audit_log as al
    al.AUDIT_LOG_PATH = str(tmp_path / "audit_log.json")
    log_action("test_tool", ["echo", "hi"], [], [], "success")
    with open(al.AUDIT_LOG_PATH) as f:
        entries = json.load(f)
    assert len(entries) == 1
    assert entries[0]["tool"] == "test_tool"
    assert entries[0]["status"] == "success"


def test_sha256_missing_file():
    result = sha256_file("/nonexistent/path/file.dmp")
    assert result == "file_not_found"


# ─────────────────────────────────────────────────────────────
# Base wrapper
# ─────────────────────────────────────────────────────────────

def test_base_wrapper_makes_evidence_item():
    w = BaseWrapper("test_tool")
    item = w.make_evidence_item(
        artifact_id="test_001",
        evidence_type="process",
        value="svchost.exe (PID:1234)",
        severity="high",
        confidence=0.9
    )
    required = ["artifact_id","source_tool","evidence_type",
                "timestamp","value","severity","confidence","linked_artifacts"]
    for field in required:
        assert field in item, f"Missing field: {field}"
    assert item["artifact_id"] == "test_001"
    assert item["source_tool"] == "test_tool"
    assert item["severity"] == "high"


def test_base_wrapper_run_command_success():
    w = BaseWrapper("echo_test")
    stdout, stderr, code = w.run_command(["echo", "hello"])
    assert code == 0
    assert "hello" in stdout


def test_base_wrapper_run_command_timeout():
    w = BaseWrapper("sleep_test")
    stdout, stderr, code = w.run_command(["sleep", "10"], timeout=1)
    assert code == -1


def test_evidence_item_schema_matches():
    import json
    with open("src/schemas/evidence_item.json") as f:
        schema = json.load(f)
    w = BaseWrapper("schema_test")
    item = w.make_evidence_item("id_001","process","test value")
    for key in schema["required"]:
        assert key in item, f"Schema field '{key}' missing from evidence_item output"


# ─────────────────────────────────────────────────────────────
# Evidence-file mapping (multiple artifacts per type)
# ─────────────────────────────────────────────────────────────

def test_map_evidence_files_keeps_multiple_memory_images():
    import autoforensiq
    mapping = autoforensiq._map_evidence_files([
        "/case/memory_dump/wannacry.raw",
        "/case/memory_dump/0zapftis.vmem",
    ])
    # Both images survive instead of the second clobbering the first.
    assert mapping["memory_dump"] == [
        "/case/memory_dump/wannacry.raw",
        "/case/memory_dump/0zapftis.vmem",
    ]


def test_map_evidence_files_recognizes_vmem_by_extension():
    import autoforensiq
    mapping = autoforensiq._map_evidence_files(["/elsewhere/snapshot.vmem"])
    assert mapping.get("memory_dump") == ["/elsewhere/snapshot.vmem"]


def test_map_evidence_files_separates_types():
    import autoforensiq
    mapping = autoforensiq._map_evidence_files([
        "/c/mem.raw", "/c/cap.pcap", "/c/disk.e01",
    ])
    assert mapping["memory_dump"] == ["/c/mem.raw"]
    assert mapping["pcap"] == ["/c/cap.pcap"]
    assert mapping["disk_image"] == ["/c/disk.e01"]
