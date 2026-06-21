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
# TSK / fls partitioned-disk regression (issue D2 — mmls offsets)
# ─────────────────────────────────────────────────────────────

# Real mmls output from the Windows Server 2022 E01 (DOS partition table,
# NTFS at sector 2048 & 206848, plus an unknown-type slot).
MMLS_WINSERVER = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)
003:  000:001   0000206848   0103583743   0103376896   NTFS / exFAT (0x07)
004:  000:002   0103583744   0104853503   0001269760   Unknown Type (0x27)
005:  -------   0104853504   0104857599   0000004096   Unallocated
"""

# A single suspicious file in fls mactime-body format (pipe-delimited).
FLS_BODY = "0|/Windows/Temp/evil.exe|0|0|0|0|512|0|0|0|0\n"


def test_parse_fls_skips_directory_nodes():
    # Issue B3: a directory whose path matches SUSPICIOUS_DIRS (mode "d/d...") is
    # not a file artifact — only the files inside it are flagged on their own rows.
    from src.wrappers.tsk_wrapper import TSKWrapper
    body = "\n".join([
        "0|/Windows/Temp|438|d/drwxrwxrwx|0|0|512|0|0|0|0",            # dir -> skipped
        "0|/Windows/Temp/taskdl.exe|453|r/rrwxrwxrwx|0|0|42|0|0|0|0",  # file -> kept
    ])
    values = [i["value"] for i in TSKWrapper()._parse_fls_lines(body)]
    assert any("taskdl.exe" in v for v in values)
    assert not any(v.rstrip().endswith("/Windows/Temp") for v in values)


def test_parse_cmdline_zero_args_stores_process_name():
    # Issue 3.4-r: a process with exactly PID + name and zero arguments must store
    # just the process name as `value`, not the raw "PID<tab>Process" row. The
    # args-bearing rows are unchanged.
    wrapper = VolatilityWrapper()
    lines = [
        "PID\tProcess\tArgs",
        "1940\ttasksche.exe",                              # zero args
        "1024\tsvchost.exe\tC:\\Windows\\svchost.exe -k netsvcs",  # with args
    ]
    by_id = {i["artifact_id"]: i for i in wrapper._parse_cmdline(lines)}
    assert by_id["cmdline_1940"]["value"] == "tasksche.exe"
    assert "1940" not in by_id["cmdline_1940"]["value"]
    assert by_id["cmdline_1024"]["value"] == "C:\\Windows\\svchost.exe -k netsvcs"


def test_tsk_enumerate_fs_offsets_parses_partitions(monkeypatch):
    # D2: mmls must yield the filesystem sector offsets (2048, 206848, ...),
    # skipping the Meta row and unallocated gaps, so fls can run with -o.
    from src.wrappers.tsk_wrapper import TSKWrapper
    w = TSKWrapper()
    monkeypatch.setattr(w, "run_command", lambda *a, **k: (MMLS_WINSERVER, "", 0))

    offsets = w._enumerate_fs_offsets("/case/winserver.E01")
    assert offsets == [2048, 206848, 103583744]


def test_tsk_enumerate_fs_offsets_bare_filesystem(monkeypatch):
    # A bare filesystem has no partition table — mmls exits non-zero, and the
    # enumerator returns [] so the caller falls back to an offset-less fls.
    from src.wrappers.tsk_wrapper import TSKWrapper
    w = TSKWrapper()
    monkeypatch.setattr(w, "run_command", lambda *a, **k: ("", "Cannot determine", 1))

    assert w._enumerate_fs_offsets("/case/ubuntu.E01") == []


def test_tsk_run_fls_partitioned_uses_offset(monkeypatch):
    # On a partitioned image, fls must be invoked WITH `-o <offset>`; a partition
    # that errors (the corrupt/foreign slot) is skipped, not fatal.
    from src.wrappers.tsk_wrapper import TSKWrapper
    w = TSKWrapper()
    calls = []

    def fake(command, *a, **k):
        calls.append(command)
        if command[0] == "mmls":
            return (MMLS_WINSERVER, "", 0)
        # fls: first offset succeeds, the rest error out.
        off = command[command.index("-o") + 1] if "-o" in command else None
        if off == "2048":
            return (FLS_BODY, "", 0)
        return ("", "Error reading image file", 1)

    monkeypatch.setattr(w, "run_command", fake)
    output, items = w._run_fls("/case/winserver.E01")

    fls_calls = [c for c in calls if c and c[0] == "fls"]
    assert all("-o" in c for c in fls_calls)           # every fls used an offset
    assert ["fls", "-o", "2048", "-r", "-m", "/", "/case/winserver.E01"] in calls
    assert len(items) == 1                              # only the readable slot
    assert "evil.exe" in items[0]["value"]


def test_tsk_run_fls_bare_filesystem_no_offset(monkeypatch):
    # On a bare filesystem (no partition table) fls runs WITHOUT `-o`, preserving
    # the prior working behavior for images like the Ubuntu casper E01.
    from src.wrappers.tsk_wrapper import TSKWrapper
    w = TSKWrapper()
    calls = []

    def fake(command, *a, **k):
        calls.append(command)
        if command[0] == "mmls":
            return ("", "Cannot determine", 1)       # no partition table
        return (FLS_BODY, "", 0)

    monkeypatch.setattr(w, "run_command", fake)
    output, items = w._run_fls("/case/ubuntu.E01")

    fls_calls = [c for c in calls if c and c[0] == "fls"]
    assert len(fls_calls) == 1
    assert "-o" not in fls_calls[0]                     # offset-less fallback
    assert len(items) == 1


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


def test_parse_malfind_rx_region_not_labelled_rwx():
    # 3.1-B: PAGE_EXECUTE_READ is an execute-only (RX) region — "page_execute"
    # is a substring of it as well as of PAGE_EXECUTE_READWRITE, so the old
    # has_rwx flag mislabelled an RX region as "RWX region detected". The reason
    # text must now say RX; a real PAGE_EXECUTE_READWRITE still reads as RWX
    # (test_parse_malfind covers the RWX+PE critical case).
    wrapper = VolatilityWrapper()
    rx = """
PID	Process	Start VPN	End VPN	Tag	Protection	CommitCharge	PrivateMemory	File output	Notes
1500	evil.exe	0x1000	0x2000	VadS	PAGE_EXECUTE_READ	4	1	Disabled	N/A
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
"""
    items = wrapper._parse_malfind([l for l in rx.splitlines() if l.strip()])
    assert len(items) == 1
    assert items[0]["severity"] == "high"          # executable private region, not down-ranked
    assert "Executable (RX) region detected" in items[0]["value"]
    assert "RWX" not in items[0]["value"]


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


def test_parse_filescan_json_is_not_matched_as_js():
    # 3.3-D: ".js" is a substring of ".json", so the relevance gate used to
    # count a spurious marker hit for a plain .json file and emit it. A .json in
    # a non-staging path must now be skipped, while a real .js dropper in a
    # staging path still clears the gate.
    wrapper = VolatilityWrapper()
    mock_output = "\n".join([
        "Volatility 3 Framework 2.28.0",
        "Offset\tName",
        "0x1000\t\\Device\\HarddiskVolume2\\Users\\bob\\Documents\\settings.json",
        "0x2000\t\\Device\\HarddiskVolume2\\Windows\\Temp\\dropper.js",
    ])
    items = wrapper._parse("windows.filescan", mock_output)
    values = [it["value"] for it in items]
    assert not any("settings.json" in v for v in values)   # .json no longer mis-hit by ".js"
    assert any("dropper.js" in v for v in values)           # real .js still flagged


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


def test_extract_strings_validates_bech32_wallets():
    # 3.3-G: native SegWit `bc1…` wallets (BIP-173 bech32 / BIP-350 bech32m)
    # were a recall gap — base58check only matched legacy 1.../3... addresses.
    # Valid v0 (P2WPKH/P2WSH) and v1 (Taproot) addresses must now be recovered,
    # with checksum validation rejecting corrupted / wrong-network look-alikes.
    wrapper = VolatilityWrapper()
    corpus = " ".join([
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",                                  # legacy P2PKH still works
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",                          # P2WPKH v0 (bech32)
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",                          # same, all-uppercase
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",      # P2TR v1 (bech32m)
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",                          # bad checksum → reject
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",                          # testnet hrp → reject
    ])
    crypto = {
        i["value"] for i in wrapper._extract_strings(corpus)
        if i["evidence_type"] == "suspicious_crypto"
    }
    assert "1a1zp1ep5qgefi2dmptftl5slmv7divfna" not in crypto  # legacy is case-sensitive...
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in crypto       # ...kept verbatim
    assert "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" in crypto   # v0 recovered
    assert "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0" in crypto  # v1
    # the all-uppercase copy is normalised to lowercase (dedup-friendly)
    assert "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4" not in crypto
    # corrupted checksum and wrong-network addresses are rejected
    assert "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5" not in crypto
    assert not any(v.startswith("tb1") for v in crypto)


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


def test_extract_strings_drops_short_cctld_fragments():
    # Regression for 3.3-J: bare 2-label tokens on a 2-letter ccTLD with a < 4
    # char SLD are string-fragment / public-suffix noise, not endpoints. They
    # must drop when bare but survive when anchored in URL/network grammar, and
    # genuine short domains (3-letter TLD, or SLD >= 4) must be kept.
    wrapper = VolatilityWrapper()
    corpus = "\n".join([
        "ho.gn", "gc.ie", "ht.ht", "exe.pt", "lp.sx",   # fragments -> dropped
        "gob.ve", "asn.au", "pro.ae",                    # public-suffix labels -> dropped
        "ft.com",                                        # 3-letter TLD -> kept
        "google.de",                                     # SLD >= 4 -> kept
        "evil-c2.io",                                    # SLD >= 4 ccTLD -> kept
        "http://ai.bj/login",                            # anchored fragment -> kept
    ])
    domains = {
        it["value"] for it in wrapper._extract_strings(corpus)
        if it["evidence_type"] == "suspicious_domain"
    }
    for frag in ("ho.gn", "gc.ie", "ht.ht", "exe.pt", "lp.sx", "gob.ve", "asn.au", "pro.ae"):
        assert frag not in domains, frag
    for keep in ("ft.com", "google.de", "evil-c2.io", "ai.bj"):
        assert keep in domains, keep


def test_extract_strings_drops_dos_exe_and_digit_fragments():
    # Regression for 3.3-J residuals: DOS/console `.com` executables swept from a
    # memory image (COMMAND.COM, MORE.COM, TREE.COM…) and digit/repeat ccTLD junk
    # ("f0hht.ht", "htaht.ht", "dn5t.aw") are string fragments, not endpoints.
    # They drop when bare but survive when anchored in URL grammar, and real
    # domains that merely look short stay.
    wrapper = VolatilityWrapper()
    corpus = "\n".join([
        "command.com", "format.com", "more.com", "tree.com", "edit.com",  # DOS exes
        "f0hht.ht", "ltchht8ht.ht", "dn5t.aw", "qv0uz.sx",                 # digit junk
        "htaht.ht", "hteht.ht",                                           # repeat-suffix junk
        "evilcorp.com",                                                  # real .com (non-DOS) -> kept
        "taxonomy.ht",                                                   # SLD no digit/repeat -> kept
        "audit.it",                                                      # word ending in ccTLD (one occurrence) -> kept
        "lonely-bare-c2.ru",                                             # hyphenated digit C2 -> kept
        "http://more.com/payload",                                       # anchored -> kept
    ])
    domains = {
        it["value"] for it in wrapper._extract_strings(corpus)
        if it["evidence_type"] == "suspicious_domain"
    }
    for frag in ("command.com", "format.com", "tree.com", "edit.com",
                 "f0hht.ht", "ltchht8ht.ht", "dn5t.aw", "qv0uz.sx",
                 "htaht.ht", "hteht.ht"):
        assert frag not in domains, frag
    for keep in ("evilcorp.com", "taxonomy.ht", "audit.it", "lonely-bare-c2.ru", "more.com"):
        assert keep in domains, keep  # more.com kept because anchored once


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


# ─────────────────────────────────────────────────────────────
# suspicious_domain extraction regression (issue D3 — allowlist + downgrade)
# ─────────────────────────────────────────────────────────────

def test_extract_strings_drops_benign_infrastructure_domains():
    # D3: a memory dump is saturated with OS/browser/CDN/CA hostnames; emitting
    # each as a suspicious_domain floods the evidence set (~22k on win10ctf) and
    # is what made P5 SHAP unscalable. Benign infra must be dropped at source.
    from src.wrappers.volatility_wrapper import VolatilityWrapper
    corpus = "\n".join([
        "www.microsoft.com", "ocsp.digicert.com", "fonts.gstatic.com",
        "ubuntu.com", "settings-win.data.microsoft.com",
    ])
    items = VolatilityWrapper()._extract_strings(corpus)
    domains = [i for i in items if i["evidence_type"] == "suspicious_domain"]
    assert domains == [], f"benign infra leaked: {[d['value'] for d in domains]}"


def test_extract_strings_downgrades_generic_domains_to_low():
    # D3: a bare domain from a string sweep is an indicator, not a finding — it
    # is low severity until the reputation layer (4.2) elevates it. (Was medium.)
    from src.wrappers.volatility_wrapper import VolatilityWrapper
    items = VolatilityWrapper()._extract_strings("beacon to evil-c2-panel.xyz now")
    doms = [i for i in items if i["evidence_type"] == "suspicious_domain"]
    assert len(doms) == 1
    assert doms[0]["value"] == "evil-c2-panel.xyz"
    assert doms[0]["severity"] == "low"


def test_extract_strings_keeps_onion_high():
    # D3 must not weaken genuine indicators: .onion hidden services stay high.
    from src.wrappers.volatility_wrapper import VolatilityWrapper
    items = VolatilityWrapper()._extract_strings(
        "ransom abcdef1234567890abcd.onion site"
    )
    onion = [i for i in items if i["value"].endswith(".onion")]
    assert len(onion) == 1
    assert onion[0]["severity"] == "high"
    assert onion[0]["evidence_type"] == "suspicious_domain"


def test_is_benign_domain_is_host_aware():
    # A lookalike subdomain ("microsoft.com.evil.ru") must NOT be whitelisted.
    from src.wrappers.volatility_wrapper import _is_benign_domain
    assert _is_benign_domain("www.microsoft.com") is True
    assert _is_benign_domain("microsoft.com") is True
    assert _is_benign_domain("microsoft.com.evil.ru") is False
    assert _is_benign_domain("evil-c2-panel.xyz") is False


def test_extract_strings_registry_key_stops_at_pipe():
    # A pipe is not legal in a registry key path; when the string sweep hits one
    # it has run past the real key into adjacent memory ("...\Services|BatteryLife").
    # The captured key must stop at the pipe (clean key, and no stray `|` to
    # corrupt the markdown report table by shifting columns right).
    from src.wrappers.volatility_wrapper import VolatilityWrapper
    corpus = (
        "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services|BatteryLife\n"
        "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\bthserv\n"
    )
    keys = [i["value"] for i in VolatilityWrapper()._extract_strings(corpus)
            if i["evidence_type"] == "registry_key"]
    assert "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services" in keys
    assert "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\bthserv" in keys
    assert all("|" not in k for k in keys), f"pipe leaked into a key: {keys}"


# ─────────────────────────────────────────────────────────────
# Domain confidence-tier regression (issue D3 — URL context, non-destructive)
# ─────────────────────────────────────────────────────────────

def test_extract_strings_anchored_domains_get_higher_confidence():
    # A domain inside URL/network grammar (scheme, Host:, www., :port, path) is a
    # likely real endpoint and ranks above a bare token — but BOTH are kept.
    from src.wrappers.volatility_wrapper import VolatilityWrapper
    corpus = "\n".join([
        "GET http://callback-host.xyz/gate.php",   # scheme + path
        "Host: beacon.example.to",                 # header anchor
        "www.tracked.io here",                     # www. prefix
        "endpoint api.svc.net:8443 ready",         # :port
        "loose prose mentions across.com somewhere",  # bare
    ])
    conf = {i["value"]: i["confidence"] for i in VolatilityWrapper()._extract_strings(corpus)
            if i["evidence_type"] == "suspicious_domain"}
    assert conf.get("callback-host.xyz") == 0.45
    assert conf.get("beacon.example.to") == 0.45
    assert conf.get("www.tracked.io") == 0.45
    assert conf.get("api.svc.net") == 0.45
    assert conf.get("across.com") == 0.20          # bare token demoted, NOT dropped


def test_extract_strings_bare_domain_is_kept_not_dropped():
    # Non-destructive: a bare domain still appears in the evidence set (so the
    # reputation layer can elevate it), just at the lower confidence tier.
    from src.wrappers.volatility_wrapper import VolatilityWrapper
    items = VolatilityWrapper()._extract_strings("config c2 = lonely-bare-c2.ru ;")
    sd = [i for i in items if i["evidence_type"] == "suspicious_domain"]
    assert [i["value"] for i in sd] == ["lonely-bare-c2.ru"]
    assert sd[0]["confidence"] == 0.20
    assert sd[0]["severity"] == "low"


def test_extract_strings_anchored_anywhere_wins():
    # If a domain appears bare once and anchored once, it takes the anchored tier
    # so a real C2 whose first textual hit is bare is not mis-demoted.
    from src.wrappers.volatility_wrapper import VolatilityWrapper
    corpus = "seen bare dual-host.io first, later GET https://dual-host.io/x"
    conf = {i["value"]: i["confidence"] for i in VolatilityWrapper()._extract_strings(corpus)
            if i["evidence_type"] == "suspicious_domain"}
    assert conf.get("dual-host.io") == 0.45


# ─────────────────────────────────────────────────────────────
# Evidence routing for .dmg / .csv (issue D4 — previously dropped)
# ─────────────────────────────────────────────────────────────

def test_map_evidence_files_routes_dmg_to_disk_image():
    import autoforensiq
    mapping = autoforensiq._map_evidence_files(["/case/macbook.dmg"])
    assert mapping.get("disk_image") == ["/case/macbook.dmg"]


def test_map_evidence_files_routes_email_csv_when_named_like_mail():
    import autoforensiq
    mapping = autoforensiq._map_evidence_files(["/case/emails.csv", "/case/spam_corpus.csv"])
    assert mapping.get("email") == ["/case/emails.csv", "/case/spam_corpus.csv"]


def test_map_evidence_files_does_not_route_generic_csv_to_email():
    # A bare data.csv (e.g. a process export) must NOT be keyword-scanned as a
    # phishing archive — it falls through unrouted rather than mis-classified.
    import autoforensiq
    mapping = autoforensiq._map_evidence_files(["/case/process_dump.csv"])
    assert "email" not in mapping


# ─────────────────────────────────────────────────────────────
# Plaso binary resolution (issue D5 — venv-aware, mirrors D1)
# ─────────────────────────────────────────────────────────────

def test_plaso_resolve_cmd_prefers_venv_bin(monkeypatch, tmp_path):
    # D5: plaso installed via venv/bin/pip lands its log2timeline.py in venv/bin,
    # which is NOT on PATH under `venv/bin/python autoforensiq.py`. The resolver
    # must find it via the interpreter's own bin dir, not just shutil.which.
    from src.wrappers import plaso_wrapper
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "python3").write_text("")
    shim = fake_bin / "log2timeline.py"
    shim.write_text("#!/bin/sh\n")
    monkeypatch.setattr(plaso_wrapper.sys, "executable", str(fake_bin / "python3"))
    monkeypatch.setattr(plaso_wrapper.shutil, "which", lambda n: None)
    assert plaso_wrapper._resolve_cmd("log2timeline.py", "log2timeline") == str(shim)


def test_plaso_resolve_cmd_falls_back_to_path_then_bare(monkeypatch, tmp_path):
    from src.wrappers import plaso_wrapper
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    monkeypatch.setattr(plaso_wrapper.sys, "executable", str(fake_bin / "python3"))
    # Not in venv/bin and not on PATH -> bare fallback name (fails loudly later).
    monkeypatch.setattr(plaso_wrapper.shutil, "which", lambda n: None)
    assert plaso_wrapper._resolve_cmd("log2timeline.py", "log2timeline") == "log2timeline"
    # On PATH -> use the PATH hit.
    monkeypatch.setattr(plaso_wrapper.shutil, "which",
                        lambda n: "/usr/bin/log2timeline.py" if n == "log2timeline.py" else None)
    assert plaso_wrapper._resolve_cmd("log2timeline.py", "log2timeline") == "/usr/bin/log2timeline.py"
