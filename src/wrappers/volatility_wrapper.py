import os
import re
import sys
import json
import hashlib
import tempfile
import subprocess
from pathlib import Path

from .base_wrapper import BaseWrapper, stable_artifact_id
from src.utils.audit_log import log_action
from src.data.threat_intel import (
    c2_port_severity, RANSOM_EXTENSIONS, EXECUTABLE_EXTENSIONS, SEVERITY_ORDER, is_benign_domain)

PLUGINS = [
    "windows.pslist",
    "windows.pstree",
    "windows.cmdline",
    "windows.netstat",
    "windows.malfind",
    "windows.filescan",
    "windows.dlllist"
]
# windows.strings is NOT here: it needs --strings-file, so it runs separately in run() with a
# generated strings file (in the loop it just fails slowly).


class ProcessNode:

    def __init__(self, pid, ppid, name):

        self.pid = pid
        self.ppid = ppid
        self.name = name
        self.cmdline = ""
        self.children = []
        self.suspicious = False
        self.reasons = []


def summarise_tree(node, depth=0, max_depth=5):
    """Human-readable indented process-tree summary used as the evidence value."""

    if not node:
        return ""
    if depth > max_depth:
        return ""

    lines = [f"{'  ' * depth}{node.name} (PID:{node.pid})"]
    for child in node.children:
        child_text = summarise_tree(child, depth + 1, max_depth)
        if child_text:
            lines.append(child_text)

    return "\n".join(lines)


def tree_to_dict(node, depth=0, max_depth=5):
    """Structured process-tree for downstream consumers (issue 4.5): the same lineage as
    summarise_tree but as nested dicts instead of indented text, so the report/UI doesn't have to
    re-parse the text blob."""

    if not node or depth > max_depth:
        return None

    return {
        "pid": node.pid,
        "ppid": node.ppid,
        "name": node.name,
        "suspicious": node.suspicious,
        "children": [
            child for child in (
                tree_to_dict(c, depth + 1, max_depth) for c in node.children
            ) if child is not None
        ],
    }


def tree_lineage(node, max_depth=5):
    """Concise one-line root→leaf lineage(s), e.g. `explorer.exe(1636) → tasksche.exe(1940) →
    @WanaDecryptor@(740)` (issue 4.5). One line per leaf path; a single linear chain collapses to
    one line."""

    paths = []

    def _walk(n, prefix, depth):
        label = prefix + [f"{n.name}({n.pid})"]
        if depth >= max_depth or not n.children:
            paths.append(" → ".join(label))
            return
        for child in n.children:
            _walk(child, label, depth + 1)

    if node:
        _walk(node, [], 0)

    return "\n".join(paths)


# Despite the name, only consumed by _parse_pslist's OWN-NAME severity (lineage is
# SUSPICIOUS_RELATIONSHIPS below). cmd.exe/powershell.exe deliberately absent (B-5/B-9a): bare
# LOLBin names FP; context rules still score their misuse.
SUSPICIOUS_PARENTS = [
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe"
]

SUSPICIOUS_RELATIONSHIPS = {
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("powershell.exe", "rundll32.exe"),
    ("mshta.exe", "cmd.exe"),
    ("wscript.exe", "powershell.exe"),
    ("explorer.exe", "powershell.exe"),
}

SUSPICIOUS_CMDLINE_KEYWORDS = [
    "-enc",
    "-encodedcommand",
    "invoke-",
    "downloadstring",
    "iex",
    "bypass",
    "hidden",
    "frombase64"
]

# Processes where RWX is commonly benign (browser/JIT/.NET hosts
JIT_ALLOWLIST = {
    "explorer.exe",
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "iexplore.exe",
    "opera.exe",
    "brave.exe",
    "svchost.exe",
    "wmiprvse.exe",
    "dllhost.exe",
    "msmpeng.exe",
}

# URL/network-context anchors — THE GATE for string-swept domains (D3): only domains sitting in URL
# grammar are emitted; bare tokens are noise (a real C2 still arrives via its actual connection/DNS
# artifact). Grammar-fixed, not image-tuned.
_URL_SCHEME_RE = re.compile(r"(?:https?|ftp|wss?)://$", re.IGNORECASE)
_HEADER_ANCHORS = ("host:", "referer:", "referrer:", "location:", "origin:",
                   "url=", "uri=")


def _has_network_context(corpus: str, start: int, end: int, value: str) -> bool:
    """True when the domain at corpus[start:end] sits inside URL/network grammar: a www. prefix,
    a preceding scheme (`http://`) or protocol-relative `//`, an HTTP header anchor (`Host:`,
    `Referer:`, …), or a trailing path/port/query."""
    if value.startswith("www."):
        return True
    pre = corpus[max(0, start - 10):start]
    if _URL_SCHEME_RE.search(pre) or pre.endswith("//"):
        return True
    pre_window = corpus[max(0, start - 16):start].lower()
    if any(anchor in pre_window for anchor in _HEADER_ANCHORS):
        return True
    suffix = corpus[end:end + 2]
    if suffix[:1] in ("/", "?"):
        return True
    if suffix[:1] == ":" and len(suffix) > 1 and suffix[1].isdigit():
        return True
    return False


# ── _extract_strings tables and validators, module-level: the method runs up to 3× per image over
# multi-hundred-MB corpora, so nothing below may be rebuilt per call. ──

# Final label must be a registered TLD — filters filename noise while keeping ccTLD/.gov/.edu C2
# a tiny allowlist would drop.
_VALID_TLDS = {
    # common / generic + frequently-abused gTLDs
    "com", "net", "org", "info", "biz", "gov", "edu", "mil", "int",
    "name", "pro", "mobi", "asia", "xyz", "top", "site", "online",
    "club", "shop", "app", "dev", "io", "co", "me", "tv", "cc", "ws",
    "su", "onion", "tk", "ml", "ga", "cf", "gq", "work", "click",
    "link", "live", "icu", "fun", "buzz", "host", "space", "website",
    "press", "party", "stream", "download", "loan", "review", "date",
    "trade", "racing", "win", "bid", "faith", "cricket", "men", "pw",
    # ISO 3166 country-code TLDs
    "ac", "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "ar", "at",
    "au", "aw", "ax", "az", "ba", "bb", "bd", "be", "bf", "bg", "bh",
    "bi", "bj", "bm", "bn", "bo", "br", "bs", "bt", "bw", "by", "bz",
    "ca", "cd", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "cr", "cu",
    "cv", "cw", "cx", "cy", "cz", "de", "dj", "dk", "dm", "do", "dz",
    "ec", "ee", "eg", "es", "et", "eu", "fi", "fj", "fk", "fm", "fo",
    "fr", "gb", "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn",
    "gp", "gr", "gt", "gu", "gw", "gy", "hk", "hn", "hr", "ht", "hu",
    "id", "ie", "il", "im", "in", "iq", "ir", "is", "it", "je", "jm",
    "jo", "jp", "ke", "kg", "kh", "ki", "kn", "kp", "kr", "kw", "ky",
    "kz", "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv",
    "ly", "ma", "mc", "mg", "mk", "mm", "mn", "mo", "mp", "mq", "mr",
    "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz", "na", "nc", "ne",
    "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om", "pa",
    "pe", "pg", "ph", "pk", "pn", "pr", "ps", "pt", "qa", "re",
    "ro", "rw", "sa", "sb", "sc", "sd", "se", "sg", "si", "sk", "sl",
    "sm", "sn", "sr", "ss", "st", "sv", "sx", "sy", "sz", "tc", "td",
    "tg", "th", "tj", "tl", "tn", "tr", "tt", "tw", "tz", "ua", "ug",
    "uk", "us", "uy", "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu",
    "wf", "ye", "yt", "za", "zm", "zw", "ru", "to",
    # ccTLDs that also double as script/binary extensions (kept valid here; the
    # ambiguous-TLD guard requires a sub-domain).
    "pl", "py", "pm", "sh", "so", "rs", "md", "ax",
}

# ccTLDs that double as code extensions (main.py, lib.so) — need a sub-domain (3+ labels) to
# count as a domain. (.pf is dropped from _VALID_TLDS entirely: Prefetch extension.)
_AMBIGUOUS_CODE_TLDS = {"py", "pl", "sh", "so", "rs", "md", "pm", "ax", "nc"}

_ONION_RE = re.compile(r"[a-z0-9]{16,56}\.onion", re.IGNORECASE)
_BTC_BASE58_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_BTC_BECH32_RE = re.compile(r"\bbc1[ac-hj-np-z02-9]{8,87}\b", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}")

# `|` is illegal in a registry path — it means the sweep ran into adjacent memory; stopping there
# also keeps stray pipes from corrupting the markdown report table.
_REGISTRY_RES = [re.compile(p, re.IGNORECASE) for p in (
    r"(?:HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKCR|HKEY_CLASSES_ROOT|HKU|HKEY_USERS)\\[^\s\"'|]+",
    r"\\Registry\\Machine\\[^\s\"'|]+",
    r"\\Registry\\User\\[^\s\"'|]+",
)]

_DOMAIN_RE = re.compile(
    r"(?<![@\\])\b(?:[a-z0-9-]{1,63}\.)+(?P<tld>[a-z]{2,24})\b",
    re.IGNORECASE,
)


def _base58_decode(value: str):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    decoded = bytearray()
    num = 0

    for char in value:
        index = alphabet.find(char)
        if index == -1:
            return None
        num = num * 58 + index

    while num > 0:
        num, remainder = divmod(num, 256)
        decoded.insert(0, remainder)

    leading_zeros = len(value) - len(value.lstrip("1"))
    return bytearray(b"\x00" * leading_zeros) + decoded


def _is_valid_btc_address(value: str) -> bool:
    if not re.fullmatch(r"^[13][1-9A-HJ-NP-Za-km-z]{25,34}$", value):
        return False

    decoded = _base58_decode(value)
    if not decoded or len(decoded) < 5:
        return False

    payload = bytes(decoded[:-4])
    checksum = bytes(decoded[-4:])
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    return digest == checksum and len(payload) == 21


# Native SegWit `bc1…` validation (BIP-173/350), which base58check can't cover: witness v0 uses
# the bech32 checksum constant (1); v1+ (Taproot) uses bech32m (0x2bc830a3).
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits, tobits):
    # 5-bit groups -> 8-bit bytes, no padding (witness-program decode).
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def _is_valid_bech32_btc_address(value: str) -> bool:
    # BIP-173 forbids mixed case; accept all-lower or all-upper.
    if value != value.lower() and value != value.upper():
        return False
    v = value.lower()
    if not (14 <= len(v) <= 90):
        return False

    pos = v.rfind("1")
    if pos < 1 or pos + 7 > len(v):
        return False

    hrp, data_part = v[:pos], v[pos + 1:]
    if hrp != "bc":                      # Bitcoin mainnet only
        return False

    data = []
    for c in data_part:
        d = _BECH32_CHARSET.find(c)
        if d == -1:
            return False
        data.append(d)

    wit_ver = data[0]
    checksum = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if wit_ver == 0:
        if checksum != 1:                # bech32
            return False
    elif 1 <= wit_ver <= 16:
        if checksum != 0x2bc830a3:        # bech32m
            return False
    else:
        return False

    program = _convertbits(data[1:-6], 5, 8)
    if program is None or not (2 <= len(program) <= 40):
        return False
    # v0 programs are exactly 20 (P2WPKH) or 32 (P2WSH) bytes.
    if wit_ver == 0 and len(program) not in (20, 32):
        return False
    return True


class VolatilityWrapper(BaseWrapper):

    consumes = "memory_dump"

    def __init__(self):

        super().__init__("volatility3")

    @staticmethod
    def _volatility_command_candidates() -> list:
        """Ordered ways to invoke Volatility3, most-specific first: the venv's own `vol` (venv
        isn't on PATH under `venv/bin/python autoforensiq.py`, D1), then the CWD-relative path
        pre-flight probes, then PATH."""
        candidates = []

        venv_vol = os.path.join(os.path.dirname(sys.executable), "vol")
        if os.path.exists(venv_vol):
            candidates.append([venv_vol])

        # CWD-relative shim — the exact path the pre-flight check probes.
        cwd_vol = os.path.join("venv", "bin", "vol")
        if os.path.exists(cwd_vol):
            candidates.append([os.path.join(".", "venv", "bin", "vol")])

        # Fallbacks for installs where Volatility is globally available.
        candidates.append(["vol"])
        candidates.append(["python3", "-m", "volatility3"])

        return candidates

    def run(self, image_path: str) -> list:
        if not Path(image_path).exists():
            print(f"  [ERROR] Memory image not found: {image_path}")
            return []

        all_items = []
        volatility_commands = self._volatility_command_candidates()
        working_command = None

        for base_cmd in volatility_commands:
            try_cmd = base_cmd + ["-h"]
            stdout, stderr, code = self.run_command(try_cmd, timeout=15)
            if code == 0:
                working_command = base_cmd
                break

        if not working_command:
            print("  [ERROR] Could not locate working Volatility3 installation")
            return []

        print(f"  [VOL] Using command: {' '.join(working_command)}")

        combined_output = ""

        # malfind is parsed after the loop so cross-plugin corroboration is available (see below).
        # Stash its raw output here when encountered.
        malfind_output = None

        for plugin in PLUGINS:
            print(f"\n  [VOL] Running {plugin}...")
            command = working_command + ["-f", image_path, plugin]
            stdout, stderr, code = self.run_command(
                command,
                input_files=[image_path],
                timeout=180
            )

            # Per-plugin return code + 1000-char stdout/stderr dumps are noisy on a normal run (the
            # GUI streams all of it), so gate them behind VOL_DEBUG — same opt-in style as
            # VOL_ENABLE_DUMPFILES below.
            if os.getenv("VOL_DEBUG", "").lower() in {"1", "true", "yes"}:
                print(f"\n  [DEBUG] Return code: {code}")
                if stderr.strip():
                    print(f"\n  [DEBUG] STDERR:\n{stderr[:1000]}")
                if stdout.strip():
                    print(f"\n  [DEBUG] STDOUT:\n{stdout[:1000]}")

            # keep a combined corpus for regex-based extraction
            if stdout:
                combined_output += "\n" + stdout

            if code != 0:
                print(f"  [SKIP] {plugin} failed")
                continue

            if not stdout.strip():
                print(f"  [SKIP] {plugin} produced empty output")
                continue

            if plugin == "windows.malfind":
                # Defer parsing until after the loop so behavioral IOCs from the other plugins
                # (suspicious cmdline / C2 connection) can be used to corroborate — and thus not
                # down-rank — JIT-process hits.
                malfind_output = stdout
                continue

            try:
                items = self._parse(plugin, stdout)
            except Exception as exc:
                print(f"  [SKIP] {plugin} parse failed: {exc}")
                continue

            print(f"  [VOL] {plugin} → {len(items)} evidence items")
            all_items.extend(items)

        # Parse the deferred malfind output now that the other plugins' evidence is available for
        # cross-IOC corroboration.
        if malfind_output is not None:
            corroborated_pids = self._collect_corroborated_pids(all_items)
            try:
                malfind_lines = [
                    l for l in malfind_output.strip().splitlines() if l.strip()
                ]
                items = self._parse_malfind(
                    malfind_lines,
                    corroborated_pids=corroborated_pids,
                )
                if corroborated_pids:
                    print(f"  [VOL] malfind corroborated PIDs: {sorted(corroborated_pids)}")
                print(f"  [VOL] windows.malfind → {len(items)} evidence items")
                all_items.extend(items)
            except Exception as exc:
                print(f"  [SKIP] windows.malfind parse failed: {exc}")

        # Optional plugin: dumpfiles can write many files to CWD when unfiltered, so keep it opt-in
        # for controlled investigations.
        if os.getenv("VOL_ENABLE_DUMPFILES", "").lower() in {"1", "true", "yes"}:
            plugin = "windows.dumpfiles"
            print(f"\n  [VOL] Running {plugin} (opt-in)...")
            command = working_command + ["-f", image_path, plugin]
            stdout, stderr, code = self.run_command(
                command,
                input_files=[image_path],
                timeout=240
            )
            if code == 0 and stdout.strip():
                try:
                    items = self._parse(plugin, stdout)
                    print(f"  [VOL] {plugin} -> {len(items)} evidence items")
                    all_items.extend(items)
                except Exception as exc:
                    print(f"  [SKIP] {plugin} parse failed: {exc}")

        # Optional plugin: yarascan requires explicit rules/file.
        yara_rules = os.getenv("VOL_YARA_RULES", "").strip()
        yara_file = os.getenv("VOL_YARA_FILE", "").strip()
        if yara_rules or yara_file:
            plugin = "windows.vadyarascan"
            print(f"\n  [VOL] Running {plugin} (configured)...")
            command = working_command + ["-f", image_path, plugin]
            can_run_yara = False
            if yara_file:
                if not Path(yara_file).exists():
                    print(f"  [SKIP] YARA file not found: {yara_file}")
                else:
                    command += ["--yara-file", yara_file]
                    can_run_yara = True
            else:
                command += ["--yara-rules", yara_rules]
                can_run_yara = True

            if can_run_yara:
                stdout, stderr, code = self.run_command(
                    command,
                    input_files=[image_path],
                    timeout=240
                )
                if code == 0 and stdout.strip():
                    try:
                        items = self._parse(plugin, stdout)
                        print(f"  [VOL] {plugin} -> {len(items)} evidence items")
                        all_items.extend(items)
                    except Exception as exc:
                        print(f"  [SKIP] {plugin} parse failed: {exc}")

        # Feed windows.strings with a real strings file generated from the image when possible. This
        # avoids volatility's internal strings collector returning empty results when no strings
        # source is set.
        strings_path = None
        try:
            strings_path = self._build_strings_file(image_path)
            if strings_path and Path(strings_path).exists():
                plugin = "windows.strings"
                print(f"\n  [VOL] Running {plugin} with generated strings file...")
                command = working_command + ["-f", image_path, plugin, "--strings-file", strings_path]
                stdout, stderr, code = self.run_command(
                    command,
                    input_files=[image_path, strings_path],
                    timeout=240,
                )
                if code == 0 and stdout.strip():
                    try:
                        items = self._parse(plugin, stdout)
                        print(f"  [VOL] {plugin} -> {len(items)} evidence items")
                        all_items.extend(items)
                    except Exception as exc:
                        print(f"  [SKIP] {plugin} parse failed: {exc}")

                # windows.strings only emits process-attributed strings; IOCs in unattributed
                # pool/heap never reach it. Sweep the raw strings file too — the final de-dupe
                # collapses any overlap.
                try:
                    with open(strings_path, "r", errors="ignore") as sf:
                        raw_strings = sf.read()
                    extracted = self._extract_strings(raw_strings)
                    if extracted:
                        print(
                            f"  [VOL] Extracted {len(extracted)} IOCs "
                            f"from raw strings file"
                        )
                        all_items.extend(extracted)
                except Exception as exc:
                    print(f"  [VOL] raw strings extraction failed: {exc}")
        finally:
            if strings_path is not None:
                try:
                    os.unlink(strings_path)
                except Exception:
                    pass

        # Run a lightweight string/IOC extraction over all plugin output
        try:
            extracted = self._extract_strings(combined_output)
            if extracted:
                print(f"  [VOL] Extracted {len(extracted)} string IOCs")
                all_items.extend(extracted)
        except Exception as exc:
            print(f"  [VOL] string extraction failed: {exc}")

        # The sweep runs over combined_output AND the strings file, so the same IOC can be emitted
        # twice — collapse, keeping the strongest.
        before = len(all_items)
        all_items = self._dedupe_items(all_items)
        if len(all_items) != before:
            print(f"  [VOL] de-duplicated {before - len(all_items)} repeat items")

        return all_items

    def _dedupe_items(self, items: list) -> list:
        """Collapse items sharing (evidence_type, value, linked_artifacts), keeping highest
        severity then confidence, first-seen order (3.3-F). linked_artifacts in the key keeps
        PID-less values (process_relation) from merging across distinct PID pairs."""

        best = {}
        order = []

        for it in items:
            key = (
                it.get("evidence_type"),
                str(it.get("value", "")).strip().lower(),
                tuple(it.get("linked_artifacts") or []),
            )

            if key not in best:
                best[key] = it
                order.append(key)
                continue

            cur = best[key]
            challenger = (
                SEVERITY_ORDER.get(it.get("severity"), 0),
                it.get("confidence", 0) or 0,
            )
            incumbent = (
                SEVERITY_ORDER.get(cur.get("severity"), 0),
                cur.get("confidence", 0) or 0,
            )
            if challenger > incumbent:
                best[key] = it

        return [best[k] for k in order]

    def _parse(self, plugin: str, output: str) -> list:
        lines = [
            l for l in output.strip().splitlines()
            if l.strip()
        ]

        # Plugin -> parser lookup (issue D6), replacing the if/elif chain. The three yarascan plugin
        # names share one parser; an unknown plugin yields no items.
        dispatch = {
            "windows.pslist": self._parse_pslist,
            "windows.pstree": self._parse_pstree,
            "windows.cmdline": self._parse_cmdline,
            "windows.netstat": self._parse_netstat,
            "windows.malfind": self._parse_malfind,
            "windows.filescan": self._parse_filescan,
            "windows.dumpfiles": self._parse_dumpfiles,
            "windows.vadyarascan": self._parse_yarascan,
            "yarascan.YaraScan": self._parse_yarascan,
            "windows.yarascan": self._parse_yarascan,
            "windows.strings": self._parse_strings,
            "windows.dlllist": self._parse_dlllist,
        }

        parser = dispatch.get(plugin)
        return parser(lines) if parser else []

    def _build_strings_file(self, image_path: str):
        """Run system `strings` over the image into a tempfile for windows.strings
        --strings-file. Returns the path, or None on failure; caller unlinks."""
        # Streamed straight to the file — run_command would hold the whole-image dump in RAM and
        # then copy it (review-1 4.2); audit logging is done inline instead.
        tmp = tempfile.NamedTemporaryFile(delete=False, prefix="af_strings_", suffix=".txt", mode="w", encoding="utf-8")
        command = ["strings", "-a", "-n", "8", image_path]
        print(f"  [RUNNING] {' '.join(command)}")
        try:
            result = subprocess.run(command, stdout=tmp, stderr=subprocess.PIPE, text=True, timeout=120)
            tmp.close()
            status = "success" if result.returncode == 0 else "failed"
            log_action(self.tool_name, command, [image_path], [], status,
                       result.stderr[:500] if result.stderr else "")
            if result.returncode == 0 and os.path.getsize(tmp.name) > 0:
                return tmp.name
        except subprocess.TimeoutExpired:
            log_action(self.tool_name, command, [image_path], [], "timeout")
        except Exception as e:
            log_action(self.tool_name, command, [image_path], [], "error", str(e))
        try:
            tmp.close()
            os.unlink(tmp.name)
        except Exception:
            pass
        return None

    def _parse_pslist(self, lines: list) -> list:
        items = []

        for line in lines:
            if (
                "Volatility 3 Framework" in line or
                ("PID" in line and "PPID" in line)
            ):
                continue

            parts = line.split()
            if len(parts) < 3:
                continue

            try:
                pid = parts[0]
                ppid = parts[1]
                name = parts[2]
                safe_name = name.lower().replace('.', '_').replace('@', '')
                severity = "high" if name.lower() in SUSPICIOUS_PARENTS else "low"
                items.append(
                    self.make_evidence_item(
                        artifact_id=f"proc_{pid}_{safe_name}",
                        evidence_type="process",
                        value=f"{name} (PID:{pid} PPID:{ppid})",
                        severity=severity,
                        confidence=0.75
                    )
                )
            except Exception:
                continue

        return items

    def _parse_pstree(self, lines: list) -> list:
        items = []
        processes = {}

        for line in lines:
            if (
                "Volatility 3 Framework" in line or
                ("PID" in line and "PPID" in line)
            ):
                continue

            clean = line.replace("*", "").strip()
            parts = clean.split()
            if len(parts) < 3:
                continue

            try:
                pid = int(parts[0])
                ppid = int(parts[1])
                name = parts[2]
                node = ProcessNode(pid, ppid, name)
                processes[pid] = node
            except Exception:
                continue

        relation_items = []

        for proc in processes.values():
            if proc.ppid in processes:
                parent = processes[proc.ppid]
                parent.children.append(proc)
                pair = (parent.name.lower(), proc.name.lower())

                if pair in SUSPICIOUS_RELATIONSHIPS:
                    proc.suspicious = True
                    proc.reasons.append(
                        f"Suspicious lineage: {parent.name} -> {proc.name}"
                    )
                    relation_items.append(
                        self.make_evidence_item(
                            artifact_id=f"relation_{parent.pid}_{proc.pid}",
                            evidence_type="process_relation",
                            value=(
                                f"Suspicious parent-child relationship: "
                                f"{parent.name} -> {proc.name}"
                            ),
                            severity="critical",
                            confidence=0.92,
                            linked_artifacts=[
                                f"proc_{parent.pid}",
                                f"proc_{proc.pid}"
                            ]
                        )
                    )

        roots = []
        for proc in processes.values():
            if proc.ppid not in processes:
                roots.append(proc)

        tree_items = []
        for root in roots:
            tree_item = self.make_evidence_item(
                artifact_id=f"process_tree_{root.pid}",
                evidence_type="process_tree",
                value=summarise_tree(root),
                severity="medium",
                confidence=0.95,
                linked_artifacts=[]
            )
            # 4.5: expose the tree as structured data and a one-line lineage so downstream consumers
            # don't have to re-parse the indented `value`.
            tree_item["process_tree_json"] = tree_to_dict(root)
            tree_item["lineage"] = tree_lineage(root)
            tree_items.append(tree_item)

        items.extend(tree_items)
        items.extend(relation_items)

        return items
    def _parse_cmdline(self, lines: list) -> list:

        items = []

        for line in lines:

            line = line.strip()

            if (
                not line or
                "Volatility 3 Framework" in line or
                ("PID" in line and "Process" in line)
            ):
                continue

            lower = line.lower()

            if (
                "unsatisfied requirement" in lower or
                "unable to validate" in lower or
                "traceback" in lower
            ):
                items.append(
                    self.make_evidence_item(
                        artifact_id=f"cmdline_warning_{len(items)}",
                        evidence_type="parser_warning",
                        value=line,
                        severity="medium",
                        confidence=1.0
                    )
                )
                continue

            parts = line.split()

            pid = parts[0] if len(parts) > 0 else "unknown"

            if len(parts) == 1:
                items.append(
                    self.make_evidence_item(
                        artifact_id=f"cmdline_empty_{pid}",
                        evidence_type="commandline_missing",
                        value=line,
                        severity="low",
                        confidence=1.0
                    )
                )
                continue

            process_name = parts[1]

            if len(parts) > 2:
                cmdline = line.split(process_name, 1)[1].strip()
            else:
                # PID + name, zero args (3.4-r): store the process name, not the raw row, so the
                # value matches the args-bearing case.
                cmdline = process_name

            severity = (
                "high"
                if any(
                    kw in lower
                    for kw in SUSPICIOUS_CMDLINE_KEYWORDS
                )
                else "low"
            )

            confidence = (
                0.90
                if severity == "high"
                else 0.60
            )

            items.append(
                self.make_evidence_item(
                    artifact_id=f"cmdline_{pid}",
                    evidence_type="commandline",
                    value=cmdline,
                    severity=severity,
                    confidence=confidence
                )
            )

        return items


    def _parse_netstat(self, lines: list) -> list:

        items = []

        for line in lines:

            line = line.strip()

            if (
                not line or
                "Volatility 3 Framework" in line or
                "Offset" in line
            ):
                continue

            parts = line.split(maxsplit=9)

            if len(parts) < 8:
                continue

            try:

                proto = parts[1]
                local_addr = parts[2]
                local_port = parts[3]
                foreign_addr = parts[4]
                foreign_port = parts[5]
                pid = parts[7]

                local_p = (
                    int(local_port)
                    if str(local_port).isdigit()
                    else 0
                )
                
                remote_p = (
                    int(foreign_port)
                    if str(foreign_port).isdigit()
                    else 0
                )

                # Tiered C2-port severity (D1): high-confidence → high, watch → medium, neither →
                # low; stronger of local/remote wins.
                port_sevs = [
                    s for s in (c2_port_severity(local_p), c2_port_severity(remote_p))
                    if s
                ]
                if "high" in port_sevs:
                    severity = "high"
                elif "medium" in port_sevs:
                    severity = "medium"
                else:
                    severity = "low"

                items.append(
                    self.make_evidence_item(
                        artifact_id=(
                            f"netstat_"
                            f"{pid}_"
                            f"{local_addr.replace('.', '_')}_"
                            f"{local_port}_"
                            f"{foreign_addr.replace('.', '_')}_"
                            f"{foreign_port}"
                        ),
                        evidence_type="network_connection",
                        value=(
                            f"{proto} "
                            f"{local_addr}:{local_port} -> "
                            f"{foreign_addr}:{foreign_port} "
                            f"(PID:{pid})"
                        ),
                        severity=severity,
                        confidence=0.75
                    )
                )

            except Exception:
                continue

        return items
    def _collect_corroborated_pids(self, items: list) -> set:
        """PIDs flagged by a *behavioral* IOC (high/critical commandline, network connection, or
        suspicious lineage) — the "corroborated by another IOC" escape from the malfind JIT
        down-rank. Name-based heuristics deliberately excluded to keep corroboration independent."""
        corroborating_types = {"commandline", "network_connection", "process_relation"}
        pids = set()

        for it in items:
            if it.get("evidence_type") not in corroborating_types:
                continue
            if it.get("severity") not in {"high", "critical"}:
                continue

            aid = str(it.get("artifact_id", ""))
            m = re.match(r"(?:cmdline|netstat)_(\d+)", aid)
            if m:
                pids.add(m.group(1))

            # Suspicious lineage implicates both endpoints: the parent (likely injected spawner)
            # and the child (payload).
            m = re.match(r"relation_(\d+)_(\d+)", aid)
            if m:
                pids.update(m.groups())

            for m in re.finditer(r"pid[:=]?\s*(\d+)", str(it.get("value", "")), re.IGNORECASE):
                pids.add(m.group(1))

        return pids

    def _parse_malfind(self, lines: list, corroborated_pids: set = None) -> list:

        items = []

        # PIDs another IOC flagged — the escape from the JIT down-rank below.
        corroborated_pids = {str(p) for p in (corroborated_pids or set())}

        grouped_regions = {}
        current_pid = None

        def _has_pe_signature(text: str) -> bool:

            lowered = text.lower()

            return (
                "shellcode" in lowered or
                " mz" in lowered or
                lowered.startswith("mz") or
                "4d 5a" in lowered or
                "4d5a" in lowered or
                "50 45 00 00" in lowered
            )

        for line in lines:

            stripped = line.strip()

            if (
                not stripped or
                "Volatility 3 Framework" in stripped or
                ("PID" in stripped and "Process" in stripped) or
                "Disasm" in stripped
            ):

                if "Volatility 3 Framework" in stripped or "PID" in stripped:
                    current_pid = None

                continue

            parts = stripped.split()

            if len(parts) < 2:
                continue

            # A real malfind table row starts with a PID and always carries a PAGE_* protection
            # column. Hexdump continuation lines also start with all-decimal bytes (e.g. "08 00
            # ..."), so isdigit() alone misparses them as phantom PID rows — require the protection
            # token.
            is_pid_row = (
                parts[0].isdigit() and
                "page_" in stripped.lower()
            )

            if is_pid_row:
                try:
                    pid = parts[0]
                    name = parts[1]

                    flags = " ".join(parts[2:]).lower()
                    current_pid = pid

                    if pid not in grouped_regions:

                        grouped_regions[pid] = {
                            "name": name,
                            "has_exec": False,
                            "has_wx": False,
                            "has_pe": False
                        }

                    # Track writable+executable (RWX) separately from execute-only (RX) so the
                    # reason text is accurate (3.1-B).
                    if (
                        "rwx" in flags or
                        "rw-x" in flags or
                        "rx" in flags or
                        "page_execute" in flags or
                        "page_exec" in flags or
                        "execute" in flags
                    ):
                        grouped_regions[pid]["has_exec"] = True

                    if (
                        "rwx" in flags or
                        "rw-x" in flags or
                        "page_execute_readwrite" in flags or
                        "page_execute_writecopy" in flags or
                        ("execute" in flags and "write" in flags)
                    ):
                        grouped_regions[pid]["has_wx"] = True

                    # `flags` is the space-joined protection columns; match "mz"/ "pe" as standalone
                    # tokens, not loose substrings (3.1-C).
                    flag_tokens = set(flags.split())
                    if (
                        _has_pe_signature(stripped) or
                        "mz" in flag_tokens or
                        "pe" in flag_tokens
                    ):
                        grouped_regions[pid]["has_pe"] = True
                except Exception:
                    pass

                continue

            if current_pid and current_pid in grouped_regions:

                # Continuation lines often carry MZ/hexdump markers.
                if _has_pe_signature(stripped):
                    grouped_regions[current_pid]["has_pe"] = True

        for pid, info in grouped_regions.items():

            name = info.get("name", "unknown")
            has_exec = info.get("has_exec", False)
            has_wx = info.get("has_wx", False)
            has_pe = info.get("has_pe", False)
            corroborated = has_exec and has_pe

            # Only call it "RWX" when the region is actually writable+executable; an execute-only
            # region is RX, so labelling it RWX is inaccurate (3.1-B).
            exec_label = "RWX region" if has_wx else "Executable (RX) region"

            if has_exec and has_pe:
                severity = "critical"
                confidence = 0.92
                reasons = [f"{exec_label} and embedded PE/shellcode detected"]
            elif has_exec or has_pe:
                severity = "high"
                confidence = 0.86
                reasons = [
                    f"{exec_label} detected" if has_exec else "Embedded PE/shellcode detected"
                ]
            else:
                severity = "medium"
                confidence = 0.70
                reasons = ["Injected regions detected (no RWX/PE signature)"]

            # Corroboration: either malfind itself saw RWX *and* a PE/shellcode signature, or
            # another tool independently flagged this PID.
            is_corroborated = corroborated or (str(pid) in corroborated_pids)

            if name.lower() in JIT_ALLOWLIST and not is_corroborated and severity in {"critical", "high"}:
                severity = "medium"
                confidence = 0.65
                reasons.append("Injection in JIT-capable process without corroborating IOC: down-ranked")
            elif name.lower() in JIT_ALLOWLIST and is_corroborated:
                reasons.append("Corroborated by another IOC; down-rank skipped")

            items.append(
                self.make_evidence_item(
                    artifact_id=f"malfind_{pid}",
                    evidence_type="injected_code",
                    value=(
                        f"Injected memory regions detected in {info['name']} "
                        f"(PID:{pid}). Reasons: {'; '.join(reasons)}"
                    ),
                    severity=severity,
                    confidence=confidence,
                    linked_artifacts=[f"proc_{pid}"]
                )
            )

        return items

    def _parse_dlllist(self, lines: list) -> list:

        items = []

        suspicious_dlls = [
            "unknown",
            # Path segment, not a bare token: "temp" as a substring matched inside ordinary DLL
            # names (DevDispI-temp-rovider.dll flagged HIGH, B-9d). The filescan/dumpfiles marker
            # lists already use the \temp\ form.
            "\\temp\\",
            "appdata\\roaming",
            "programdata"
        ]

        for line in lines:
            lower = line.lower()

            # Defender's platform dir under ProgramData (MpOav.dll etc.) trips the "programdata"
            # marker but isn't an implant indicator (B-3).
            if "\\microsoft\\windows defender\\" in lower:
                continue

            if any(s in lower for s in suspicious_dlls):
                items.append(
                    self.make_evidence_item(
                        artifact_id=stable_artifact_id("dll", line.strip()),
                        evidence_type="suspicious_dll",
                        value=line.strip(),
                        severity="high",
                        confidence=0.78
                    )
                )

        return items

    def _parse_filescan(self, lines: list) -> list:

        items = []
        seen = set()

        # Two marker classes, scored differently (B-9b): location markers count AT MOST ONCE
        # (Windows nests these dir names — two hits are usually one location); a payload marker on
        # top still reaches high.
        location_markers = [
            "\\appdata\\",
            "\\temp\\",
            "\\users\\public\\",
            "\\programdata\\",
            "\\startup",
            "\\runonce",
            "\\tasks\\",
            "\\intel\\",
        ]
        payload_markers = [
            ".onion",
            ".ps1",
            ".vbs",
            ".js",
            ".hta",
            ".bat",
            ".cmd"
        ]

        # Parents that don't normally host random-named subfolders (WannaCry's \Intel\<random>\).
        # \Temp\/\AppData\/\Public\ excluded — they hold legit hash-named dirs (browser caches).
        staging_parents = {"intel", "programdata"}

        def _has_suspicious_staging_path(path: str) -> bool:
            lowered = path.lower().replace("/", "\\")
            segments = [segment for segment in lowered.split("\\") if segment]

            for index, segment in enumerate(segments[:-1]):
                if segment in staging_parents and index + 1 < len(segments):
                    child = segments[index + 1]

                    if (
                        len(child) >= 12 and
                        re.match(r"^[a-z0-9]+$", child) and
                        re.search(r"[a-z]", child) and
                        re.search(r"\d", child)
                    ):
                        return True

            return False

        # Extensions that are common system binaries; only consider them suspicious when they appear
        # in staging/execution paths above.
        binary_exts = {".dll", ".exe"}

        # Payload signals suspicious anywhere (the staging gate would otherwise drop *.WNCRY in a
        # Pictures folder); extensions come from the shared RANSOM_EXTENSIONS list.
        malware_filename_markers = [
            "@wanadecryptor@", "wanadecryptor", "wannadecryptor",
            "tasksche", "taskdl", "taskse", "mssecsvc",
            "wannacry", "wanacry", "@please_read_me@",
        ]
        # Boundary-aware: "tasksche" inside "TaskScheduler" flagged system files as WannaCry (B-9b);
        # letters on either side disqualify the hit.
        malware_name_re = re.compile(
            "|".join(f"(?<![a-z]){re.escape(tok)}(?![a-z])"
                     for tok in malware_filename_markers)
        )

        for line in lines:

            # crude heuristic: look for absolute paths (Windows backslash or Unix slash)
            if "\\" in line or "/" in line:

                # Paths contain single spaces ("Documents and Settings") — split only on tabs / 2+
                # spaces, take the last path-looking field.
                fields = re.split(r"\t+| {2,}", line.strip())
                candidate = ""
                for field in reversed(fields):
                    if "\\" in field or "/" in field:
                        candidate = field.strip()
                        break

                if "\\" in candidate or "/" in candidate:

                    normalized = candidate.lower()

                    if normalized in seen:
                        continue

                    ext = ""
                    try:
                        ext = Path(normalized).suffix
                    except Exception:
                        ext = ""

                    basename = normalized.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]

                    # desktop.ini/thumbs.db are ubiquitous benign files that hit the location
                    # markers — drop regardless of path. startswith, not equality (raw-strings
                    # scraping glues garbage onto basenames); a masquerading desktop.ini.exe is NOT
                    # skipped.
                    if basename.startswith(("desktop.ini", "thumbs.db")) and \
                            not basename.endswith(EXECUTABLE_EXTENSIONS):
                        continue

                    # Ransomware extension / named payload: high regardless of path, bypassing the
                    # gates below.
                    if (
                        ext in RANSOM_EXTENSIONS or
                        malware_name_re.search(basename)
                    ):
                        seen.add(normalized)
                        items.append(
                            self.make_evidence_item(
                                artifact_id=stable_artifact_id("file", candidate),
                                evidence_type="file_artifact",
                                value=candidate,
                                severity="high",
                                confidence=0.95
                            )
                        )
                        continue

                    # relevance gate to avoid flooding with low-signal paths. ".js" as a substring
                    # also matches ".json", so count it only when it's the real file extension
                    # (3.3-D).
                    location_hits = sum(1 for m in location_markers if m in normalized)
                    payload_hits = 0
                    for marker in payload_markers:
                        if marker == ".js":
                            if ext == ".js":
                                payload_hits += 1
                        elif marker in normalized:
                            payload_hits += 1
                    # Location capped at 1 (see the marker-class note above).
                    marker_hits = min(location_hits, 1) + payload_hits

                    # Autostart persistence (T1547.001): executable/script/.lnk inside \Startup\ is
                    # a finding on its own (dev01 N6).
                    in_autostart = (
                        "\\startup\\" in normalized
                        and (basename.endswith(EXECUTABLE_EXTENSIONS)
                             or basename.endswith(".lnk"))
                    )

                    in_random_staging = _has_suspicious_staging_path(normalized)
                    # Safety net: random-named staging clears the gate even when the parent isn't
                    # substring-matched as a \parent\ marker.
                    if marker_hits == 0 and in_random_staging:
                        marker_hits = 1

                    # dll/exe outside any staging path = benign mass noise; skip.
                    if ext in binary_exts and marker_hits == 0:
                        continue

                    if marker_hits == 0:
                        continue

                    seen.add(normalized)

                    # Random-named staging (3.3-C), location+payload, or autostart → high; a single
                    # generic location marker stays medium (too noisy on its own).
                    if marker_hits >= 2 or in_random_staging or in_autostart:
                        severity = "high"
                        confidence = 0.90
                    else:
                        severity = "medium"
                        confidence = 0.80

                    items.append(
                        self.make_evidence_item(
                            artifact_id=stable_artifact_id("file", candidate),
                            evidence_type="file_artifact",
                            value=candidate,
                            severity=severity,
                            confidence=confidence
                        )
                    )

        return items

    def _parse_dumpfiles(self, lines: list) -> list:

        items = []
        seen = set()

        suspicious_markers = [
            "\\appdata\\",
            "\\temp\\",
            "\\users\\public\\",
            "\\programdata\\",
            ".exe",
            ".dll",
            ".ps1",
            ".vbs",
            ".js",
            ".bat",
            ".cmd",
            ".hta"
        ]

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            if (
                "Volatility 3 Framework" in stripped or
                "Progress:" in stripped or
                stripped.startswith("Cache")
            ):
                continue

            # Volatility dumpfiles output is tabular:
            # Cache  FileObject  FileName  Result
            cols = re.split(r"\s{2,}", stripped)
            if len(cols) < 4:
                continue

            file_name = cols[2].strip()
            result = cols[3].strip()

            if not file_name or file_name in {"N/A", "-"}:
                continue

            if not result or result in {"N/A", "-"}:
                continue

            lowered_name = file_name.lower()
            lowered_result = result.lower()

            if lowered_name in seen:
                continue

            if not any(marker in lowered_name for marker in suspicious_markers):
                continue

            # Skip rows where extraction did not actually produce a file.
            if "error" in lowered_result or "failed" in lowered_result:
                continue

            seen.add(lowered_name)

            items.append(
                self.make_evidence_item(
                    artifact_id=stable_artifact_id("dumpfile", file_name, result),
                    evidence_type="extracted_file",
                    value=f"{file_name} -> {result}",
                    severity="high",
                    confidence=0.90
                )
            )

        return items

    def _parse_yarascan(self, lines: list) -> list:
        items = []

        for line in lines:
            cleaned = line.strip()
            if (
                not cleaned or
                "Volatility 3 Framework" in cleaned or
                "Progress:" in cleaned
            ):
                continue

            if "Offset" in cleaned and "Rule" in cleaned:
                continue

            items.append(
                self.make_evidence_item(
                    artifact_id=stable_artifact_id("yara", cleaned),
                    evidence_type="yara_match",
                    value=cleaned,
                    severity="high",
                    confidence=0.90
                )
            )

        return items

    def _parse_strings(self, lines: list) -> list:
        corpus = "\n".join(lines)
        return self._extract_strings(corpus)

    def _extract_strings(self, corpus: str) -> list:
        items = []
        if not corpus:
            return items

        seen = set()

        def _add_item(value: str, evidence_type: str, severity: str, confidence: float, artifact_prefix: str):
            normalized = value.lower()
            if normalized in seen:
                return

            seen.add(normalized)
            items.append(
                self.make_evidence_item(
                    artifact_id=stable_artifact_id(artifact_prefix, value),
                    evidence_type=evidence_type,
                    value=value,
                    severity=severity,
                    confidence=confidence
                )
            )

        # .onion kept even bare (rarely sits in URL grammar) but at LOW — an in-memory threat-intel
        # feed carries dozens of uncontacted families' .onions, which at HIGH manufactured a false
        # verdict (B-8).
        for match in _ONION_RE.finditer(corpus):
            _add_item(match.group(0).lower(), "suspicious_domain", "low", 0.6, "ioc")

        # Checksum-valid BTC wallets at LOW, same rationale as .onion above; a catalog-known ransom
        # wallet still escalates via the rescorer.
        for match in _BTC_BASE58_RE.finditer(corpus):
            candidate = match.group(0)
            if _is_valid_btc_address(candidate):
                _add_item(candidate, "suspicious_crypto", "low", 0.6, "btc")

        for match in _BTC_BECH32_RE.finditer(corpus):
            candidate = match.group(0)
            if _is_valid_bech32_btc_address(candidate):
                _add_item(candidate.lower(), "suspicious_crypto", "low", 0.6, "btc")

        for match in _EMAIL_RE.finditer(corpus):
            addr = match.group(0)
            local, _, domain = addr.partition("@")
            labels = domain.split(".")
            tld = labels[-1].lower()

            # Require a well-formed local part + real TLD — rejects the filename / binary noise the
            # loose regex matches ("5@0.FF", digits-only).
            if (
                len(labels) < 2 or
                len(labels[-2]) < 2 or
                tld not in _VALID_TLDS or
                tld in _AMBIGUOUS_CODE_TLDS or
                not any(c.isalpha() for c in local) or
                local.startswith(".") or local.endswith(".") or ".." in local or
                any(
                    not lbl or not lbl[0].isalnum() or not lbl[-1].isalnum()
                    for lbl in labels
                )
            ):
                continue

            _add_item(addr, "email_address", "medium", 0.85, "email")

        for pattern in _REGISTRY_RES:
            for match in pattern.finditer(corpus):
                _add_item(match.group(0), "registry_key", "medium", 0.88, "reg")

        # Emit a domain ONLY when anchored in URL/network grammar (_has_network_context): bare
        # fragments were 25k of 36k items on dev01 and stalled P5. A real C2 arrives via its
        # anchored network artifact and the rescorer elevates it. .onion is handled above
        # regardless.
        ANCHORED_CONF = 0.45
        seen_domains = set()
        anchored_domains = []

        for match in _DOMAIN_RE.finditer(corpus):
            value = match.group(0).lower()
            tld = match.group("tld").lower()

            if tld not in _VALID_TLDS:
                continue

            labels = value.split(".")
            if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
                continue

            # Drop 1-character second-level labels ("t.com", "h.it") — noise.
            if len(labels[-2]) < 2:
                continue

            # Disambiguate ccTLDs that double as script extensions: only accept them with a
            # sub-domain (e.g. "panel.c2.pl"), not a bare "script.py".
            if tld in _AMBIGUOUS_CODE_TLDS and len(labels) < 3:
                continue

            # Benign OS/CDN/CA infrastructure dominates a dump — drop.
            if is_benign_domain(value):
                continue

            # THE GATE: only domains in real URL/network grammar survive.
            if not _has_network_context(corpus, match.start(), match.end(), value):
                continue

            if value not in seen_domains:
                seen_domains.add(value)
                anchored_domains.append(value)

        for value in anchored_domains:
            _add_item(value, "suspicious_domain", "low", ANCHORED_CONF, "dom")

        return items


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m src.wrappers.volatility_wrapper <memory.dmp>")
        sys.exit(1)

    wrapper = VolatilityWrapper()
    items = wrapper.run(sys.argv[1])
    output = {"tool": "volatility3", "items": items}

    os.makedirs("output/raw", exist_ok=True)
    with open("output/raw/volatility3_output.json", "w") as f:
        json.dump(output, f, indent=2)

    print(
        f"\n[DONE] {len(items)} evidence items saved to "
        f"output/raw/volatility3_output.json"
    )
