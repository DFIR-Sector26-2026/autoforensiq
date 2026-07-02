import os
import re
import sys
import json
import uuid
import hashlib
import tempfile
from pathlib import Path

from .base_wrapper import BaseWrapper
from src.data.threat_intel import c2_port_severity, RANSOM_EXTENSIONS

PLUGINS = [
    "windows.pslist",
    "windows.pstree",
    "windows.cmdline",
    "windows.netstat",
    "windows.malfind",
    "windows.filescan",
    "windows.dlllist"
]
# NB: windows.strings is intentionally NOT in PLUGINS. It requires a
# --strings-file argument, so running it in the main loop (which can't pass one)
# just triggers a slow, failing vol pass. It is run separately, correctly, in the
# dedicated strings block in run() with a generated --strings-file.


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

    lines = [
        f"{'  ' * depth}{node.name} (PID:{node.pid})"
    ]

    for child in node.children:

        child_text = summarise_tree(
            child,
            depth + 1,
            max_depth
        )

        if child_text:
            lines.append(child_text)

    return "\n".join(lines)


def tree_to_dict(node, depth=0, max_depth=5):
    """Structured process-tree for downstream consumers (issue 4.5): the same
    lineage as summarise_tree but as nested dicts instead of indented text, so
    the report/UI doesn't have to re-parse the text blob."""

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
    """Concise one-line root→leaf lineage(s), e.g.
    `explorer.exe(1636) → tasksche.exe(1940) → @WanaDecryptor@(740)` (issue 4.5).
    One line per leaf path; a single linear chain collapses to one line."""

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


SUSPICIOUS_PARENTS = [
    "cmd.exe",
    "powershell.exe",
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

# Benign infrastructure domains (issue D3). A raw memory dump is saturated with
# OS / browser / CDN / certificate / telemetry hostnames; emitting each one as a
# `suspicious_domain` floods the evidence set (a Windows dump produced ~22k of
# them) and is the input that made P5 SHAP unscalable. Any extracted host that
# equals one of these registrable bases — or is a sub-domain of it — is dropped
# at the source. This is curated benign infrastructure, NOT a way to whitelist
# real C2: the host-aware reputation layer (ioc_rescorer, issue 4.2) still runs
# on whatever survives, so a curated bad host is never suppressed here.
BENIGN_DOMAIN_SUFFIXES = {
    # Microsoft / Windows OS + telemetry + update + cloud
    "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com",
    "msftconnecttest.com", "microsoftonline.com", "live.com", "msn.com",
    "office.com", "office365.com", "outlook.com", "bing.com", "skype.com",
    "xboxlive.com", "azure.com", "azureedge.net", "msedge.net", "windows.net",
    "msocdn.com", "s-microsoft.com", "microsoft.net",
    # Mozilla / Firefox
    "mozilla.org", "mozilla.com", "mozilla.net", "firefox.com",
    # Google
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "google-analytics.com", "doubleclick.net", "gvt1.com", "gvt2.com",
    "youtube.com", "ytimg.com", "googlesyndication.com",
    # Apple
    "apple.com", "icloud.com", "mzstatic.com",
    # CDNs
    "akamai.net", "akamaiedge.net", "akamaihd.net", "edgekey.net",
    "edgesuite.net", "llnwd.net", "cloudfront.net", "cloudflare.com",
    "fastly.net", "fbcdn.net", "amazonaws.com",
    # Certificate authorities / OCSP / CRL
    "digicert.com", "verisign.com", "globalsign.com", "symantec.com",
    "entrust.net", "godaddy.com", "sectigo.com", "letsencrypt.org",
    "comodoca.com", "usertrust.com", "thawte.com", "geotrust.com",
    # Linux distros (the bundled Ubuntu / casper images)
    "ubuntu.com", "debian.org", "canonical.com", "archlinux.org",
    "launchpad.net", "kernel.org",
    # Standards / schema hosts that litter binaries
    "w3.org", "oasis-open.org", "ietf.org", "iana.org",
    # Common vendor hosts
    "adobe.com", "intel.com", "nvidia.com", "amd.com", "dell.com",
    "hp.com", "lenovo.com", "java.com", "oracle.com",
}


def _is_benign_domain(host: str) -> bool:
    """True when `host` is benign infrastructure (issue D3): it equals one of
    BENIGN_DOMAIN_SUFFIXES or is a sub-domain of one. Host-aware, so a lookalike
    like "microsoft.com.evil.tld" is NOT treated as benign."""
    host = host.lower().rstrip(".")
    for base in BENIGN_DOMAIN_SUFFIXES:
        if host == base or host.endswith("." + base):
            return True
    return False


# URL / network-context anchors (issue D3). A domain recovered from a flat string
# sweep is treated as a real network endpoint only when it sits inside URL grammar
# — a scheme, an HTTP header, a www. prefix, or a trailing path/port/query. This
# is the GATE for string-derived domains (see _extract_strings): an anchored
# domain is emitted; a bare token adrift in prose or binary is dropped as noise,
# since a bare-but-real C2 still reaches the pipeline through its actual
# connection/DNS artifact. The anchor set is fixed from URL grammar, not tuned to
# any one image, so it generalises.
_URL_SCHEME_RE = re.compile(r"(?:https?|ftp|wss?)://$", re.IGNORECASE)
_HEADER_ANCHORS = ("host:", "referer:", "referrer:", "location:", "origin:",
                   "url=", "uri=")


def _has_network_context(corpus: str, start: int, end: int, value: str) -> bool:
    """True when the domain at corpus[start:end] sits inside URL/network grammar:
    a www. prefix, a preceding scheme (`http://`) or protocol-relative `//`, an
    HTTP header anchor (`Host:`, `Referer:`, …), or a trailing path/port/query."""
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


class VolatilityWrapper(BaseWrapper):

    consumes = "memory_dump"

    def __init__(self):

        super().__init__("volatility3")

    @staticmethod
    def _volatility_command_candidates() -> list:
        """Ordered ways to invoke Volatility3, most-specific first.

        The pipeline is launched as `venv/bin/python autoforensiq.py ...`, so the
        venv is NOT on PATH; a bare `vol` / `python3 -m volatility3` then fails and
        the wrapper silently returns 0 items while pre-flight (which probes
        `./venv/bin/vol`) reports OK (issue D1). We therefore try the venv's own
        `vol` console script first — resolved from the running interpreter's
        directory so it works regardless of CWD — then the CWD-relative path
        pre-flight verifies, before falling back to whatever is on PATH.
        """
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

            stdout, stderr, code = self.run_command(
                try_cmd,
                timeout=15
            )

            if code == 0:

                working_command = base_cmd
                break

        if not working_command:

            print(
                "  [ERROR] Could not locate "
                "working Volatility3 installation"
            )

            return []

        print(
            f"  [VOL] Using command: "
            f"{' '.join(working_command)}"
        )

        combined_output = ""

        # malfind is parsed after the loop so cross-plugin corroboration is
        # available (see below). Stash its raw output here when encountered.
        malfind_output = None

        for plugin in PLUGINS:

            print(f"\n  [VOL] Running {plugin}...")

            command = (
                working_command +
                ["-f", image_path, plugin]
            )

            stdout, stderr, code = self.run_command(
                command,
                input_files=[image_path],
                timeout=180
            )

            # Per-plugin return code + 1000-char stdout/stderr dumps are noisy on
            # a normal run (the GUI streams all of it), so gate them behind
            # VOL_DEBUG — same opt-in style as VOL_ENABLE_DUMPFILES below.
            if os.getenv("VOL_DEBUG", "").lower() in {"1", "true", "yes"}:

                print(f"\n  [DEBUG] Return code: {code}")

                if stderr.strip():

                    print(
                        f"\n  [DEBUG] STDERR:\n"
                        f"{stderr[:1000]}"
                    )

                if stdout.strip():

                    print(
                        f"\n  [DEBUG] STDOUT:\n"
                        f"{stdout[:1000]}"
                    )

            # keep a combined corpus for regex-based extraction
            if stdout:
                combined_output += "\n" + stdout

            if code != 0:

                print(f"  [SKIP] {plugin} failed")

                continue

            if not stdout.strip():

                print(
                    f"  [SKIP] "
                    f"{plugin} produced empty output"
                )

                continue

            if plugin == "windows.malfind":
                # Defer parsing until after the loop so behavioral IOCs from the
                # other plugins (suspicious cmdline / C2 connection) can be used
                # to corroborate — and thus not down-rank — JIT-process hits.
                malfind_output = stdout
                continue

            try:
                items = self._parse(plugin, stdout)
            except Exception as exc:
                print(f"  [SKIP] {plugin} parse failed: {exc}")
                continue

            print(
                f"  [VOL] {plugin} → "
                f"{len(items)} evidence items"
            )

            all_items.extend(items)

        # Parse the deferred malfind output now that the other plugins' evidence
        # is available for cross-IOC corroboration.
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
                    print(
                        f"  [VOL] malfind corroborated PIDs: "
                        f"{sorted(corroborated_pids)}"
                    )
                print(f"  [VOL] windows.malfind → {len(items)} evidence items")
                all_items.extend(items)
            except Exception as exc:
                print(f"  [SKIP] windows.malfind parse failed: {exc}")

        # Optional plugin: dumpfiles can write many files to CWD when unfiltered,
        # so keep it opt-in for controlled investigations.
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

        # Feed windows.strings with a real strings file generated from the
        # image when possible. This avoids volatility's internal strings
        # collector returning empty results when no strings source is set.
        strings_path = None
        strings_cleanup = None
        try:
            strings_path, strings_cleanup = self._build_strings_file(image_path)
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

                # windows.strings only emits strings it can attribute to a
                # mapped process, so memory-resident IOCs sitting in unattributed
                # pool/heap (killswitch domain, .onion C2, BTC wallets, registry
                # keys) never reach it. Run the IOC sweep directly over the raw
                # strings file too so those are recovered; the final de-dupe
                # collapses any overlap with the attributed output.
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
            if strings_cleanup is not None:
                try:
                    strings_cleanup.cleanup()
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

        # The string sweep runs over both `combined_output` and the separate
        # windows.strings output, so the same IOC (onion / domain / wallet) can
        # be emitted twice. Collapse identical (type, value) items, keeping the
        # strongest, so downstream stages and the P7 findings cap aren't fed
        # duplicates.
        before = len(all_items)
        all_items = self._dedupe_items(all_items)
        if len(all_items) != before:
            print(f"  [VOL] de-duplicated {before - len(all_items)} repeat items")

        return all_items

    def _dedupe_items(self, items: list) -> list:
        """Collapse evidence items that share the same (evidence_type, value,
        linked_artifacts), keeping the one with the highest severity then
        confidence. Original ordering of the first occurrence is preserved.

        `linked_artifacts` is part of the key so items whose value omits the PID
        (e.g. process_relation, "parent.name -> child.name") are not merged
        across distinct PID pairs; string IOCs have no links, so they still
        de-duplicate as intended (issue 3.3-F)."""

        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}

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
                severity_rank.get(it.get("severity"), 0),
                it.get("confidence", 0) or 0,
            )
            incumbent = (
                severity_rank.get(cur.get("severity"), 0),
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

        # Plugin -> parser lookup (issue D6), replacing the if/elif chain. The
        # three yarascan plugin names share one parser; an unknown plugin yields
        # no items.
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
        """
        Run the system `strings` utility against the raw image to produce a
        temporary strings file suitable for feeding to volatility's
        `windows.strings --strings-file` option. Returns (path, cleanup)
        where cleanup is an object with a `cleanup()` method that removes
        the tempfile. Returns (None, None) on failure.
        """

        try:
            stdout, stderr, code = self.run_command(
                ["strings", "-a", "-n", "8", image_path],
                input_files=[image_path],
                timeout=120,
            )
        except Exception:
            return None, None

        if code != 0 or not stdout.strip():
            return None, None

        tmp = tempfile.NamedTemporaryFile(delete=False, prefix="af_strings_", suffix=".txt", mode="w", encoding="utf-8")
        try:
            tmp.write(stdout)
            tmp.flush()
            tmp.close()
        except Exception:
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
            return None, None

        class _Cleanup:
            def __init__(self, path):
                self._path = path

            def cleanup(self):
                try:
                    if os.path.exists(self._path):
                        os.unlink(self._path)
                except Exception:
                    pass

        return tmp.name, _Cleanup(tmp.name)

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

                safe_name = (
                    name.lower()
                    .replace('.', '_')
                    .replace('@', '')
                )

                severity = (
                    "high"
                    if any(
                        s in name.lower()
                        for s in SUSPICIOUS_PARENTS
                    )
                    else "low"
                )

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

                pair = (
                    parent.name.lower(),
                    proc.name.lower()
                )

                if pair in SUSPICIOUS_RELATIONSHIPS:

                    proc.suspicious = True

                    proc.reasons.append(
                        f"Suspicious lineage: "
                        f"{parent.name} -> {proc.name}"
                    )

                    relation_items.append(
                        self.make_evidence_item(
                            artifact_id=(
                                f"relation_{parent.pid}_{proc.pid}"
                            ),
                            evidence_type="process_relation",
                            value=(
                                f"Suspicious parent-child "
                                f"relationship: "
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
            # 4.5: expose the tree as structured data and a one-line lineage so
            # downstream consumers don't have to re-parse the indented `value`.
            tree_item["process_tree_json"] = tree_to_dict(root)
            tree_item["lineage"] = tree_lineage(root)
            tree_items.append(tree_item)

        items.extend(tree_items)
        items.extend(relation_items)

        return items
    def _parse_cmdline(self, lines: list) -> list:

        items = []

        suspicious_keywords = [
            "-enc",
            "-encodedcommand",
            "invoke-",
            "downloadstring",
            "iex",
            "bypass",
            "hidden",
            "frombase64"
        ]

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
                # Exactly PID + process name, zero arguments (issue 3.4-r): the
                # command line is just the executable. Store the process name, not
                # the raw "PID<tab>Process" row (the PID is already in artifact_id),
                # so the value matches the args-bearing case.
                cmdline = process_name

            severity = (
                "high"
                if any(
                    kw in lower
                    for kw in suspicious_keywords
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

                # C2-port severity is tiered (issue D1): a high-confidence port
                # (4444/4445/1337/31337) -> high; a dual-use watch port
                # (IRC/8888/9999/...) -> medium; neither -> low. Take the
                # stronger of the local/remote port verdicts.
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
        """PIDs independently flagged by a *behavioral* IOC — a suspicious
        command line or a C2/external network connection at high/critical
        severity. Used as the spec's "corroborated by another IOC" escape so a
        malfind injection in a JIT-capable process (chrome/svchost/...) stays
        elevated instead of being down-ranked. Deliberately excludes name-based
        heuristics (e.g. pslist's suspicious-parent flag) to keep corroboration
        independent of the same allowlist logic malfind already applies.
        """
        import re

        corroborating_types = {"commandline", "network_connection"}
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

            for m in re.finditer(r"pid[:=]?\s*(\d+)", str(it.get("value", "")), re.IGNORECASE):
                pids.add(m.group(1))

        return pids

    def _parse_malfind(self, lines: list, corroborated_pids: set = None) -> list:

        items = []

        # PIDs independently flagged by another IOC (e.g. a suspicious cmdline,
        # a C2 netstat connection, a recovered payload). Used as the spec's
        # "corroborated by another IOC" escape from the system-process down-rank.
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

            # A real malfind table row starts with a PID and always carries a
            # PAGE_* protection column. Hexdump continuation lines also start
            # with all-decimal bytes (e.g. "08 00 ..."), so isdigit() alone
            # misparses them as phantom PID rows — require the protection token.
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

                    # malfind only emits suspicious VADs, so any executable
                    # private region is notable. Track a truly writable+
                    # executable region (classic RWX shellcode home) separately
                    # from an execute-only RX region, so the reason text below
                    # doesn't claim "RWX" for a PAGE_EXECUTE_READ region (3.1-B).
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

                    # `flags` is the space-joined protection columns; match "mz"/
                    # "pe" as standalone tokens, not loose substrings (3.1-C).
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

            # Only call it "RWX" when the region is actually writable+executable;
            # an execute-only region is RX, so labelling it RWX is inaccurate (3.1-B).
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

            # Processes where RWX/executable private memory is *commonly benign*
            # — browsers and JIT/.NET hosts allocate RWX for generated code.
            # These are the real false-positive sources, so injections here are
            # down-ranked unless corroborated. Core system processes (csrss,
            # winlogon, lsass, services, smss, wininit) are deliberately NOT in
            # this set: they never legitimately host RWX/injected code, so a hit
            # there is a strong signal and must keep its severity.
            jit_allowlist = {
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
            }

            # Corroboration: either malfind itself saw RWX *and* a PE/shellcode
            # signature, or another tool independently flagged this PID.
            is_corroborated = corroborated or (str(pid) in corroborated_pids)

            if name.lower() in jit_allowlist and not is_corroborated and severity in {"critical", "high"}:
                severity = "medium"
                confidence = 0.65
                reasons.append("Injection in JIT-capable process without corroborating IOC: down-ranked")
            elif name.lower() in jit_allowlist and is_corroborated:
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
            "temp",
            "appdata\\roaming",
            "programdata"
        ]

        for line in lines:

            lower = line.lower()

            if any(
                s in lower
                for s in suspicious_dlls
            ):

                items.append(
                    self.make_evidence_item(
                        artifact_id=(
                            f"dll_{str(uuid.uuid4())[:8]}"
                        ),
                        evidence_type="suspicious_dll",
                        value=line.strip(),
                        severity="high",
                        confidence=0.78
                    )
                )

        return items

    def _parse_filescan(self, lines: list) -> list:

        import re

        items = []
        seen = set()

        # Markers that indicate staging/execution locations or payloads.
        suspicious_markers = [
            "\\appdata\\",
            "\\temp\\",
            "\\users\\public\\",
            "\\programdata\\",
            "\\startup",
            "\\runonce",
            "\\tasks\\",
            "\\intel\\",
            ".onion",
            ".ps1",
            ".vbs",
            ".js",
            ".hta",
            ".bat",
            ".cmd"
        ]

        # Parents that don't normally host random-named subfolders, so a
        # gibberish child under one is a malware-staging hallmark (e.g. WannaCry's
        # \Intel\<random>\ and \ProgramData\<random>\). Deliberately excludes
        # \Temp\, \AppData\, \Public\: those legitimately hold random/hash-named
        # dirs (browser caches, installer temp), which would be false positives.
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

        # Extensions that are common system binaries; only consider them
        # suspicious when they appear in staging/execution paths above.
        binary_exts = {".dll", ".exe"}

        # Ransomware / payload signals that are suspicious on their own,
        # independent of where the file sits. The staging-path gate otherwise
        # drops these (e.g. WannaCry *.WNCRY encrypted victim files in a
        # Pictures folder, or a named dropper outside \Intel\).
        # Ransomware / encrypted-payload extensions come from the shared
        # threat-intel list (RANSOM_EXTENSIONS) so tsk and volatility agree.
        malware_filename_markers = [
            "@wanadecryptor@", "wanadecryptor", "wannadecryptor",
            "tasksche", "taskdl", "taskse", "mssecsvc",
            "wannacry", "wanacry", "@please_read_me@",
        ]

        for line in lines:

            # crude heuristic: look for absolute paths (Windows backslash or Unix slash)
            if "\\" in line or "/" in line:

                # filescan rows are "Offset<TAB>Name". The Name is a path that
                # can contain single spaces (e.g. "Documents and Settings",
                # "Users\Public\My Tools"). Splitting on every space truncates
                # the path and loses the staging-path marker, dropping the file.
                # Split only on tabs / runs of 2+ spaces, then take the last
                # field that still looks like a path.
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

                    # Known ransomware extension or named payload — a strong
                    # signal on its own, so flag it high regardless of path
                    # (bypasses the staging-marker / system-binary gates below).
                    if (
                        ext in RANSOM_EXTENSIONS or
                        any(tok in basename for tok in malware_filename_markers)
                    ):
                        seen.add(normalized)
                        items.append(
                            self.make_evidence_item(
                                artifact_id=f"file_{str(uuid.uuid4())[:8]}",
                                evidence_type="file_artifact",
                                value=candidate,
                                severity="high",
                                confidence=0.95
                            )
                        )
                        continue

                    # relevance gate to avoid flooding with low-signal paths.
                    # ".js" as a substring also matches ".json", so count it
                    # only when it's the real file extension (3.3-D).
                    marker_hits = 0
                    for marker in suspicious_markers:
                        if marker == ".js":
                            if ext == ".js":
                                marker_hits += 1
                        elif marker in normalized:
                            marker_hits += 1

                    in_random_staging = _has_suspicious_staging_path(normalized)
                    # Ensure a random-named staging path still clears the
                    # relevance gate below. Redundant for normal filescan output
                    # (its parents, intel/programdata, are also markers, so
                    # marker_hits is already >= 1) but kept as a safety net for
                    # path forms where the parent isn't substring-matched as a
                    # `\parent\` marker (e.g. no leading separator).
                    if marker_hits == 0 and in_random_staging:
                        marker_hits = 1

                    # If this looks like a plain system binary (dll/exe) but is
                    # not located in a staging/execution path, skip it to avoid
                    # mass noise from benign system files.
                    if ext in binary_exts and marker_hits == 0:
                        continue

                    if marker_hits == 0:
                        continue

                    seen.add(normalized)

                    # A randomly-named staging directory is a malware hallmark and
                    # ranks high on its own (3.3-C), as does any path hitting 2+
                    # markers. A single generic location marker (\temp\, \appdata\)
                    # stays medium — too noisy to call high on its own.
                    if marker_hits >= 2 or in_random_staging:
                        severity = "high"
                        confidence = 0.90
                    else:
                        severity = "medium"
                        confidence = 0.80

                    items.append(
                        self.make_evidence_item(
                            artifact_id=(
                                f"file_{str(uuid.uuid4())[:8]}"
                            ),
                            evidence_type="file_artifact",
                            value=candidate,
                            severity=severity,
                            confidence=confidence
                        )
                    )

        return items

    def _parse_dumpfiles(self, lines: list) -> list:

        import re

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
                    artifact_id=f"dumpfile_{str(uuid.uuid4())[:8]}",
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
                    artifact_id=f"yara_{str(uuid.uuid4())[:8]}",
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

        import re

        items = []

        if not corpus:
            return items

        seen = set()

        # A domain's final label must be a *registered* TLD. This filters
        # filename noise (ntdll.dll, ntoskrnl.exe, *.pdb/.sys — none are TLDs)
        # while still recovering C2 on country-code / .gov / .edu domains that
        # a tiny allowlist would silently drop.
        valid_tlds = {
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
            # ccTLDs that also double as script/binary extensions (kept valid
            # here; the ambiguous-TLD guard below requires a sub-domain).
            "pl", "py", "pm", "sh", "so", "rs", "md", "ax",
        }

        # Valid ccTLDs that are ALSO common source/script extensions. In a
        # memory-image string sweep these are overwhelmingly files (main.py,
        # lib.so, mod.rs, run.sh) rather than 2-label domains, so for these we
        # require a sub-domain (3+ labels) before treating them as a domain.
        # "ax" = Åland ccTLD, but also the Windows DirectShow filter extension
        # (l3codecx.ax, divxdec.ax). "nc" (New Caledonia) is gibberish-prone in
        # raw strings — both overwhelmingly noise as 2-label "domains".
        # (".pf" — French Polynesia — is dropped from valid_tlds entirely above:
        # it's the Prefetch file extension, e.g. TASKDL.EXE-01687054.pf.)
        ambiguous_code_tlds = {"py", "pl", "sh", "so", "rs", "md", "pm", "ax", "nc"}

        def _add_item(value: str, evidence_type: str, severity: str, confidence: float, artifact_prefix: str):
            normalized = value.lower()
            if normalized in seen:
                return

            seen.add(normalized)
            items.append(
                self.make_evidence_item(
                    artifact_id=f"{artifact_prefix}_{str(uuid.uuid4())[:8]}",
                    evidence_type=evidence_type,
                    value=value,
                    severity=severity,
                    confidence=confidence
                )
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

        # Native SegWit (bech32 / bech32m, BIP-173 / BIP-350) — the modern
        # `bc1…` address family the base58check path above can't validate:
        #   * witness v0  (P2WPKH/P2WSH) uses the bech32 checksum constant (1)
        #   * witness v1+ (P2TR Taproot) uses the bech32m constant (0x2bc830a3)
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

        for match in re.finditer(r"[a-z0-9]{16,56}\.onion", corpus, flags=re.IGNORECASE):

            _add_item(match.group(0).lower(), "suspicious_domain", "high", 0.95, "ioc")

        for match in re.finditer(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", corpus):

            candidate = match.group(0)

            if _is_valid_btc_address(candidate):
                _add_item(candidate, "suspicious_crypto", "high", 0.93, "btc")

        for match in re.finditer(r"\bbc1[ac-hj-np-z02-9]{8,87}\b", corpus, flags=re.IGNORECASE):

            candidate = match.group(0)

            if _is_valid_bech32_btc_address(candidate):
                _add_item(candidate.lower(), "suspicious_crypto", "high", 0.93, "btc")

        for match in re.finditer(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}", corpus):

            addr = match.group(0)
            local, _, domain = addr.partition("@")
            labels = domain.split(".")
            tld = labels[-1].lower()

            # Require a well-formed local part and domain with a real TLD.
            # Rejects filename / binary noise the loose regex otherwise matches,
            # e.g. "WANADECRYPTOR@.EXE-06F053F5.pf" (empty leading label),
            # "5@0.FF" (bogus TLD), "J.@L.IN" (1-char SLD / trailing-dot local),
            # "15090.61304@aaa.zzz.org" (digits-only local).
            if (
                len(labels) < 2 or
                len(labels[-2]) < 2 or
                tld not in valid_tlds or
                tld in ambiguous_code_tlds or
                not any(c.isalpha() for c in local) or
                local.startswith(".") or local.endswith(".") or ".." in local or
                any(
                    not lbl or not lbl[0].isalnum() or not lbl[-1].isalnum()
                    for lbl in labels
                )
            ):
                continue

            _add_item(addr, "email_address", "medium", 0.85, "email")

        # The path char class excludes the pipe: `|` is not a legal character in
        # a Windows registry key path, so a `|` means the string sweep has run
        # past the real key into adjacent memory (e.g.
        # "...\CurrentControlSet\Services|BatteryLife"). Stopping at the pipe both
        # keeps the key clean and stops that stray `|` from corrupting the
        # markdown report table (it was read as a column delimiter, shifting
        # every later column one to the right).
        registry_patterns = [
            r"(?:HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKCR|HKEY_CLASSES_ROOT|HKU|HKEY_USERS)\\[^\s\"'|]+",
            r"\\Registry\\Machine\\[^\s\"'|]+",
            r"\\Registry\\User\\[^\s\"'|]+",
        ]

        for pattern in registry_patterns:

            for match in re.finditer(pattern, corpus, flags=re.IGNORECASE):

                _add_item(match.group(0), "registry_key", "medium", 0.88, "reg")

        domain_pattern = re.compile(
            r"(?<![@\\])\b(?:[a-z0-9-]{1,63}\.)+(?P<tld>[a-z]{2,24})\b",
            flags=re.IGNORECASE,
        )

        # Emit a memory-string domain ONLY when it is anchored in URL / DNS /
        # connection grammar at least once (see _has_network_context). A bare
        # domain fragment — a naked token adrift in prose or binary — carries no
        # network evidence and is overwhelmingly noise: a memory sweep yields tens
        # of thousands of them (25k of 36k on the dev01 image, e.g.
        # "conticrypt.ph/.pa/.pe" smeared across ccTLDs), which flooded
        # unified_evidence (27 MB) and stalled the P5 ML stage. A genuinely
        # malicious host reaches the pipeline through its real network artifact
        # (a connection / DNS query / URL), which is anchored and kept here; the
        # reputation rescorer then elevates it. .onion hosts are emitted above at
        # high severity regardless.
        ANCHORED_CONF = 0.45
        seen_domains = set()
        anchored_domains = []

        for match in domain_pattern.finditer(corpus):

            value = match.group(0).lower()
            tld = match.group("tld").lower()

            if tld not in valid_tlds:
                continue

            labels = value.split(".")
            if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
                continue

            # Drop 1-character second-level labels ("t.com", "h.it") — noise.
            if len(labels[-2]) < 2:
                continue

            # Disambiguate ccTLDs that double as script extensions: only accept
            # them with a sub-domain (e.g. "panel.c2.pl"), not a bare "script.py".
            if tld in ambiguous_code_tlds and len(labels) < 3:
                continue

            # Drop benign OS / browser / CDN / CA / telemetry infrastructure —
            # these dominate a memory dump and are pure noise.
            if _is_benign_domain(value):
                continue

            # The gate: keep only domains seen in real URL/network grammar. Bare
            # string fragments (short ccTLD junk, DOS `.com` names, digit/repeat
            # noise) are all dropped here — no per-class bare filters needed.
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

        print(
            "Usage: python -m "
            "src.wrappers.volatility_wrapper "
            "<memory.dmp>"
        )

        sys.exit(1)

    wrapper = VolatilityWrapper()

    items = wrapper.run(sys.argv[1])

    output = {
        "tool": "volatility3",
        "items": items
    }

    os.makedirs("output/raw", exist_ok=True)

    with open(
        "output/raw/volatility3_output.json",
        "w"
    ) as f:

        json.dump(output, f, indent=2)

    print(
        f"\n[DONE] {len(items)} "
        f"evidence items saved to "
        f"output/raw/volatility3_output.json"
    )
