import os
import re
import json
import math
import shutil
import statistics
import tempfile
from collections import Counter
from datetime import datetime, timezone
from src.wrappers.base_wrapper import BaseWrapper, stable_artifact_id
from src.data.threat_intel import (
    C2_PORTS_ALL, c2_port_severity, is_allowlisted_dns, is_lan_ipv4,
    EXECUTABLE_EXTENSIONS, RANSOM_EXTENSIONS,
)
import hashlib

# A scripted UA on outbound web traffic is a strong signal
SUSPICIOUS_USER_AGENTS = (
    "curl/", "wget/", "python-requests", "python-urllib", "go-http-client",
    "libwww-perl", "powershell", "okhttp", "java/", "axios/", "winhttp",
)

# HTTP-body inspection (B3): text bodies only, size-capped, surfaced only when carrying an embedded
# URL or long hex token — heartbeats don't add noise.
BODY_TEXT_CONTENT_TYPES = ("json", "text", "urlencoded", "xml", "javascript")
BODY_MAX_BYTES = 8192
_BODY_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_BODY_HEXID_RE = re.compile(r"\b[0-9a-f]{32,64}\b")

# a flow whose session initiations recur at a steady interval is C2-shaped even with an empty catalog
BEACON_MIN_COUNT = 8
BEACON_MIN_INTERVAL_S = 5.0     # faster = retries/scanning, not beaconing
BEACON_MAX_INTERVAL_S = 3600.0
BEACON_MAX_CV = 0.45            # stdev/mean of inter-arrival deltas; allows deliberate jitter

# Upload-volume anomaly (BUGS 2.3): browsing uploads run ~KB and download-dominant; 
EXFIL_MIN_UPLOAD_BYTES = 1_000_000
EXFIL_MIN_ASYMMETRY = 5



# DNS_ALLOWLIST / DNS_ALLOWLIST_SUFFIXES now live in src.data.threat_intel so the aggregator's B1
# co-occurrence pass shares the same benign-infra definition.

# A domain is only "high" when its longest label is BOTH long AND high-entropy.
DNS_SUSPICIOUS_MIN_LABEL_LEN = 12
DNS_SUSPICIOUS_ENTROPY = 3.8

# DNS qtype codes → record names (4.3-r): qry.type in the artifact_id keeps A and HTTPS lookups for
# the same domain/instant from collapsing onto one id.
DNS_QTYPE_NAMES = {
    "1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "12": "PTR", "15": "MX",
    "16": "TXT", "28": "AAAA", "33": "SRV", "43": "DS", "48": "DNSKEY",
    "65": "HTTPS", "257": "CAA",
}

def _epoch_to_iso(epoch: str) -> str:
    """frame.time_epoch float → readable ISO-8601 UTC for the timestamp field; raw epochs stay
    inside artifact_ids (no id churn). Unparseable input is returned unchanged."""
    try:
        dt = datetime.fromtimestamp(float(epoch), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return epoch or ""
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


class TsharkWrapper(BaseWrapper):
    consumes = "pcap"

    def __init__(self):
        super().__init__("tshark")

    def run(self, pcap_path: str) -> list:
        if not os.path.exists(pcap_path):
            print(f"  [ERROR] PCAP not found: {pcap_path}")
            return []

        all_items = []
        all_items.extend(self._get_conversations(pcap_path))
        all_items.extend(self._get_dns_queries(pcap_path))
        all_items.extend(self._get_http_requests(pcap_path))
        all_items.extend(self._get_http_bodies(pcap_path))
        all_items.extend(self._get_host_identities(pcap_path))
        all_items.extend(self._get_suspicious_ports(pcap_path))
        all_items.extend(self._get_beacon_patterns(pcap_path))
        all_items.extend(self._get_transferred_files(pcap_path))
        return all_items

    def _get_transferred_files(self, pcap_path: str) -> list:
        """Recover the actual files carried over HTTP/SMB — data exfiltration and malware delivery
        both move real files, and http.file_data string-sweeping (_get_http_bodies) never
        reconstructs them since it explicitly skips binary content. tshark's own --export-objects
        carves each transferred object out to disk exactly as the client/server exchanged it.

        A repeated request/response (a scanner probing the same endpoint, a heartbeat body) can
        export the byte-identical object dozens of times; those are grouped by content hash into
        one item with an observation count instead of one near-duplicate finding per instance."""
        print("  [TSHARK] Extracting transferred files...")
        # (protocol, sha256) -> {fname, size, protocol, count}
        by_hash: dict[tuple, dict] = {}
        for protocol in ("http", "smb"):
            out_dir = tempfile.mkdtemp(prefix=f"tshark_objects_{protocol}_")
            try:
                _, _, code = self.run_command([
                    "tshark", "-r", pcap_path,
                    "--export-objects", f"{protocol},{out_dir}",
                ], input_files=[pcap_path], timeout=120)
                if code != 0:
                    continue
                for fname in sorted(os.listdir(out_dir)):
                    fpath = os.path.join(out_dir, fname)
                    if not os.path.isfile(fpath):
                        continue
                    size = os.path.getsize(fpath)
                    with open(fpath, "rb") as f:
                        sha256 = hashlib.sha256(f.read()).hexdigest()
                    key = (protocol, sha256)
                    rec = by_hash.get(key)
                    if rec is None:
                        by_hash[key] = {"fname": fname, "size": size,
                                        "protocol": protocol, "sha256": sha256, "count": 1}
                    else:
                        rec["count"] += 1
            finally:
                shutil.rmtree(out_dir, ignore_errors=True)

        items = [self._transferred_file_item(rec) for rec in by_hash.values()]
        print(f"  [TSHARK] Transferred files → {len(items)} distinct file(s) recovered")
        return items

    def _transferred_file_item(self, rec: dict) -> dict:
        fname, size, protocol, sha256, count = (
            rec["fname"], rec["size"], rec["protocol"], rec["sha256"], rec["count"]
        )
        ext = os.path.splitext(fname)[1].lower()

        if ext in RANSOM_EXTENSIONS:
            severity, confidence = "critical", 0.90
        elif ext in EXECUTABLE_EXTENSIONS:
            severity, confidence = "high", 0.85
        else:
            severity, confidence = "medium", 0.60

        seen = f", seen {count}x" if count > 1 else ""
        return self.make_evidence_item(
            artifact_id=stable_artifact_id("transferred_file", protocol, sha256),
            evidence_type="transferred_file",
            value=(
                f"File transferred via {protocol.upper()}: {fname} "
                f"({size:,} bytes, SHA256 {sha256[:16]}…{seen})"
            ),
            severity=severity,
            confidence=confidence,
        )

    def _get_beacon_patterns(self, pcap_path: str) -> list:
        """Catalog-free C2 heuristic (BUGS 2.3): flag flows whose TCP session initiations (bare
        SYNs) recur at a steady interval. Loopback never left the machine (1.2b) and is skipped;
        a LAN destination stays low (agent heartbeats), a public one is medium."""
        print("  [TSHARK] Checking beacon cadence...")
        stdout, _, code = self.run_command([
            "tshark", "-r", pcap_path,
            "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.dstport",
        ], input_files=[pcap_path], timeout=120)

        items = []
        if code != 0 or not stdout.strip():
            return items

        flows = {}
        for line in stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) < 4 or not parts[1] or not parts[2]:
                continue
            try:
                ts = float(parts[0])
            except ValueError:
                continue
            flows.setdefault((parts[1], parts[2], parts[3]), []).append(ts)

        for (src, dst, dport), stamps in flows.items():
            if len(stamps) < BEACON_MIN_COUNT or dst.startswith("127."):
                continue
            stamps.sort()
            deltas = [b - a for a, b in zip(stamps, stamps[1:])]
            mean = statistics.mean(deltas)
            if not BEACON_MIN_INTERVAL_S <= mean <= BEACON_MAX_INTERVAL_S:
                continue
            cv = statistics.pstdev(deltas) / mean
            if cv >= BEACON_MAX_CV:
                continue
            items.append(self.make_evidence_item(
                artifact_id=stable_artifact_id("beacon", src, dst, dport),
                evidence_type="beacon_pattern",
                value=(
                    f"Beacon pattern: {src} → {dst}:{dport} — {len(stamps)} connections "
                    f"every ~{mean:.0f}s (cv={cv:.2f})"
                ),
                severity="low" if is_lan_ipv4(dst) else "medium",
                confidence=0.70,
                timestamp=_epoch_to_iso(str(stamps[0])),
            ))
        print(f"  [TSHARK] Beacon cadence → {len(items)} flow(s)")
        return items

    def _get_conversations(self, pcap_path: str) -> list:
        print("  [TSHARK] Extracting conversations...")
        stdout, _, code = self.run_command([
            "tshark", "-r", pcap_path,
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.dstport",
            "-e", "frame.len",
            "-e", "frame.time_epoch",
            "-Y", "tcp"
        ], input_files=[pcap_path], timeout=120)

        items = []
        if code != 0 or not stdout.strip():
            return items
        # Aggregate bytes/packets per (src,dst,dport) to derive totals for heuristics
        aggregates = {}
        for line in stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            try:
                src = parts[0]
                dst = parts[1]
                dport = parts[2]
                length = int(parts[3]) if parts[3].isdigit() else 0
                timestamp = float(parts[4]) if len(parts) > 4 and parts[4] else None
                key = (src, dst, dport)
                agg = aggregates.setdefault(key, {"bytes": 0, "packets": 0, "first_ts": None})
                agg["bytes"] += length
                agg["packets"] += 1
                if timestamp is not None:
                    if agg["first_ts"] is None or timestamp < agg["first_ts"]:
                        agg["first_ts"] = timestamp
            except Exception:
                continue

        for (src, dst, dport), agg in aggregates.items():
            try:
                port = int(dport) if dport.isdigit() else 0
                # Tiered C2-port severity (issue D1): high-confidence -> high, dual-use watch port
                # -> medium, otherwise low.
                severity = c2_port_severity(port) or "low"
                ts = str(agg["first_ts"]) if agg.get("first_ts") is not None else ""
                items.append(self.make_evidence_item(
                    artifact_id=(
		        f"conn_"
                        f"{src.replace('.','_')}_"
                        f"{dst.replace('.','_')}_"
                        f"{dport}_"
                        f"{ts or 'notime'}"
                   ),
                    evidence_type="network_connection",
                    value=f"TCP {src} → {dst}:{dport} ({agg['bytes']} bytes, {agg['packets']} packets)",
                    severity=severity,
                    confidence=0.75,
                    timestamp=_epoch_to_iso(ts)
                ))
            except Exception:
                continue

        # a large upload-dominant transfer from a LAN host to a non-LAN peer flags on volume/asymmetry alone 
        direction_bytes = {}
        for (src, dst, _dport), agg in aggregates.items():
            direction_bytes[(src, dst)] = direction_bytes.get((src, dst), 0) + agg["bytes"]
        for (src, dst), sent in direction_bytes.items():
            if sent < EXFIL_MIN_UPLOAD_BYTES:
                continue
            if not is_lan_ipv4(src) or is_lan_ipv4(dst) or dst.startswith("127."):
                continue
            received = direction_bytes.get((dst, src), 0)
            if sent < EXFIL_MIN_ASYMMETRY * max(received, 1):
                continue
            items.append(self.make_evidence_item(
                artifact_id=stable_artifact_id("volanom", src, dst),
                evidence_type="volume_anomaly",
                value=(
                    f"Upload-volume anomaly: {src} sent {sent:,} bytes to {dst} "
                    f"(received {received:,})"
                ),
                severity="medium",
                confidence=0.65,
            ))

        print(f"  [TSHARK] Conversations → {len(items)} items")
        return items

    def _get_dns_queries(self, pcap_path: str) -> list:
        print("  [TSHARK] Extracting DNS queries...")
        stdout, _, code = self.run_command([
            "tshark", "-r", pcap_path,
            "-Y", "dns.flags.response == 0",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "dns.qry.name",
            "-e", "dns.qry.type"
        ], input_files=[pcap_path], timeout=60)

        items = []
        if code != 0 or not stdout.strip():
            return items

        for line in stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            timestamp, src, domain = parts[0], parts[1], parts[2].lower()
            if not domain:
                continue
            # qry.type disambiguates A vs AAAA vs HTTPS lookups for the same domain at the same
            # instant (4.3-r). tshark joins multi-question packets with commas; take the first code
            # for the id/label.
            qtype = parts[3].split(",")[0].strip() if len(parts) > 3 else ""
            qtype_name = DNS_QTYPE_NAMES.get(qtype, qtype or "?")
            # High only when the longest label is long AND high-entropy AND not allowlisted;
            # everything else is low.
            label = self._dns_longest_label(domain)
            entropy = self._string_entropy(label)
            looks_random = (
                len(label) >= DNS_SUSPICIOUS_MIN_LABEL_LEN
                and entropy >= DNS_SUSPICIOUS_ENTROPY
            )
            severity = "high" if looks_random and not self._dns_is_allowlisted(domain) else "low"
            items.append(self.make_evidence_item(
                artifact_id=(
                    f"dns_"
                    f"{src.replace('.','_')}_"
                    f"{domain.replace('.','_')[:30]}_"
                    f"{qtype_name}_"
                    f"{timestamp}"
                ),
                evidence_type="dns_query",
                value=f"DNS {qtype_name} query from {src} → {domain} (label entropy: {entropy:.2f})",
                severity=severity,
                confidence=0.80,
                timestamp=_epoch_to_iso(timestamp)
            ))
        print(f"  [TSHARK] DNS queries → {len(items)} items")
        return items

    def _get_http_requests(self, pcap_path: str) -> list:
        print("  [TSHARK] Extracting HTTP requests...")
        stdout, _, code = self.run_command([
            "tshark", "-r", pcap_path,
            "-Y", "http.request",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "http.host",
            "-e", "http.request.uri",
            "-e", "http.user_agent"
        ], input_files=[pcap_path], timeout=60)

        items = []
        if code != 0 or not stdout.strip():
            return items

        for line in stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            timestamp = parts[0]
            src  = parts[1]
            host = parts[2] if len(parts) > 2 else ""
            uri  = parts[3] if len(parts) > 3 else ""
            user_agent = parts[4] if len(parts) > 4 else ""

            # surface non-browser UA on outbound HTTP in the value and raise severity (B2). Loopback never left the machine 
            suspicious_ua = not src.startswith("127.") and any(
                tok in user_agent.lower() for tok in SUSPICIOUS_USER_AGENTS
            )
            value = f"HTTP {src} → {host}{uri}"
            if user_agent:
                value += f" [UA: {user_agent}]"

            items.append(self.make_evidence_item(
                artifact_id=(
                    f"http_"
                    f"{src.replace('.','_')}_"
                    f"{host[:20]}_"
                    f"{hashlib.md5(uri.encode()).hexdigest()[:8]}_"
                    f"{timestamp}"
                ),
                evidence_type="http_request",
                value=value,
                severity="high" if suspicious_ua else "medium",
                confidence=0.70,
                timestamp=_epoch_to_iso(timestamp)
            ))
        print(f"  [TSHARK] HTTP requests → {len(items)} items")
        return items

    def _get_http_bodies(self, pcap_path: str) -> list:
        """Inspect text HTTP bodies for embedded C2 indicators (bot ids / C2 URLs live in bodies,
        invisible to header-only parsing — B3)."""
        print("  [TSHARK] Inspecting HTTP bodies...")
        stdout, _, code = self.run_command([
            "tshark", "-r", pcap_path,
            "-Y", "http.file_data",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "http.content_type",
            "-e", "http.request.uri",
            "-e", "http.file_data"
        ], input_files=[pcap_path], timeout=60)

        items = []
        if code != 0 or not stdout.strip():
            return items

        for line in stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) < 6:
                continue
            timestamp, src, dst, ctype, uri, hexdata = parts[:6]
            if not hexdata:
                continue
            # Text bodies only — skip the multipart exfil upload and other binary.
            if not any(t in ctype.lower() for t in BODY_TEXT_CONTENT_TYPES):
                continue
            try:
                raw = bytes.fromhex(hexdata.replace(":", ""))
            except ValueError:
                continue
            text = raw[:BODY_MAX_BYTES].decode("utf-8", "ignore")

            urls = list(dict.fromkeys(_BODY_URL_RE.findall(text)))
            ids = list(dict.fromkeys(_BODY_HEXID_RE.findall(text)))
            # No embedded URL or long token → heartbeat/fingerprint, not worth an item.
            if not urls and not ids:
                continue

            indicators = []
            if urls:
                indicators.append("url=" + ", ".join(urls)[:200])
            if ids:
                indicators.append("id=" + ", ".join(ids)[:120])

            items.append(self.make_evidence_item(
                artifact_id=(
                    f"httpbody_"
                    f"{src.replace('.','_')}_"
                    f"{dst.replace('.','_')}_"
                    f"{hashlib.md5((uri + text).encode()).hexdigest()[:8]}_"
                    f"{timestamp}"
                ),
                evidence_type="http_body",
                value=f"HTTP body {src} → {dst}{uri} [{'; '.join(indicators)}]",
                severity="high" if urls else "medium",
                confidence=0.75,
                timestamp=_epoch_to_iso(timestamp)
            ))
        print(f"  [TSHARK] HTTP bodies → {len(items)} indicator item(s)")
        return items

    def _get_host_identities(self, pcap_path: str) -> list:
        """Map internal (RFC1918) hosts to their MAC address, so the victim's hardware identity
        is surfaced alongside its IP (issue B4)."""
        print("  [TSHARK] Extracting host identities (IP → MAC)...")
        stdout, _, code = self.run_command([
            "tshark", "-r", pcap_path,
            "-Y", "eth.src and ip.src",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "eth.src"
        ], input_files=[pcap_path], timeout=60)

        items = []
        if code != 0 or not stdout.strip():
            return items

        macs = {}       # internal ip -> (mac, first_timestamp), first seen wins
        for line in stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            timestamp = parts[0]
            # tshark may emit multiple ip.src values (comma-joined); take the first LAN address.
            # eth.src is a single source MAC.
            ip = next((t for t in parts[1].split(",") if is_lan_ipv4(t)), "")
            mac = parts[2].split(",")[0]
            if not ip or not mac or ip in macs:
                continue
            macs[ip] = (mac, timestamp)

        for ip, (mac, timestamp) in macs.items():
            items.append(self.make_evidence_item(
                artifact_id=f"hostid_{ip.replace('.','_')}_{mac.replace(':','')}",
                evidence_type="host_identity",
                value=f"Host {ip} has MAC {mac}",
                severity="low",
                confidence=0.90,
                timestamp=_epoch_to_iso(timestamp)
            ))
        print(f"  [TSHARK] Host identities → {len(items)} item(s)")
        return items

    def _get_suspicious_ports(self, pcap_path: str) -> list:
        print("  [TSHARK] Checking suspicious ports...")
        # One combined-filter pass; was one full pcap read per port (12 scans). The reconciler
        # counts suspicious_port as a data_exfiltration signature type, so the items stay.
        port_set = ", ".join(str(p) for p in sorted(C2_PORTS_ALL))
        stdout, _, code = self.run_command([
            "tshark", "-r", pcap_path,
            "-Y", f"tcp.dstport in {{{port_set}}}",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.dstport"
        ], input_files=[pcap_path], timeout=30)

        items = []
        if code == 0 and stdout.strip():
            # Group packets by destination port, keeping first-seen order within each.
            by_port: dict[int, list[list[str]]] = {}
            for line in stdout.strip().splitlines():
                fields = line.split("\t")
                try:
                    port = int(fields[3])
                except (IndexError, ValueError):
                    continue
                by_port.setdefault(port, []).append(fields)

            for port in sorted(by_port):
                lines = by_port[port]
                first = lines[0]
                timestamp = first[0] if first else ""
                src = first[1] if len(first) > 1 else "unknown"
                dst = first[2] if len(first) > 2 else "unknown"
                # High-confidence C2 port -> high; dual-use watch port -> medium.
                items.append(self.make_evidence_item(
                    artifact_id=f"suspport_{port}",
                    evidence_type="suspicious_port",
                    value=f"Traffic on suspicious port {port}: {src} → {dst} ({len(lines)} packets)",
                    severity=c2_port_severity(port),
                    confidence=0.88,
                    timestamp=_epoch_to_iso(timestamp)
                ))
        print(f"  [TSHARK] Suspicious ports → {len(items)} items")
        return items

    def _dns_is_allowlisted(self, domain: str) -> bool:
        return is_allowlisted_dns(domain)

    def _dns_longest_label(self, domain: str) -> str:
        # Ignore the TLD; score the most-significant remaining label.
        labels = [l for l in domain.split(".") if l]
        if len(labels) > 1:
            labels = labels[:-1]            # drop TLD
        return max(labels, key=len) if labels else ""

    def _string_entropy(self, s: str) -> float:
        if not s:
            return 0
        counts = Counter(s)
        total = len(s)
        return -sum((c/total) * math.log2(c/total) for c in counts.values())


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m src.wrappers.tshark_wrapper <capture.pcap>")
        sys.exit(1)
    wrapper = TsharkWrapper()
    items = wrapper.run(sys.argv[1])
    output = {"tool": "tshark", "items": items}
    os.makedirs("output/raw", exist_ok=True)
    with open("output/raw/tshark_output.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n[DONE] {len(items)} evidence items saved to output/raw/tshark_output.json")
