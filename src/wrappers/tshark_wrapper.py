import os
import re
import json
from datetime import datetime, timezone
from src.wrappers.base_wrapper import BaseWrapper
from src.data.threat_intel import (
    C2_PORTS_ALL, c2_port_severity, is_allowlisted_dns, is_lan_ipv4,
)
import hashlib

# Non-browser HTTP User-Agents typical of malware droppers and C2 clients. A scripted UA on outbound
# web traffic is a strong signal (issue B2: the macOS stealer beaconed with curl/8.7.1). Matched
# case-insensitively as substrings.
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
        return all_items

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

            # A non-browser UA on outbound HTTP is a strong automation/malware signal — surface it
            # in the value and raise severity (issue B2).
            suspicious_ua = any(
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
                    severity=c2_port_severity(port) or "high",
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
        import math
        from collections import Counter
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
