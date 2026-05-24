import os
import json
import subprocess
from src.wrappers.base_wrapper import BaseWrapper

SUSPICIOUS_PORTS = [4444, 4445, 1337, 31337, 8888, 9999, 6667, 6668]
SUSPICIOUS_PROTOS = ["dns", "http", "smb", "ftp"]

class TsharkWrapper(BaseWrapper):
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
            if len(parts) < 4:
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
                severity = "high" if port in SUSPICIOUS_PORTS else "low"
                ts = str(agg["first_ts"]) if agg.get("first_ts") is not None else ""
                items.append(self.make_evidence_item(
                    artifact_id=f"conn_{src.replace('.','_')}_{dst.replace('.','_')}_{dport}_{int(agg['first_ts'])}",
                    evidence_type="network_connection",
                    value=f"TCP {src} → {dst}:{dport} ({agg['bytes']} bytes, {agg['packets']} packets)",
                    severity=severity,
                    confidence=0.75,
                    timestamp=ts
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
            "-e", "dns.qry.name"
        ], input_files=[pcap_path], timeout=60)

        items = []
        if code != 0 or not stdout.strip():
            return items

        for line in stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            timestamp, src, domain = parts[0], parts[1], parts[2]
            if not domain:
                continue
            entropy = self._string_entropy(domain)
            severity = "high" if entropy > 3.5 else "low"
            items.append(self.make_evidence_item(
                artifact_id=f"dns_{domain.replace('.','_')[:30]}",
                evidence_type="dns_query",
                value=f"DNS query from {src} → {domain} (entropy: {entropy:.2f})",
                severity=severity,
                confidence=0.80,
                timestamp=timestamp
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
            "-e", "http.request.uri"
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
            items.append(self.make_evidence_item(
                artifact_id=f"http_{src.replace('.','_')}_{host[:20]}",
                evidence_type="http_request",
                value=f"HTTP {src} → {host}{uri}",
                severity="medium",
                confidence=0.70,
                timestamp=timestamp
            ))
        print(f"  [TSHARK] HTTP requests → {len(items)} items")
        return items

    def _get_suspicious_ports(self, pcap_path: str) -> list:
        print("  [TSHARK] Checking suspicious ports...")
        items = []
        for port in SUSPICIOUS_PORTS:
            stdout, _, code = self.run_command([
                "tshark", "-r", pcap_path,
                "-Y", f"tcp.dstport == {port}",
                "-T", "fields",
                "-e", "frame.time_epoch",
                "-e", "ip.src",
                "-e", "ip.dst"
            ], input_files=[pcap_path], timeout=30)

            if code != 0 or not stdout.strip():
                continue
            lines = stdout.strip().splitlines()
            if lines:
                first = lines[0].split("\t")
                timestamp = first[0] if first else ""
                src = first[1] if len(first) > 1 else "unknown"
                dst = first[2] if len(first) > 2 else "unknown"
                items.append(self.make_evidence_item(
                    artifact_id=f"suspport_{port}",
                    evidence_type="suspicious_port",
                    value=f"Traffic on suspicious port {port}: {src} → {dst} ({len(lines)} packets)",
                    severity="high",
                    confidence=0.88,
                    timestamp=timestamp
                ))
        print(f"  [TSHARK] Suspicious ports → {len(items)} items")
        return items

    def _string_entropy(self, s: str) -> float:
        import math
        from collections import Counter
        if not s:
            return 0
        counts = Counter(s)
        total = len(s)
        return -sum((c/total) * math.log2(c/total) for c in counts.values())


if __name__ == "__main__":
    import sys, json
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
