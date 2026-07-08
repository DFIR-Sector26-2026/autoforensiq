"""Single source of truth for threat-intel indicators (D1) — the C2 port list
previously drifted across four hardcoded copies (wrappers, rescorer, ML).

Two port tiers: HIGH = overwhelmingly malicious (Metasploit/backdoor ports);
WATCH = dual-use (IRC, alt-HTTP, old trojans) surfaced at medium. Predominantly
legitimate ports (2222/3333/4000/5555/7777) are deliberately excluded as noise.
"""

# Overwhelmingly malicious, rarely legitimate -> severity "high".
C2_PORTS_HIGH = frozenset({4444, 4445, 1337, 31337})

# Dual-use (legitimate too) -> severity "medium", still surfaced.
C2_PORTS_WATCH = frozenset({6666, 6667, 6668, 6669, 8888, 9999, 12345, 54321})

# Every port worth flagging at all (both tiers). Used as the ML "known C2 port" feature, where a
# port is one signal among fourteen rather than a verdict.
C2_PORTS_ALL = C2_PORTS_HIGH | C2_PORTS_WATCH

# Remote-interactive admin channels (T1021: RDP/VNC/WinRM), the lateral-movement backbone (B-6).
# Dual-use → medium, and only with a real remote peer (every host listens on 3389/5985 itself). SMB
# 445 / LDAP 389 excluded: routine domain traffic.
LATERAL_MOVEMENT_PORTS = frozenset({3389, 5900, 5985, 5986})


# Known-good infrastructure, substring match on the full lowercased domain (a random subdomain under
# cloudfront etc. is still legitimate). Shared by the tshark DNS gating and the aggregator's B1
# co-occurrence pass.
DNS_ALLOWLIST = (
    "apple.com", "icloud.com", "aaplimg.com", "apple-dns.net",
    "apple-cloudkit", "cdn-apple.com", "mzstatic.com",
    "akamai", "akamaized.net", "akadns.net",
    "cloudflare", "fastly", "google", "gstatic", "googleapis", "ggpht",
    "amazonaws", "cloudfront", "azureedge", "microsoft", "windows.com",
    "windowsupdate", "msftncsi", "msftconnecttest", "mshome.net", "mozilla",
    "ubuntu.com", "debian.org", "fedoraproject.org", "digicert", "verisign",
)
# Suffixes that are always local/non-routable noise.
DNS_ALLOWLIST_SUFFIXES = (".local", ".arpa", ".lan", ".internal", ".home")


# Ransomware / encrypted-payload extensions — a strong signal anywhere. One list shared by tsk_fls
# and volatility filescan; tuple so str.endswith() works.
RANSOM_EXTENSIONS = (
    ".wnry", ".wncry", ".wcry", ".wncryt",
    ".locky", ".zepto", ".odin", ".cerber", ".cerber3",
    ".crypt", ".crypto", ".crypted", ".encrypted", ".enc",
    ".locked", ".ecc", ".ezz", ".exx",
    ".ryuk", ".lockbit", ".conti", ".djvu",
)

# Executable / script extensions. NOT flagged on extension alone — see the staging-dir gate in
# tsk_wrapper. Shared with the report's IOC extraction.
EXECUTABLE_EXTENSIONS = (
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".hta", ".scr", ".jar",
)


def is_lan_ipv4(ip: str) -> bool:
    """True for an RFC1918 (LAN) IPv4 address string — the internal hosts. Used to pick the
    affected machine out of a connection and to map hosts to MACs."""
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or any(ip.startswith(f"172.{n}.") for n in range(16, 32))
    )


def c2_port_severity(port):
    """Return the severity a C2-indicator port warrants, or None if the port is not a C2
    indicator. `port` may be an int or a digit string."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if port in C2_PORTS_HIGH:
        return "high"
    if port in C2_PORTS_WATCH:
        return "medium"
    return None
