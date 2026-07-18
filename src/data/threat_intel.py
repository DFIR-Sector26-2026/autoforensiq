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

# Canonical severity ranking (D6) — was independently defined in both aggregator modules and a
# volatility local. The report/ML/JS variants differ semantically and stay separate.
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Remote-interactive admin channels (T1021: RDP/VNC/WinRM), the lateral-movement backbone (B-6).
# Dual-use → medium, and only with a real remote peer (every host listens on 3389/5985 itself). SMB
# 445 / LDAP 389 excluded: routine domain traffic.
LATERAL_MOVEMENT_PORTS = frozenset({3389, 5900, 5985, 5986})


# Known-good infrastructure, exact-or-subdomain match (D7: the old substring rule allowlisted
# lookalikes — "counter-google.com" matched "google"). Shared by the tshark DNS gating and the
# aggregator's B1 co-occurrence pass via is_allowlisted_dns().
DNS_ALLOWLIST = (
    "apple.com", "icloud.com", "aaplimg.com", "apple-dns.net",
    "apple-cloudkit.com", "cdn-apple.com", "mzstatic.com",
    "akamai.net", "akamai.com", "akamaiedge.net", "akamaihd.net",
    "akamaized.net", "akadns.net",
    "cloudflare.com", "cloudflare.net", "cloudflare-dns.com",
    "fastly.net", "fastlylb.net",
    "google.com", "googleusercontent.com", "googlevideo.com", "googlemail.com",
    "gstatic.com", "googleapis.com", "ggpht.com",
    "amazonaws.com", "amazonaws.com.cn", "cloudfront.net", "azureedge.net",
    "microsoft.com", "microsoft.net", "microsoftonline.com", "windows.com",
    "windowsupdate.com", "msftncsi.com", "msftconnecttest.com", "mshome.net",
    "mozilla.org", "mozilla.com", "mozilla.net",
    "ubuntu.com", "debian.org", "fedoraproject.org", "digicert.com", "verisign.com",
)
# Suffixes that are always local/non-routable noise.
DNS_ALLOWLIST_SUFFIXES = (".local", ".arpa", ".lan", ".internal", ".home")


def is_allowlisted_dns(domain: str) -> bool:
    """True when `domain` is one of DNS_ALLOWLIST or a sub-domain of one (lookalike-safe), or ends
    in a local/non-routable suffix."""
    d = domain.lower().rstrip(".")
    return matching_base(d, DNS_ALLOWLIST) is not None or d.endswith(DNS_ALLOWLIST_SUFFIXES)


# Benign infrastructure dropped at source by the volatility string sweep (D3): a dump carries ~22k
# OS/CDN/CA hostnames that flooded the evidence set and P5. Exact-or-subdomain match only
# (lookalike-safe, unlike DNS_ALLOWLIST's substring rule above — D7); reputation still runs on
# whatever survives.
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


def matching_base(host: str, bases) -> str | None:
    """Return the base domain `host` equals or is a sub-domain of, else None. The one
    exact-or-subdomain primitive — lookalikes ("microsoft.com.evil.tld") never match."""
    for base in bases:
        if host == base or host.endswith("." + base):
            return base
    return None


def is_benign_domain(host: str) -> bool:
    """True when `host` equals one of BENIGN_DOMAIN_SUFFIXES or is a sub-domain of one. Host-aware,
    so a lookalike like "microsoft.com.evil.tld" is NOT treated as benign."""
    return matching_base(host.lower().rstrip("."), BENIGN_DOMAIN_SUFFIXES) is not None


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
