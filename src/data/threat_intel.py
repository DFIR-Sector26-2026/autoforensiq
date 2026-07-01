"""Single source of truth for threat-intelligence indicators (issue D1).

The C2 port list used to be hardcoded — and drifted — across four places: the
Volatility and Tshark wrappers (severity), the IOC catalog (rescorer boost), and
the ML feature extractor. A connection to 4445 was "suspicious" to the wrappers
but invisible to the model; 2222/3333/4000 were anomalies to the model but
flagged by nothing else. Centralising the ports here fixes that drift and makes
"add a C2 port" a one-line edit.

Ports are split into two confidence tiers, because they are not equivalent:

  * HIGH  — overwhelmingly malicious, rarely legitimate (Metasploit handlers,
            backdoor/elite ports). A match drives severity "high" in the
            wrappers and a critical floor in the rescorer.
  * WATCH — dual-use: historically abused for C2 but also legitimate (IRC
            6666-6669, alt-HTTP 8888/9999, old NetBus/BO trojans 12345/54321).
            Surfaced at "medium" so the pipeline notes them without screaming
            "high C2" at a Jupyter or IRC connection.

Predominantly-legitimate ports (2222 alt-SSH, 3333, 4000, 5555 ADB, 7777 game
servers) are deliberately excluded from both tiers — too noisy to flag.
"""

# Overwhelmingly malicious, rarely legitimate -> severity "high".
C2_PORTS_HIGH = frozenset({4444, 4445, 1337, 31337})

# Dual-use (legitimate too) -> severity "medium", still surfaced.
C2_PORTS_WATCH = frozenset({6666, 6667, 6668, 6669, 8888, 9999, 12345, 54321})

# Every port worth flagging at all (both tiers). Used as the ML "known C2 port"
# feature, where a port is one signal among fourteen rather than a verdict.
C2_PORTS_ALL = C2_PORTS_HIGH | C2_PORTS_WATCH


# Known-good infrastructure — substring match against the full lowercased
# domain. A random-looking subdomain under one of these (e.g. a hex label under
# cloudfront.net) is still legitimate, so we match the parent. Shared so both the
# tshark wrapper (DNS gating) and the aggregator (issue B1 co-occurrence) agree
# on what counts as benign.
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


def c2_port_severity(port):
    """Return the severity a C2-indicator port warrants, or None if the port is
    not a C2 indicator. `port` may be an int or a digit string."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if port in C2_PORTS_HIGH:
        return "high"
    if port in C2_PORTS_WATCH:
        return "medium"
    return None
