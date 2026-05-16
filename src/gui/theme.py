# AutoForensiq GUI — colour palette and typography constants.

DARK_BG       = "#0d1117"
CARD_BG       = "#161b22"
ACCENT        = "#7c6af5"
ACCENT_DIM    = "#3d3580"
ACCENT_HOVER  = "#9b8cf7"
SUCCESS       = "#3fb950"
DANGER        = "#f85149"
WARNING       = "#d29922"
TEXT_PRIMARY  = "#e6edf3"
TEXT_SECONDARY = "#8b949e"
TEXT_MUTED    = "#484f58"
BORDER        = "#30363d"
INPUT_BG      = "#010409"
ROW_BG        = "#1a1f2b"

FONT_FAMILY = "Segoe UI"

ARTIFACT_BADGES: dict[str, dict] = {
    "memory_dump":     {"bg": "#1c3a5e", "fg": "#58a6ff", "label": "Memory Dump"},
    "pcap":            {"bg": "#173a28", "fg": "#3fb950", "label": "PCAP"},
    "disk_image":      {"bg": "#3a2a1c", "fg": "#d29922", "label": "Disk Image"},
    "registry_hive":   {"bg": "#3a1c2a", "fg": "#f778ba", "label": "Registry Hive"},
    "log_files":       {"bg": "#2a1c3a", "fg": "#bc8cff", "label": "Log Files"},
    "email_archive":   {"bg": "#3a3a1c", "fg": "#e3b341", "label": "Email Archive"},
    "browser_history": {"bg": "#1c3a3a", "fg": "#39d0d8", "label": "Browser History"},
    "unknown":         {"bg": "#2d2d2d", "fg": "#8b949e", "label": "Unknown"},
}
