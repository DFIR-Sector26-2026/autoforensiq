import sys


def ensure_utf8_stdio() -> None:
    """Reconfigure stdout/stderr to UTF-8. Windows terminals default to the legacy
    console code page (e.g. cp1252), which can't encode the ✔/✗/→/─ characters used
    throughout the pipeline's console output — every print() then crashes with
    UnicodeEncodeError. Call this once, first, in any standalone entry point."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
