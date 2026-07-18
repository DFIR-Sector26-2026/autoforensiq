"""Drift guard for the two hand-maintained extension-routing maps (cross-cutting ⚪ item):
GUI `_EXT_MAP` vs CLI `_map_evidence_files` (.vmem had already drifted when this was added)."""

from autoforensiq import _map_evidence_files, _EVIDENCE_KEY_TO_ARTIFACT_TYPE
from src.gui.launcher import _EXT_MAP

# Every extension either map routes; the union catches an extension added to only one side.
_ALL_EXTS = sorted(set(_EXT_MAP) | {
    ".dmp", ".mem", ".raw", ".vmem", ".pcap", ".pcapng", ".img", ".dd", ".e01",
    ".dmg", ".dat", ".hiv", ".eml", ".msg", ".log", ".evtx",
})


def test_gui_ext_map_agrees_with_cli_evidence_mapping():
    for ext in _ALL_EXTS:
        mapped = _map_evidence_files([f"sample{ext}"])
        assert len(mapped) == 1, f"CLI does not route {ext}"
        cli_key = next(iter(mapped))
        cli_type = _EVIDENCE_KEY_TO_ARTIFACT_TYPE.get(cli_key, cli_key)
        assert _EXT_MAP.get(ext) == cli_type, (
            f"{ext}: GUI badges {_EXT_MAP.get(ext)!r} but the CLI routes it to {cli_type!r} — "
            "sync launcher._EXT_MAP with autoforensiq._map_evidence_files"
        )
