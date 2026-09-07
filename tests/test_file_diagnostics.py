"""Tests for the per-evidence-file sanity checks run before a wrapper is invoked."""

from src.utils.file_diagnostics import diagnose_evidence_file


def test_empty_file_is_flagged(tmp_path):
    p = tmp_path / "memory.dmp"
    p.write_bytes(b"")
    diagnosis = diagnose_evidence_file(str(p), "memory_dump")
    assert diagnosis is not None
    assert "empty" in diagnosis.lower()


def test_valid_pcap_header_passes(tmp_path):
    p = tmp_path / "capture.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
    assert diagnose_evidence_file(str(p), "pcap") is None


def test_pcap_with_wrong_header_is_flagged(tmp_path):
    p = tmp_path / "capture.pcap"
    p.write_bytes(b"not a pcap file at all, just text padding here")
    diagnosis = diagnose_evidence_file(str(p), "pcap")
    assert diagnosis is not None
    assert "header" in diagnosis.lower()


def test_valid_registry_hive_header_passes(tmp_path):
    p = tmp_path / "NTUSER.DAT"
    p.write_bytes(b"regf" + b"\x00" * 100)
    assert diagnose_evidence_file(str(p), "registry_hive") is None


def test_registry_hive_missing_regf_signature_is_flagged(tmp_path):
    p = tmp_path / "NTUSER.DAT"
    p.write_bytes(b"not a real hive" + b"\x00" * 100)
    diagnosis = diagnose_evidence_file(str(p), "registry_hive")
    assert diagnosis is not None
    assert "header" in diagnosis.lower()


def test_tiny_memory_dump_below_plausible_size_is_flagged(tmp_path):
    p = tmp_path / "memory.dmp"
    p.write_bytes(b"\x00" * 100)  # far below the plausible-size floor
    diagnosis = diagnose_evidence_file(str(p), "memory_dump")
    assert diagnosis is not None
    assert "too small" in diagnosis.lower()


def test_evidence_type_with_no_checks_is_never_flagged(tmp_path):
    p = tmp_path / "history.txt"
    p.write_bytes(b"http://example.com\n")
    assert diagnose_evidence_file(str(p), "browser") is None


def test_valid_raw_disk_image_with_no_e01_signature_is_not_flagged(tmp_path):
    # Raw .img/.dd disk images have no fixed header at all - an NTFS/FAT partition table can start
    # with almost any bytes. A real, mmls/fls-verified-valid raw image was previously flagged as
    # "invalid header" here because the check only recognised the E01/EWF signature. Size is the
    # only universal check for this type; a plausibly-sized raw image must pass cleanly.
    p = tmp_path / "disk.img"
    p.write_bytes(b"\xeb\x52\x90NTFS    " + b"\x00" * 2_000_000)  # plausible size, no E01 magic
    assert diagnose_evidence_file(str(p), "disk_image") is None


def test_tiny_disk_image_below_plausible_size_is_still_flagged(tmp_path):
    p = tmp_path / "disk.img"
    p.write_bytes(b"\x00" * 100)
    diagnosis = diagnose_evidence_file(str(p), "disk_image")
    assert diagnosis is not None
    assert "too small" in diagnosis.lower()
