from src.classifier.intent_classifier import classify, validate_case_context

# A report that name-drops every artifact type, so the narrative-only classifier
# would otherwise emit the full over-broad artifact_types dump (issue 1.2).
_REPORT_ALL = (
    "Ransomware encrypted files and demanded bitcoin. Collected a memory dump, "
    "a disk image, a pcap network capture, the registry hive, the windows event "
    "log, an email pst export, and browser history."
)

_MOCK = {"llm": {"mock_mode": True}}


def test_affected_systems_excludes_report_headers():
    # Issue B5: all-caps report headings (INCIDENT, REPORT, TIMELINE) and the
    # long dashed case id must not be mistaken for hostnames; a real machine name
    # (carries a digit/hyphen, <= 15 NetBIOS chars) and IPs are kept.
    report = ("INCIDENT REPORT SUMMARY TIMELINE - case SYN-2026-0615-RANSOM. "
              "Host WIN-VICTIM-22 at 10.10.14.22 was encrypted.")
    aff = classify(report, config_override=_MOCK)["affected_systems"]
    assert "10.10.14.22" in aff
    assert "WIN-VICTIM-22" in aff
    for noise in ("INCIDENT", "REPORT", "SUMMARY", "TIMELINE", "SYN-2026-0615-RANSOM"):
        assert noise not in aff


def test_narrative_lists_all_types_without_provided():
    # Baseline: with no provided evidence, the narrative dump is left untouched
    # and no claimed field is added (backward compatible — standalone / GUI).
    result = classify(_REPORT_ALL, config_override=_MOCK)
    assert len(result["artifact_types"]) == 7
    assert "artifact_types_claimed" not in result


def test_artifact_types_narrowed_to_present():
    # Only a memory dump + pcap were actually supplied → artifact_types collapses
    # to exactly those, narrative claim preserved separately.
    result = classify(
        _REPORT_ALL,
        config_override=_MOCK,
        provided_artifact_types=["pcap", "memory_dump"],
    )
    assert result["artifact_types"] == ["memory_dump", "pcap"]  # canonical order
    assert set(result["artifact_types_claimed"]) == {
        "memory_dump", "disk_image", "pcap", "registry_hive",
        "log_files", "email_archive", "browser_history",
    }
    # Still schema-valid with the new claimed field.
    validate_case_context(result)


def test_unknown_provided_types_are_ignored():
    # Junk types that aren't in the enum can't narrow; narrative is left as-is.
    result = classify(
        _REPORT_ALL,
        config_override=_MOCK,
        provided_artifact_types=["not_a_real_type"],
    )
    assert len(result["artifact_types"]) == 7
    assert "artifact_types_claimed" not in result


def test_insider_threat_sample_report_not_misread_as_data_exfiltration():
    # The bundled insider_threat sample scored an exact tie (3-3) between
    # insider_threat and data_exfiltration ("employee"/"insider" vs.
    # "upload"/"transfer") — data_exfiltration won only because it's declared
    # earlier in _MOCK_KEYWORDS, so max() picked it first on the tie. A
    # resignation-then-USB-exfiltration pattern is a defining insider-threat
    # signal in general, not specific to this one sample, so those keywords
    # were added to break the tie correctly rather than reordering the dict.
    from pathlib import Path
    report_path = Path(__file__).resolve().parents[1] / "tests" / "incidents" / "04_insider_threat.txt"
    report_text = report_path.read_text()
    result = classify(report_text, config_override=_MOCK)
    assert result["case_type"] == "insider_threat"
