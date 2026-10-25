"""_build_evidence_sources (autoforensiq.py) attributes each tool's findings back to the
evidence file(s) it actually consumed. Its predecessor compared a tuple of evidence keys against
evidence_files' plain-string keys, which never matched — evidence_sources was silently empty on
every real run, breaking the "Sources" column in ioc_report.md/final_report.md and the per-file
reports (both read case_context["evidence_sources"])."""

from autoforensiq import _build_evidence_sources


def test_single_key_tool_resolves_its_file():
    evidence_files = {"registry_hive": ["data/test_cases/demo_ntuser_run.dat"]}
    sources = _build_evidence_sources(evidence_files)
    assert sources.get("regripper") == "demo_ntuser_run.dat"


def test_multiple_tools_each_resolve_their_own_file():
    evidence_files = {
        "pcap": ["data/test_cases/capture.pcap"],
        "registry_hive": ["data/test_cases/demo_ntuser_run.dat"],
    }
    sources = _build_evidence_sources(evidence_files)
    assert sources.get("tshark") == "capture.pcap"
    assert sources.get("regripper") == "demo_ntuser_run.dat"


def test_tool_with_no_matching_evidence_is_absent():
    evidence_files = {"pcap": ["data/test_cases/capture.pcap"]}
    sources = _build_evidence_sources(evidence_files)
    assert "regripper" not in sources


def test_multiple_files_for_one_key_are_joined():
    evidence_files = {"memory_dump": ["a.dmp", "b.dmp"]}
    sources = _build_evidence_sources(evidence_files)
    assert sources.get("volatility3") == "a.dmp, b.dmp"


def test_no_evidence_files_returns_empty_sources():
    assert _build_evidence_sources({}) == {}
