"""Tool-selector regression tests (issue 2.1).

2.1 was: tool selection keyed off the narrative `artifact_types` dump, not the
evidence files actually provided, so a PCAP-only case still selected
memory/disk/registry tools. It is resolved by the 1.2 narrowing — the classifier
now sets `artifact_types` to exactly the provided evidence types (preserving the
narrative claim under `artifact_types_claimed`), and `select_tools()` keys off
that. These tests lock in file-driven selection end-to-end and at the unit level.
"""

import json
from pathlib import Path

from src.classifier.intent_classifier import classify
from src.agents.tool_selector import select_tools, tool_matches_artifacts

_ONTOLOGY = json.load(
    open(Path(__file__).resolve().parents[1] / "src" / "data" / "tool_ontology.json")
)

# A narrative that claims essentially every artifact type, so an un-narrowed
# selection would pull in every memory/disk/registry/network/email tool.
_KITCHEN_SINK_REPORT = (
    "Ransomware incident. We collected the memory dump, disk image, registry "
    "hives, network capture, and email archive for analysis."
)


def _classify(provided):
    return classify(
        _KITCHEN_SINK_REPORT,
        config_override={"llm": {"mock_mode": True}},
        provided_artifact_types=provided,
    )


def test_pcap_only_selects_only_network_tool():
    # Only a pcap was provided; the narrative still claims everything.
    ctx = _classify(["pcap"])
    assert ctx["artifact_types"] == ["pcap"]
    # The over-broad narrative claim is preserved for the divergence report.
    assert set(ctx["artifact_types_claimed"]) >= {"memory_dump", "registry_hive"}

    selected = {t["name"] for t in select_tools(ctx, _ONTOLOGY)}
    assert selected == {"tshark"}
    # The memory/disk/registry tools the narrative would have pulled in are gone.
    assert "volatility3" not in selected
    assert "regripper" not in selected


def test_memory_only_selects_memory_tools_not_network():
    ctx = _classify(["memory_dump"])
    assert ctx["artifact_types"] == ["memory_dump"]
    selected = {t["name"] for t in select_tools(ctx, _ONTOLOGY)}
    assert "tshark" not in selected
    assert {"volatility3", "memprocfs"} <= selected


def test_multiple_provided_types_select_their_union():
    ctx = _classify(["pcap", "registry_hive"])
    assert ctx["artifact_types"] == ["pcap", "registry_hive"]
    selected = {t["name"] for t in select_tools(ctx, _ONTOLOGY)}
    assert "tshark" in selected and "regripper" in selected
    assert "volatility3" not in selected


def test_tool_matches_artifacts_unit():
    tshark = next(t for t in _ONTOLOGY["tools"] if t["name"] == "tshark")
    assert tool_matches_artifacts(tshark, {"pcap", "memory_dump"}) is True
    assert tool_matches_artifacts(tshark, {"memory_dump"}) is False


# ─────────────────────────────────────────────────────────────
# email / browser tools were missing from the ontology (issue D4)
# ─────────────────────────────────────────────────────────────

def test_ontology_validates_and_includes_email_and_browser():
    # The wrappers exist in orchestrator.WRAPPER_MAP; the ontology + the
    # SUPPORTED_WRAPPER_NAMES allowlist must agree, or validate_ontology raises.
    from src.agents.tool_selector import validate_ontology
    validate_ontology(_ONTOLOGY)  # must not raise
    names = {t["name"] for t in _ONTOLOGY["tools"]}
    assert {"email", "browser"} <= names


def test_email_tool_matches_email_archive_unit():
    email = next(t for t in _ONTOLOGY["tools"] if t["name"] == "email")
    assert tool_matches_artifacts(email, {"email_archive"}) is True
    assert tool_matches_artifacts(email, {"pcap"}) is False


def test_email_archive_case_selects_email_tool():
    # D4 end-to-end at the selector: an email_archive case must select email
    # (previously selected nothing because email was absent from the ontology).
    ctx = _classify(["email_archive"])
    assert ctx["artifact_types"] == ["email_archive"]
    selected = {t["name"] for t in select_tools(ctx, _ONTOLOGY)}
    assert selected == {"email"}


def test_browser_history_case_selects_browser_tool():
    ctx = _classify(["browser_history"])
    selected = {t["name"] for t in select_tools(ctx, _ONTOLOGY)}
    assert selected == {"browser"}
