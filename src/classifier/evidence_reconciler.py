"""Evidence ↔ Narrative Reconciler (1.1): runs after P4 and checks whether the recovered evidence
supports the narrative case_type. Lower-only — adds a separate reconciled_confidence
(classifier_confidence stays untouched for the audit trail) and raises
narrative_evidence_divergence when support is weak. Support = fraction of the case_type's
corroborating evidence-type categories present in the unified evidence."""

# Evidence types whose presence corroborates each case_type — deliberately broad (a corroboration
# signal, not a re-classifier). NB the tool vocabulary is split (volatility emits registry_key/…,
# regripper/email emit registry_entry/ phishing_email), so signatures list both spellings.
_CASE_TYPE_SIGNATURES = {
    "ransomware": {
        "suspicious_crypto", "file_artifact", "extracted_file",
        "suspicious_domain", "registry_key", "registry_entry", "ioc",
    },
    "malware_infection": {
        "injected_code", "malfind", "process", "process_relation",
        "suspicious_domain", "ioc",
    },
    "apt_intrusion": {
        "injected_code", "malfind", "network_connection", "process_relation",
        "registry_key", "registry_entry", "suspicious_domain", "ioc",
    },
    "data_exfiltration": {
        "network_connection", "http_request", "dns_query",
        "suspicious_port", "ioc",
    },
    "phishing": {
        "phishing_email", "email_address", "suspicious_url",
        "suspicious_domain", "dns_query",
    },
    "insider_threat": {
        "file_artifact", "extracted_file", "registry_key", "registry_entry",
        "timeline_event", "commandline",
    },
}

# Support at/above this fraction keeps the classifier's confidence; below it the divergence flag is
# raised and confidence is lowered proportionally.
_DIVERGENCE_THRESHOLD = 0.5

# When diverged, reconciled confidence interpolates over [floor, 1.0] of the original as support
# runs 0 → threshold, so zero support halves confidence.
_NO_SUPPORT_FLOOR = 0.5


def _present_evidence_types(unified_evidence: dict) -> set:
    """Evidence types that actually carry at least one item."""
    by_type = unified_evidence.get("evidence_by_type") or {}
    evidence_items = unified_evidence.get("evidence_items", [])
    present = {etype for etype, items in by_type.items() if items}
    if not present:
        # Fall back to scanning items if the index isn't populated.
        present = {
            item.get("evidence_type", "")
            for item in evidence_items
            if item.get("evidence_type")
        }
    # "ioc" counts as present whenever any item is ioc_match-tagged — it's an annotation, not a
    # distinct evidence_type (B5: was always reported absent).
    if any(item.get("ioc_match") for item in evidence_items):
        present.add("ioc")
    return present


def _support_score(case_type: str, present: set):
    """Return (score in [0,1], supporting types, expected-but-absent types).

    Score is the fraction of the case_type's corroborating categories present.
    A case_type with no signature (e.g. "unknown") returns (None, [], []) — it
    can't be reconciled, so confidence is left as-is.
    """
    expected = _CASE_TYPE_SIGNATURES.get(case_type)
    if not expected:
        return None, [], []

    supporting = sorted(expected & present)
    absent = sorted(expected - present)
    score = len(supporting) / len(expected)
    return score, supporting, absent


def reconcile_evidence(case_context: dict, unified_evidence: dict) -> dict:
    """Reconcile the narrative classification against the aggregated evidence.

    Returns an `evidence_reconciliation` block. Pure function — does not mutate
    its inputs; the caller decides what to attach/persist.
    """
    case_type = case_context.get("case_type", "unknown")
    classifier_confidence = float(case_context.get("classifier_confidence", 0.0) or 0.0)

    present = _present_evidence_types(unified_evidence)
    total_items = unified_evidence.get("total_items", len(unified_evidence.get("evidence_items", [])))

    claimed = (
        case_context.get("artifact_types_claimed")
        or case_context.get("artifact_types")
        or []
    )

    block = {
        "narrative_case_type": case_type,
        "classifier_confidence": round(classifier_confidence, 2),
        "reconciled_confidence": round(classifier_confidence, 2),
        "evidence_support_score": None,
        "narrative_evidence_divergence": False,
        "supporting_evidence_types": [],
        "expected_but_absent": [],
        "artifact_types_claimed": list(claimed),
        "evidence_suggests": None,
        "notes": [],
    }

    # Nothing recovered, or an un-scorable case_type → can't reconcile.
    if not present or total_items == 0:
        block["notes"].append(
            "No analysable evidence was recovered; confidence left unreconciled."
        )
        return block

    score, supporting, absent = _support_score(case_type, present)

    if score is None:
        block["notes"].append(
            f"case_type '{case_type}' has no evidence signature; "
            "confidence left unreconciled."
        )
        return block

    divergence = score < _DIVERGENCE_THRESHOLD

    if divergence:
        # Lower proportionally to how far below the support threshold we are
        factor = _NO_SUPPORT_FLOOR + (1.0 - _NO_SUPPORT_FLOOR) * (score / _DIVERGENCE_THRESHOLD)
        reconciled = round(classifier_confidence * factor, 2)
    else:
        # Adequately corroborated → keep the classifier's confidence as-is.
        reconciled = round(classifier_confidence, 2)

    block["evidence_support_score"] = round(score, 2)
    block["reconciled_confidence"] = reconciled
    block["narrative_evidence_divergence"] = divergence
    block["supporting_evidence_types"] = supporting
    block["expected_but_absent"] = absent

    # Informational: does the evidence corroborate some other case_type more strongly? We surface it
    # but never overwrite case_type here (out of scope — that would re-route MITRE /
    # recommendations).
    best_other, best_other_score = None, score
    for other_type in _CASE_TYPE_SIGNATURES:
        if other_type == case_type:
            continue
        other_score, _, _ = _support_score(other_type, present)
        if other_score is not None and other_score > best_other_score + 0.25:
            best_other, best_other_score = other_type, other_score
    if best_other:
        block["evidence_suggests"] = best_other

    # Human-readable summary lines for the report / audit trail.
    if supporting:
        block["notes"].append(
            "Evidence corroborates the narrative via: " + ", ".join(supporting) + "."
        )
    if divergence:
        block["notes"].append(
            f"Evidence weakly supports a '{case_type}' classification "
            f"(support {score:.0%}); confidence lowered "
            f"{classifier_confidence:.0%} → {reconciled:.0%}."
        )
        if absent:
            block["notes"].append(
                "Expected but absent: " + ", ".join(absent) + "."
            )
    if best_other:
        block["notes"].append(
            f"Recovered evidence aligns more strongly with '{best_other}'."
        )

    return block
