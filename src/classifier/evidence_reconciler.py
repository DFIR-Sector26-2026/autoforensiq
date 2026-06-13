"""
AutoForensiq — Evidence ↔ Narrative Reconciler (issue 1.1)
===========================================================
The P1 intent classifier scores `case_type` and `classifier_confidence` purely
from the incident-report narrative; it never sees the artifacts P3/P4 actually
recover. This module runs *after* aggregation (P4) and reconciles that narrative
classification against the real evidence, so a confident-but-unsupported
classification is no longer carried downstream unchallenged.

Design (per the issue's "at minimum, lower confidence" fix, and the chosen
conservative direction):
  - The classifier's self-reported `classifier_confidence` is left untouched
    (audit trail). We add a separate `reconciled_confidence`.
  - Reconciliation is **lower-only**: strong evidence support leaves confidence
    unchanged; weak/absent support lowers it. It never inflates confidence.
  - A `narrative_evidence_divergence` flag is raised when the evidence fails to
    substantively support the narrative case_type (or points elsewhere).

Heuristic, in keeping with the rest of the pipeline: each case_type maps to the
evidence-type categories whose presence would corroborate it; the support score
is the fraction of those categories present in the unified evidence.
"""

# Evidence-type categories whose presence corroborates each case_type. Keys are
# the schema case_type enum; values are evidence_type values emitted by the P3
# wrappers / IOC engine (see unified_evidence). Kept deliberately broad — this is
# a corroboration signal, not a re-classifier.
# NB the vocabulary is split: the memory-string extractor (volatility_wrapper)
# emits registry_key / suspicious_crypto / suspicious_domain / email_address,
# while regripper/email wrappers emit registry_entry / phishing_email. Signatures
# list both spellings so reconciliation works regardless of the producing tool.
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

# At or above this fraction of corroborating categories present, the evidence is
# judged to substantively support the narrative case_type: confidence is kept as
# the classifier reported it. Below it, the divergence flag is raised and
# confidence is lowered proportionally.
_DIVERGENCE_THRESHOLD = 0.5

# When diverged, reconciled confidence interpolates over [floor, 1.0] of the
# original as support runs 0 → threshold, so zero support halves confidence.
_NO_SUPPORT_FLOOR = 0.5


def _present_evidence_types(unified_evidence: dict) -> set:
    """Evidence types that actually carry at least one item."""
    by_type = unified_evidence.get("evidence_by_type") or {}
    present = {etype for etype, items in by_type.items() if items}
    if present:
        return present
    # Fall back to scanning items if the index isn't populated.
    return {
        item.get("evidence_type", "")
        for item in unified_evidence.get("evidence_items", [])
        if item.get("evidence_type")
    }


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
        # Lower proportionally to how far below the support threshold we are.
        factor = _NO_SUPPORT_FLOOR + (1.0 - _NO_SUPPORT_FLOOR) * (score / _DIVERGENCE_THRESHOLD)
        reconciled = round(classifier_confidence * factor, 2)
    else:
        # Adequately corroborated → keep the classifier's confidence as-is.
        reconciled = round(classifier_confidence, 2)
    # Lower-only: never inflate the classifier's self-reported confidence.
    reconciled = min(reconciled, round(classifier_confidence, 2))

    block["evidence_support_score"] = round(score, 2)
    block["reconciled_confidence"] = reconciled
    block["narrative_evidence_divergence"] = divergence
    block["supporting_evidence_types"] = supporting
    block["expected_but_absent"] = absent

    # Informational: does the evidence corroborate some other case_type more
    # strongly? We surface it but never overwrite case_type here (out of scope —
    # that would re-route MITRE / recommendations).
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
