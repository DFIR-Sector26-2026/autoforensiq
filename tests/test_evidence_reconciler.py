from src.classifier.evidence_reconciler import reconcile_evidence


def _unified(types):
    """Build a minimal unified_evidence with one item per given evidence_type."""
    by_type = {t: [{"evidence_type": t, "artifact_id": f"{t}_1"}] for t in types}
    items = [item for group in by_type.values() for item in group]
    return {
        "evidence_by_type": by_type,
        "evidence_items": items,
        "total_items": len(items),
    }


def test_corroborated_narrative_keeps_confidence():
    ctx = {"case_type": "ransomware", "classifier_confidence": 0.9}
    unified = _unified(["suspicious_crypto", "file_artifact", "suspicious_domain", "ioc"])
    block = reconcile_evidence(ctx, unified)
    assert block["narrative_evidence_divergence"] is False
    assert block["reconciled_confidence"] == 0.9
    assert "suspicious_crypto" in block["supporting_evidence_types"]


def test_unsupported_narrative_lowers_confidence_and_flags():
    # Narrative says ransomware, but only network evidence (data_exfiltration
    # shape) was recovered → no ransomware corroboration.
    ctx = {"case_type": "ransomware", "classifier_confidence": 0.9}
    unified = _unified(["network_connection", "http_request", "dns_query"])
    block = reconcile_evidence(ctx, unified)
    assert block["narrative_evidence_divergence"] is True
    assert block["reconciled_confidence"] < 0.9
    assert block["evidence_suggests"] == "data_exfiltration"


def test_reconciliation_never_inflates():
    ctx = {"case_type": "data_exfiltration", "classifier_confidence": 0.4}
    unified = _unified(["network_connection", "http_request", "dns_query", "suspicious_port", "ioc"])
    block = reconcile_evidence(ctx, unified)
    assert block["reconciled_confidence"] <= 0.4


def test_unknown_case_type_is_not_reconciled():
    ctx = {"case_type": "unknown", "classifier_confidence": 0.35}
    unified = _unified(["process", "network_connection"])
    block = reconcile_evidence(ctx, unified)
    assert block["narrative_evidence_divergence"] is False
    assert block["reconciled_confidence"] == 0.35
    assert block["evidence_support_score"] is None


def test_no_evidence_leaves_confidence_unreconciled():
    ctx = {"case_type": "ransomware", "classifier_confidence": 0.8}
    unified = {"evidence_by_type": {}, "evidence_items": [], "total_items": 0}
    block = reconcile_evidence(ctx, unified)
    assert block["narrative_evidence_divergence"] is False
    assert block["reconciled_confidence"] == 0.8
