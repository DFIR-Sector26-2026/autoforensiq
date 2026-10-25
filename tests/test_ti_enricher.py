"""PF-1b ThreatFox enricher: opt-in, annotation-only, cached, offline-degrading.
No test here may touch the network — the query function is always injected."""

from src.ioc import ti_enricher


def _item(aid, value, severity="critical", ioc_match=None):
    return {"artifact_id": aid, "evidence_type": "suspicious_domain", "value": value,
            "severity": severity, "ioc_match": ioc_match if ioc_match is not None else ["x"]}


def _fail_query(*a, **k):
    raise AssertionError("network query attempted")


def test_no_auth_key_skips_silently(monkeypatch):
    monkeypatch.delenv(ti_enricher.AUTH_KEY_ENV, raising=False)
    items = [_item("a1", "gx7ekbenv2riucmf.onion")]
    assert ti_enricher.enrich_items(items, _query=_fail_query) == 0
    assert "ti_attribution" not in items[0]


def test_annotates_flagged_indicators_only(monkeypatch, tmp_path):
    monkeypatch.setenv(ti_enricher.AUTH_KEY_ENV, "test-key")
    queried = []

    def fake_query(indicator, auth_key, timeout):
        queried.append(indicator)
        return {"family": "WannaCry", "confidence": 90, "threat_type": "botnet_cc"}

    items = [
        _item("hit", "C2: gx7ekbenv2riucmf.onion"),
        _item("unflagged", "57g7spgrzlojinas.onion", ioc_match=[]),   # no ioc_match -> skipped
        _item("low", "xxlvbrloxvriy2c5.onion", severity="low"),       # not flagged high -> skipped
        _item("lan", "TCP 192.168.1.5 → 10.0.0.2", severity="high"),  # LAN IPs are victims
    ]
    n = ti_enricher.enrich_items(items, cache_path=tmp_path / "c.json", _query=fake_query)
    assert n == 1
    assert queried == ["gx7ekbenv2riucmf.onion"]
    assert "ti:WannaCry" in items[0]["ioc_match"]
    assert items[0]["ti_attribution"][0]["source"] == "ThreatFox"
    # severity is never changed by third-party data
    assert items[0]["severity"] == "critical"
    assert all("ti_attribution" not in it for it in items[1:])


def test_cache_prevents_repeat_queries_including_misses(monkeypatch, tmp_path):
    monkeypatch.setenv(ti_enricher.AUTH_KEY_ENV, "test-key")
    calls = []

    def fake_query(indicator, auth_key, timeout):
        calls.append(indicator)
        return None  # ThreatFox has no entry

    cache = tmp_path / "c.json"
    items = [_item("a1", "gx7ekbenv2riucmf.onion")]
    assert ti_enricher.enrich_items(items, cache_path=cache, _query=fake_query) == 0
    # Second run: the miss is served from cache, not re-queried.
    assert ti_enricher.enrich_items(items, cache_path=cache, _query=_fail_query) == 0
    assert calls == ["gx7ekbenv2riucmf.onion"]


def test_network_error_degrades_silently(monkeypatch, tmp_path):
    monkeypatch.setenv(ti_enricher.AUTH_KEY_ENV, "test-key")

    def broken_query(indicator, auth_key, timeout):
        raise OSError("connection refused")

    items = [_item("a1", "gx7ekbenv2riucmf.onion")]
    n = ti_enricher.enrich_items(items, cache_path=tmp_path / "c.json", _query=broken_query)
    assert n == 0
    assert "ti_attribution" not in items[0]
