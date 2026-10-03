import pytest
from modules.scam import assess
from modules.safe_http import validate_url, UnsafeURL
from detector import detect_input, is_valid_for_type


@pytest.mark.parametrize("kind,q,verdict", [
    ("domain", "sbi-kyc-update.xyz", "likely_scam"),
    ("url", "http://paytm-reward.top/claim?otp=1", "likely_scam"),
    ("domain", "onlinesbi.sbi", "no_strong_signals"),
    ("domain", "hdfcbannk.com", "suspicious"),
    ("upi", "rahul@oksbi", "no_strong_signals"),
    ("email", "a@mailinator.com", "suspicious"),
])
def test_verdicts(kind, q, verdict):
    assert assess(kind, q)["verdict"] == verdict


def test_short_brand_needs_token_match():
    assert not any(s["id"] == "brand_in_domain" for s in assess("domain", "ebisbicycles.com")["signals"])


def test_new_domain_signal():
    from datetime import date
    r = assess("domain", "example-shop.com", {"domain_created": date.today().isoformat()})
    assert any(s["id"] == "new_domain" for s in r["signals"])


def test_upi_detected_and_not_email():
    assert detect_input("rahul@oksbi") == "upi"
    assert detect_input("a@b.com") == "email"


def test_scan_type_must_match_query():
    assert not is_valid_for_type("username", "../../etc/passwd")
    assert not is_valid_for_type("username", "-rf")
    assert not is_valid_for_type("ip", "999.1.1.1")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.5/", "file:///etc/passwd", "http://example.com:8080/", "http://u:p@example.com/",
])
def test_ssrf_blocked(url):
    with pytest.raises(UnsafeURL):
        validate_url(url)


def test_api_rejects_mismatched_type():
    from app import app
    c = app.test_client()
    r = c.post("/scan", json={"query": "../../x", "scan_type": "username"})
    assert r.status_code == 400


def test_api_upi_scan_returns_signed_scam_risk():
    from app import app
    c = app.test_client()
    r = c.post("/scan", json={"query": "refund.kyc@okaxis", "scan_type": "upi"})
    assert r.status_code == 200
    j = r.get_json()
    assert j["scam_risk"]["verdict"] in ("suspicious", "likely_scam") and "_sig" in j
    assert r.headers["X-Content-Type-Options"] == "nosniff"


# ── live feeds (network mocked) ───────────────────────────────────────────────
def test_feed_hit_forces_likely_scam(monkeypatch):
    hit = {"source": "OpenPhish", "detail": "Listed in the OpenPhish phishing feed", "reference": "x"}
    r = assess("domain", "totally-normal-site.com", {"feed_hits": [hit]})
    assert r["verdict"] == "likely_scam" and r["signals"][0]["id"] == "feed_openphish"


def test_openphish_match(monkeypatch):
    from modules import threat_feeds as tf
    monkeypatch.setattr(tf, "_openphish", {"ts": 9e12, "urls": frozenset({"http://evil.example/login"}),
                                           "hosts": frozenset({"evil.example"})})
    assert tf._check_openphish("evil.example")
    assert tf._check_openphish("http://evil.example/login")
    assert not tf._check_openphish("good.example")


def test_feeds_fail_open(monkeypatch):
    from modules import threat_feeds as tf
    import requests
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "k")
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_KEY", "k")
    def boom(*a, **k): raise requests.ConnectionError("down")
    monkeypatch.setattr(requests, "post", boom)
    monkeypatch.setattr(requests, "get", boom)
    monkeypatch.setattr(tf, "_openphish", {"ts": 0.0, "urls": frozenset(), "hosts": frozenset()})
    out = tf.check("http://x.example")
    assert out["hits"] == [] and len(out["sources_checked"]) == 3


def test_urlhaus_parsing(monkeypatch):
    from modules import threat_feeds as tf
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "k")
    class R:
        status_code = 200
        def json(self): return {"query_status": "ok", "url_count": 3, "urlhaus_reference": "https://urlhaus.abuse.ch/host/x/"}
    monkeypatch.setattr(tf.requests, "post", lambda *a, **k: R())
    assert tf._check_urlhaus("bad.example")["source"] == "URLhaus"


def test_free_brief_without_api_key(monkeypatch):
    from modules import ai_brief
    monkeypatch.setattr(ai_brief, "ANTHROPIC_API_KEY", "")
    sr = assess("domain", "sbi-kyc-update.xyz")
    out = ai_brief.generate_brief({"query": "sbi-kyc-update.xyz", "type": "domain",
                                   "scam_risk": sr, "report": {}})
    assert out["generated"] and "LIKELY SCAM" in out["brief"] and "1930" in out["brief"]
