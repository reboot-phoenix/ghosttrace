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


# ── deep mode: page analysis (network mocked) ─────────────────────────────────
PHISH_HTML = """<html><head><title>SBI Net Banking - Verify KYC</title></head><body>
<p>URGENT: your account will be blocked. Verify your account immediately.</p>
<form action="https://collector.evil.example/post"><input type="text" name="user">
<input type="password" name="pass"><input name="otp" placeholder="Enter OTP"></form>
<iframe src="http://x.example" width="0" height="0"></iframe>
<a href="https://wa.me/919999999999">Chat</a></body></html>"""


class _FakeResp:
    status_code = 200
    text = PHISH_HTML
    chain = ["http://bit-ly.example/a", "https://sbi-verify.example/login"]


def test_deep_page_analysis_flags_phishing(monkeypatch):
    from modules import page_analysis as pa
    monkeypatch.setattr(pa, "safe_get", lambda *a, **k: _FakeResp())
    facts = pa.analyze("http://bit-ly.example/a")
    assert facts["cross_domain_redirect"] and facts["hidden_iframes"] == 1
    assert "OTP" in facts["forms"][0]["asks_for"] and "sbi" in facts["brand_mentions"]
    r = assess("domain", "sbi-verify.example", {"page": facts, "first_seen": None})
    ids = {s["id"] for s in r["signals"]}
    assert {"collects_sensitive", "form_posts_elsewhere", "page_impersonates_brand",
            "hidden_iframe", "urgency_language", "chat_contact"} <= ids
    assert r["verdict"] == "likely_scam"


def test_fast_vs_deep_differ(monkeypatch):
    from modules import page_analysis as pa
    monkeypatch.setattr(pa, "safe_get", lambda *a, **k: _FakeResp())
    fast = assess("domain", "verify-portal.example")
    deep = assess("domain", "verify-portal.example",
                  {"page": pa.analyze("http://verify-portal.example"), "first_seen": None})
    assert deep["score"] > fast["score"]


def test_deep_never_raises_on_blocked(monkeypatch):
    from modules import page_analysis as pa
    out = pa.analyze("http://127.0.0.1/")
    assert out["error"] and assess("domain", "x.example", {"page": out})["verdict"] in (
        "no_strong_signals", "suspicious", "likely_scam")


def test_safe_get_records_chain(monkeypatch):
    from modules import safe_http as sh
    monkeypatch.setattr(sh, "validate_url", lambda u: u)
    class R:
        status_code = 200; is_redirect = False; headers = {}
        def iter_content(self, n): yield b"hi"
        def close(self): pass
    monkeypatch.setattr(sh.requests, "request", lambda method, *a, **k: R())
    assert sh.safe_get("https://a.example").chain == ["https://a.example"]


def test_safe_head_blocks_ssrf_and_redirect_to_private(monkeypatch):
    from modules import safe_http as sh
    with pytest.raises(sh.UnsafeURL):
        sh.safe_head("http://169.254.169.254/latest/meta-data/")

    # a *remote-looking* URL that 302s to a private address must still be blocked, because the
    # redirect target is re-validated before it is followed
    monkeypatch.setattr(sh, "validate_url", lambda u: u if "127.0.0.1" not in u else (_ for _ in ()).throw(sh.UnsafeURL("blocked")))
    class Redirect:
        status_code = 302; is_redirect = True; headers = {"Location": "http://127.0.0.1/admin"}
        def iter_content(self, n): return iter(())
        def close(self): pass
    monkeypatch.setattr(sh.requests, "request", lambda method, url, **k: Redirect())
    with pytest.raises(sh.UnsafeURL):
        sh.safe_head("https://looks-public.example")


# ── community reports + web mentions ──────────────────────────────────────────
@pytest.fixture
def rdb(tmp_path, monkeypatch):
    monkeypatch.setenv("REPORTS_DB", str(tmp_path / "r.db"))
    from modules import reports
    reports._inited.clear()
    return reports


def test_reports_distinct_reporters_and_dedupe(rdb):
    assert rdb.add_report("phone", "+91 98765 01234", "fake_job", "1.1.1.1")["status"] == "recorded"
    assert rdb.add_report("phone", "9876501234", "fake_job", "1.1.1.1")["status"] == "duplicate"
    rdb.add_report("phone", "+919876501234", "phishing", "2.2.2.2")
    s = rdb.summary("phone", "09876501234"[1:])
    assert s["count"] == 2 and "fake_job" in s["categories"]


def test_reports_raise_score(rdb):
    for i in range(5):
        rdb.add_report("upi", "legit.looking@oksbi", "upi_fraud", f"9.9.9.{i}")
    rep = rdb.summary("upi", "legit.looking@oksbi")
    r = assess("upi", "legit.looking@oksbi", {"reports": rep})
    assert r["verdict"] == "likely_scam" and any(s["id"] == "community_reports" for s in r["signals"])


def test_reports_store_no_raw_ip(rdb):
    rdb.add_report("domain", "bad.example", "phishing", "203.0.113.7")
    import sqlite3, os
    dump = " ".join(str(r) for r in sqlite3.connect(os.environ["REPORTS_DB"]).execute("SELECT * FROM reports"))
    assert "203.0.113.7" not in dump


def test_web_mentions_requires_indicator_and_scam_word(monkeypatch):
    from modules import web_mentions as wm
    monkeypatch.setattr(wm, "search", lambda q, max_results=10: [
        {"title": "9876501234 is a fraud number, beware", "snippet": "", "link": "https://a"},
        {"title": "Call 9876501234 for support", "snippet": "", "link": "https://b"},
        {"title": "Fraud news today", "snippet": "unrelated", "link": "https://c"}])
    out = wm.scam_mentions("phone", "+919876501234")
    assert out["hits"] == 1
    assert assess("phone", "+919876501234", {"web": out})["score"] >= 25


def test_report_endpoint(rdb):
    from app import app
    c = app.test_client()
    ok = c.post("/report", json={"kind": "phone", "value": "+919876501234", "category": "fake_job"})
    assert ok.status_code == 200 and ok.get_json()["status"] == "recorded"
    assert c.post("/report", json={"kind": "username", "value": "x"}).status_code == 400
    assert c.post("/report", json={"kind": "phone", "value": "../../x"}).status_code == 400
    r = c.post("/scan", json={"query": "+919876501234", "scan_type": "phone"})
    assert r.status_code == 200


# ── bulk feed database ────────────────────────────────────────────────────────
@pytest.fixture
def fdb(tmp_path, monkeypatch):
    monkeypatch.setenv("FEEDS_DB", str(tmp_path / "f.db"))
    from modules import feed_db
    feed_db._inited.clear()
    return feed_db


def _fake_lines(monkeypatch, fdb, lines):
    monkeypatch.setattr(fdb, "_lines", lambda src: iter(lines))


def test_feed_import_and_lookup(fdb, monkeypatch):
    _fake_lines(monkeypatch, fdb, ["# comment", "evil-login.example", "Bad.Example.", "not a host!", "sbi-kyc.xyz"])
    assert fdb.refresh_source("phishing_database") == 3
    assert fdb.lookup("evil-login.example")[0]["label"] == "Phishing.Database"
    assert fdb.lookup("https://www.bad.example/x")            # parent domain listed
    assert not fdb.lookup("good.example")
    assert fdb.stats() == {"Phishing.Database": 3}


def test_shared_platform_listing_is_ignored(fdb, monkeypatch):
    _fake_lines(monkeypatch, fdb, ["sites.google.com", "evil.000webhostapp.com", "000webhostapp.com"])
    fdb.refresh_source("phishing_database")
    assert not fdb.lookup("https://sites.google.com/view/anything")
    assert not fdb.lookup("other.000webhostapp.com")           # only the platform itself is listed
    assert fdb.lookup("evil.000webhostapp.com")                # the specific subdomain still matches


def test_failed_refresh_keeps_old_data(fdb, monkeypatch):
    _fake_lines(monkeypatch, fdb, ["evil.example"])
    fdb.refresh_source("phishing_database")
    _fake_lines(monkeypatch, fdb, [])
    with pytest.raises(ValueError):
        fdb.refresh_source("phishing_database")
    assert fdb.lookup("evil.example")


def test_check_uses_local_db_and_scores(fdb, monkeypatch):
    from modules import threat_feeds as tf
    _fake_lines(monkeypatch, fdb, ["totally-new-phish.example"])
    fdb.refresh_source("phishing_database")
    monkeypatch.setattr(tf, "_openphish", {"ts": 9e12, "urls": frozenset(), "hosts": frozenset()})
    out = tf.check("https://totally-new-phish.example/login")
    assert out["hits"] and any("Local database" in s for s in out["sources_checked"])
    r = assess("url", "https://totally-new-phish.example/login", {"feed_hits": out["hits"]})
    assert r["verdict"] == "likely_scam"


# ── structure signals (tuned on real phishing vs top-site data) ───────────────
@pytest.mark.parametrize("host,flagged", [
    ("lighthearted-truffle-abf285.netlify.app", True),                         # random-looking on free host
    ("9hqbn0uyk2ju793r59dg5cs2wqxbgpr-65218347249.shopifypreview.com", True),  # long number subdomain
    ("kimerickreations.blogspot.com", False),                                   # readable blog name
    ("numerology-thenumbersandtheirmeanings.blogspot.com", False),
    ("reboot-phoenix.github.io", False),                                        # personal site on free host
    ("www.sbi.co.in", False), ("netbanking.hdfcbank.com", False), ("aws.amazon.com", False),
    ("jmljefdywjpngwre-dot-millinium.ey.r.appspot.com", None),                  # cloud infra: just must not crash
])
def test_structure_signals(host, flagged):
    r = assess("domain", host)
    if flagged is not None:
        assert (r["verdict"] != "no_strong_signals") is flagged


def test_free_hosting_alone_is_a_weak_signal():
    r = assess("domain", "mysite.pages.dev")
    assert r["verdict"] == "no_strong_signals" and any(s["id"] == "shared_hosting" for s in r["signals"])


# ── feedback loop ─────────────────────────────────────────────────────────────
def test_feedback_dedupe_and_scam_label_files_a_report(rdb):
    from modules import feedback as fb
    assert fb.add_feedback("domain", "agltradeuae.com", "no_strong_signals", "scam", "1.1.1.1")["status"] == "recorded"
    assert fb.add_feedback("domain", "agltradeuae.com", "no_strong_signals", "scam", "1.1.1.1")["status"] == "duplicate"
    assert rdb.summary("domain", "agltradeuae.com")["count"] == 1          # "scam" also counts as a report


def test_safe_label_never_lowers_a_score(rdb):
    from modules import feedback as fb
    for i in range(5):
        fb.add_feedback("domain", "evil-kyc.example", "likely_scam", "safe", f"2.2.2.{i}")
    assert rdb.summary("domain", "evil-kyc.example")["count"] == 0          # only logged for human review
    q = fb.review_queue()
    assert q["false_alarms"][0]["indicator"] == "domain:evil-kyc.example" and q["false_alarms"][0]["reporters"] == 5


def test_review_queue_lists_misses_and_stats(rdb):
    from modules import feedback as fb
    fb.add_feedback("upi", "nice.person@oksbi", "no_strong_signals", "scam", "3.3.3.1")
    fb.add_feedback("upi", "nice.person@oksbi", "no_strong_signals", "scam", "3.3.3.2")
    fb.add_feedback("domain", "ok.example", "no_strong_signals", "correct", "3.3.3.3")
    q = fb.review_queue()
    assert q["missed_scams"][0]["reporters"] == 2 and q["stats"]["agreement_pct"] == 33.3
    assert fb.review_queue(min_reporters=3)["missed_scams"] == []


def test_feedback_rejects_garbage(rdb):
    from modules import feedback as fb
    assert fb.add_feedback("domain", "x.example", "bogus", "scam", "1.1.1.1")["status"] == "invalid"
    assert fb.add_feedback("domain", "x.example", "suspicious", "maybe", "1.1.1.1")["status"] == "invalid"
    assert fb.add_feedback("domain", "no-dot", "suspicious", "scam", "1.1.1.1")["status"] == "invalid"


def test_feedback_endpoint_and_admin_gate(rdb, monkeypatch):
    from app import app
    c = app.test_client()
    ok = c.post("/feedback", json={"kind": "domain", "value": "agltradeuae.com",
                                   "verdict": "no_strong_signals", "label": "scam"})
    assert ok.status_code == 200 and ok.get_json()["status"] == "recorded"
    assert c.post("/feedback", json={"kind": "domain", "value": "../x", "verdict": "suspicious", "label": "scam"}).status_code == 400
    assert c.post("/feedback", json={"kind": "domain", "value": "a.example", "verdict": "x", "label": "scam"}).status_code == 400
    monkeypatch.delenv("ADMIN_TOKEN", raising=False)
    assert c.get("/admin/misses").status_code == 404                              # disabled by default
    monkeypatch.setenv("ADMIN_TOKEN", "s3cret-token")
    assert c.get("/admin/misses").status_code == 403
    assert c.get("/admin/misses", headers={"X-Admin-Token": "wrong"}).status_code == 403
    r = c.get("/admin/misses", headers={"X-Admin-Token": "s3cret-token"})
    assert r.status_code == 200 and r.get_json()["missed_scams"][0]["indicator"] == "domain:agltradeuae.com"
