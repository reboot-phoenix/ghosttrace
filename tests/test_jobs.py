import time
import pytest

from modules.cache import TTLCache
from modules import timeouts, jobs, pipeline
from modules import search as srch


# ── cache ─────────────────────────────────────────────────────────────────────
def test_cache_ttl_and_eviction(monkeypatch):
    c = TTLCache(ttl=10, max_items=2)
    c.set("a", 1); c.set("b", 2); c.set("c", 3)
    assert c.get("a") is None and c.get("b") == 2 and c.get("c") == 3     # oldest evicted
    t = [time.time()]
    monkeypatch.setattr("modules.cache.time.time", lambda: t[0] + 11)
    assert c.get("b") is None                                             # expired


# ── timeouts ──────────────────────────────────────────────────────────────────
def test_run_with_timeout_raises_user_safe():
    with pytest.raises(timeouts.ScanTimeout) as e:
        timeouts.run_with_timeout(lambda: time.sleep(1), 0.1)
    assert e.value.user_safe


def test_gather_isolates_failures_and_timeouts():
    def boom(): raise ValueError("secret")
    out = timeouts.gather({
        "fast": (lambda: 42, (), 2),
        "slow": (lambda: time.sleep(1), (), 0.1),
        "bad": (boom, (), 2),
    })
    assert out["fast"] == {"ok": True, "value": 42, "error": None}
    assert not out["slow"]["ok"] and "timed out" in out["slow"]["error"]
    assert out["bad"]["error"] == "ValueError" and "secret" not in str(out["bad"])


# ── jobs ──────────────────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _clean_jobs():
    jobs._jobs.clear()
    yield
    jobs._jobs.clear()


def _wait(jid, timeout=3):
    end = time.time() + timeout
    while time.time() < end:
        j = jobs.get(jid)
        if j["status"] in ("done", "error"):
            return j
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_job_records_steps_and_result():
    def work(progress):
        progress("one"); time.sleep(0.02); progress("two")
        return {"ok": True}
    j = _wait(jobs.submit(work, "1.1.1.1"))
    assert j["status"] == "done" and j["result"] == {"ok": True}
    assert [s["label"] for s in j["steps"]] == ["one", "two"] and all(s["status"] == "done" for s in j["steps"])


def test_job_error_hides_internals_but_shows_user_safe():
    def leaky(progress): raise RuntimeError("secret path /srv/x")
    def safe(progress): raise timeouts.ScanTimeout("took too long")
    j1, j2 = _wait(jobs.submit(leaky, "a")), _wait(jobs.submit(safe, "b"))
    assert "secret" not in j1["error"] and j1["error"].startswith("Scan failed")
    assert j2["error"] == "took too long"


def test_per_ip_cap_and_unknown_job():
    gate = []
    slow = lambda progress: (time.sleep(0.5), {})[1]
    jobs.submit(slow, "9.9.9.9"); jobs.submit(slow, "9.9.9.9")
    with pytest.raises(jobs.Busy) as e:
        jobs.submit(slow, "9.9.9.9")
    assert e.value.code == 429
    jobs.submit(slow, "8.8.8.8")                       # other IPs unaffected
    assert jobs.get("nope") is None


# ── API: start + poll ─────────────────────────────────────────────────────────
def _poll(client, jid, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        r = client.get(f"/scan/status/{jid}")
        j = r.get_json()
        if j["status"] in ("done", "error"):
            return j
        time.sleep(0.05)
    raise AssertionError("never finished")


def test_api_start_and_poll_upi():
    from app import app
    c = app.test_client()
    r = c.post("/scan/start", json={"query": "refund.kyc@okaxis", "scan_type": "upi"})
    assert r.status_code == 202
    j = _poll(c, r.get_json()["job_id"])
    assert j["status"] == "done" and j["result"]["scam_risk"]["verdict"] in ("suspicious", "likely_scam")
    assert "_sig" in j["result"] and any(s["label"] == "Scoring" for s in j["steps"])


def test_api_start_validates_and_unknown_job():
    from app import app
    c = app.test_client()
    assert c.post("/scan/start", json={"query": "../../x", "scan_type": "username"}).status_code == 400
    assert c.post("/scan/start", json={"query": ""}).status_code == 400
    assert c.get("/scan/status/does-not-exist").status_code == 404


# ── pipeline: cache + partial results ─────────────────────────────────────────
def _params(**kw):
    return {"query": "example.com", "scan_type": "domain", "mode": "fast", "filters": [], "original_url": None, **kw}


def test_pipeline_caches_identical_scans():
    calls = []
    def fake_domain(q):
        calls.append(q); return {"type": "domain", "query": q, "score": 0, "chips": [], "rdap": {}}
    p1 = pipeline.run_scan(_params(), {"domain": fake_domain}, lambda d: "sig")
    p2 = pipeline.run_scan(_params(), {"domain": fake_domain}, lambda d: "sig")
    assert len(calls) == 1 and p1 is p2


def test_pipeline_reports_skipped_sources_and_does_not_cache(monkeypatch):
    fake = lambda q: {"type": "domain", "query": q, "score": 0, "chips": [], "rdap": {}}
    monkeypatch.setattr(pipeline, "gather", lambda tasks: {
        n: {"ok": False, "value": None, "error": "timed out after 15s"} for n in tasks})
    out = pipeline.run_scan(_params(mode="deep"), {"domain": fake}, lambda d: "sig")
    assert any("Page analysis" in s for s in out["scam_risk"]["skipped"])
    monkeypatch.undo()
    calls = []
    def counting(q):
        calls.append(1); return {"type": "domain", "query": q, "score": 0, "chips": [], "rdap": {}}
    monkeypatch.setattr(pipeline, "gather", lambda tasks: {
        n: {"ok": False, "value": None, "error": "x"} for n in tasks})
    pipeline.run_scan(_params(mode="deep", query="b.example"), {"domain": counting}, lambda d: "s")
    pipeline.run_scan(_params(mode="deep", query="b.example"), {"domain": counting}, lambda d: "s")
    assert len(calls) == 2                               # partial results are not cached


def test_pipeline_main_scan_timeout_is_friendly(monkeypatch):
    monkeypatch.setitem(pipeline.SCAN_TIMEOUT, "fast", 0.1)
    with pytest.raises(timeouts.ScanTimeout) as e:
        pipeline.run_scan(_params(), {"domain": lambda q: time.sleep(1)}, lambda d: "s")
    assert "too long" in str(e.value)


# ── search: merge, retry, cache ───────────────────────────────────────────────
def R(link): return {"title": link, "link": link, "snippet": ""}


def test_search_merges_engines_and_dedupes(monkeypatch):
    monkeypatch.setattr(srch, "GOOGLE_CSE_KEY", "k"); monkeypatch.setattr(srch, "GOOGLE_CSE_ID", "i")
    monkeypatch.setattr(srch, "_google_cse", lambda q, n: [R("https://a")])
    monkeypatch.setattr(srch, "_ddg", lambda q, n: [R("https://a"), R("https://b"), R("https://c")])
    out = srch.search("q1")
    assert [r["link"] for r in out] == ["https://a", "https://b", "https://c"]


def test_search_caches_success_but_not_failure(monkeypatch):
    n = {"c": 0}
    def flaky(q, k):
        n["c"] += 1
        return [] if n["c"] == 1 else [R("https://x"), R("https://y"), R("https://z")]
    monkeypatch.setattr(srch, "_ddg", flaky)
    assert srch.search("q2") == []                  # failure: not cached
    assert len(srch.search("q2")) == 3              # retried
    srch.search("q2")
    assert n["c"] == 2                              # success was cached


def test_ddg_retries_once(monkeypatch):
    attempts = {"n": 0}
    class FakeDDGS:
        def __init__(self, timeout=10): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def text(self, q, max_results=10):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise RuntimeError("ratelimit")
            return [{"title": "t", "href": "https://ok", "body": "b"}]
    monkeypatch.setattr(srch, "DDGS", FakeDDGS)
    assert srch._ddg("q", 5)[0]["link"] == "https://ok" and attempts["n"] == 2


# ── Google CSE quota awareness ────────────────────────────────────────────────
def test_cse_quota_error_disables_engine_for_the_day(monkeypatch):
    class Resp:
        def json(self): return {"error": {"code": 429, "message": "Quota exceeded for quota metric"}}
    calls = {"n": 0}
    def fake_get(*a, **k):
        calls["n"] += 1; return Resp()
    monkeypatch.setattr(srch, "GOOGLE_CSE_KEY", "k"); monkeypatch.setattr(srch, "GOOGLE_CSE_ID", "i")
    monkeypatch.setattr(srch.requests, "get", fake_get)
    monkeypatch.setattr(srch, "_ddg", lambda q, n: [R("https://a"), R("https://b"), R("https://c")])
    srch._cse.update(day="", used=0, exhausted=False, last_error=None)
    assert len(srch.search("quota-q1")) == 3            # falls back to DDG
    assert srch.search_status()["google_cse"]["exhausted"] is True
    srch.search("quota-q2")
    assert calls["n"] == 1                               # no more wasted CSE calls today
    assert "429" in srch.search_status()["google_cse"]["last_error"]


def test_cse_stops_at_daily_limit(monkeypatch):
    monkeypatch.setattr(srch, "GOOGLE_CSE_KEY", "k"); monkeypatch.setattr(srch, "GOOGLE_CSE_ID", "i")
    monkeypatch.setattr(srch, "CSE_DAILY_LIMIT", 2)
    monkeypatch.setattr(srch, "_google_cse", lambda q, n: (srch._cse.__setitem__("used", srch._cse["used"] + 1), [R("https://g")])[1])
    monkeypatch.setattr(srch, "_ddg", lambda q, n: [R("https://d1"), R("https://d2"), R("https://d3")])
    srch._cse.update(day=srch._cse_today(), used=0, exhausted=False, last_error=None)
    for i in range(4):
        srch.search(f"limit-q{i}")
    assert srch._cse["used"] == 2


def test_fast_name_scan_uses_five_searches_deep_uses_all(monkeypatch):
    from modules import name as nm
    seen = []
    monkeypatch.setattr(nm, "search", lambda q, max_results=10: (seen.append(q), [])[1])
    nm.scan_name("Jane Roe", mode="fast"); fast = len(seen)
    seen.clear(); nm.scan_name("Jane Roe", mode="deep")
    assert fast == 5 and len(seen) == 14
