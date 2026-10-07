import pytest
from modules import recon


def test_asn_batch_parses_success_rows(monkeypatch):
    class R:
        def json(self): return [
            {"query": "1.1.1.1", "status": "success", "as": "AS13335 Cloudflare",
             "asname": "CLOUDFLARENET", "org": "Cloudflare, Inc.", "country": "United States"},
            {"query": "10.0.0.5", "status": "fail"},
        ]
    monkeypatch.setattr(recon.requests, "post", lambda *a, **k: R())
    out = recon._asn_batch(["1.1.1.1", "10.0.0.5"])
    assert out["1.1.1.1"]["org"] == "Cloudflare, Inc." and out["10.0.0.5"] == {}


def test_asn_batch_empty_list_short_circuits(monkeypatch):
    monkeypatch.setattr(recon.requests, "post", lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not call")))
    assert recon._asn_batch([]) == {}


def test_is_public_rejects_private_and_bad_input():
    assert recon._is_public("8.8.8.8") and not recon._is_public("10.1.2.3")
    assert not recon._is_public("127.0.0.1") and not recon._is_public("not-an-ip")


def test_head_tries_https_then_http(monkeypatch):
    calls = []
    class R:
        def __init__(self, u): self.status_code, self.chain = 200, [u]
    def fake_safe_head(url, timeout, headers):
        calls.append(url)
        if url.startswith("https"):
            raise recon.requests.RequestException("no tls")
        return R(url)
    monkeypatch.setattr(recon, "safe_head", fake_safe_head)
    out = recon._head("example.com")
    assert out["alive"] and out["scheme"] == "http" and not out["blocked"]
    assert calls == ["https://example.com", "http://example.com"]


def test_head_both_schemes_fail(monkeypatch):
    def fake_safe_head(*a, **k): raise recon.requests.RequestException("down")
    monkeypatch.setattr(recon, "safe_head", fake_safe_head)
    out = recon._head("dead.example")
    assert out == {"alive": False, "scheme": None, "status": None, "redirects_to": None, "blocked": False}


def test_head_blocked_target_is_reported_distinctly_not_as_down(monkeypatch):
    """A host that resolves to a private/internal address must be refused (SSRF guard), and the
    result must say so — not look identical to an ordinary unreachable host."""
    def fake_safe_head(url, timeout, headers):
        raise recon.UnsafeURL("host does not resolve to a public address")
    monkeypatch.setattr(recon, "safe_head", fake_safe_head)
    out = recon._head("internal.example")
    assert out["alive"] is False and out["blocked"] is True and "reason" in out


def test_head_redirect_target_recorded(monkeypatch):
    class R:
        status_code, chain = 301, ["https://example.com", "https://www.example.com/"]
    monkeypatch.setattr(recon, "safe_head", lambda *a, **k: R())
    out = recon._head("example.com")
    assert out["redirects_to"] == "https://www.example.com/"


def test_recon_domain_clusters_and_never_hits_live_targets(monkeypatch):
    """Full pipeline on fake data: no real network calls, so this is deterministic."""
    monkeypatch.setattr(recon, "_crtsh", lambda d: ["api.example.com", "www.example.com", "old.example.com"])
    ips = {"example.com": "93.184.0.1", "api.example.com": "93.184.0.1",   # shares IP with apex
          "www.example.com": "93.184.0.2", "old.example.com": "10.0.0.9"}  # private: excluded
    monkeypatch.setattr(recon, "_resolve", lambda h: ips.get(h))
    monkeypatch.setattr(recon, "_rdap_domain", lambda d: {"registrar": "Example Registrar"})
    monkeypatch.setattr(recon, "_asn_batch", lambda ips_: {
        "93.184.0.1": {"asn": "AS1", "asname": "EXAMPLE-NET", "org": "Example Hosting", "country": "US"},
        "93.184.0.2": {"asn": "AS1", "asname": "EXAMPLE-NET", "org": "Example Hosting", "country": "US"},
    })
    called = []
    monkeypatch.setattr(recon, "_head", lambda h: (called.append(h), {"alive": True, "scheme": "https", "status": 200, "redirects_to": None})[1])

    out = recon.recon_domain("example.com")

    assert out["passive_only"] is True
    assert out["apex"]["registrar"] == "Example Registrar"
    # old.example.com resolved, but only to a private IP: excluded from public IPs/ASN/live-probe
    row = {h["host"]: h for h in out["hosts"]}["old.example.com"]
    assert row["ip"] == "10.0.0.9" and row["org"] == "" and row["alive"] is None
    assert "old.example.com" not in out["unresolved"]
    assert len(set(called)) == len(called)                                # each live host probed once
    assert "10.0.0.5" not in str(out["graph"]["nodes"])                  # no private IPs leaked into graph
    shared_ip = out["clusters"]["shared_ip"]
    assert any(c["ip"] == "93.184.0.1" and set(c["hosts"]) == {"example.com", "api.example.com"} for c in shared_ip)
    shared_org = out["clusters"]["shared_org"]
    assert any(c["org"] == "Example Hosting" and len(c["hosts"]) >= 3 for c in shared_org)
    assert any(w.startswith("1 host(s)") for w in out["warnings"])       # private-IP exclusion warning
    host_rows = {r["host"]: r for r in out["hosts"]}
    assert host_rows["api.example.com"]["org"] == "Example Hosting"
    assert host_rows["old.example.com"]["ip"] == "10.0.0.9" and host_rows["old.example.com"]["alive"] is None


def test_recon_domain_probe_live_false_skips_head_calls(monkeypatch):
    monkeypatch.setattr(recon, "_crtsh", lambda d: [])
    monkeypatch.setattr(recon, "_resolve", lambda h: "93.184.0.1")
    monkeypatch.setattr(recon, "_rdap_domain", lambda d: {})
    monkeypatch.setattr(recon, "_asn_batch", lambda ips: {})
    monkeypatch.setattr(recon, "_head", lambda h: (_ for _ in ()).throw(AssertionError("must not probe")))
    out = recon.recon_domain("example.com", probe_live=False)
    assert out["hosts"][0]["alive"] is None


# ── CDN/shared-provider cluster separation ────────────────────────────────────
def test_cdn_clusters_reported_separately_from_notable_clusters(monkeypatch):
    monkeypatch.setattr(recon, "_crtsh", lambda d: ["a.example.com", "b.example.com", "c.example.com"])
    ips = {"example.com": "104.16.0.1", "a.example.com": "104.16.0.1",   # Cloudflare: routine
          "b.example.com": "93.184.216.34", "c.example.com": "93.184.216.34"}  # dedicated: notable
    monkeypatch.setattr(recon, "_resolve", lambda h: ips.get(h))
    monkeypatch.setattr(recon, "_rdap_domain", lambda d: {})
    monkeypatch.setattr(recon, "_asn_batch", lambda ips_: {
        "104.16.0.1": {"asn": "AS13335", "asname": "CLOUDFLARENET", "org": "Cloudflare, Inc.", "country": "US"},
        "93.184.216.34": {"asn": "AS64500", "asname": "SMALLHOST", "org": "Small Dedicated Hosting LLC", "country": "US"},
    })
    monkeypatch.setattr(recon, "_head", lambda h: {"alive": True, "scheme": "https", "status": 200, "redirects_to": None, "blocked": False})

    out = recon.recon_domain("example.com")

    assert not any(c["ip"] == "104.16.0.1" for c in out["clusters"]["shared_ip"])
    assert any(c["ip"] == "104.16.0.1" for c in out["clusters"]["common_provider_ip"])
    assert any(c["ip"] == "93.184.216.34" for c in out["clusters"]["shared_ip"])
    assert not any(c["ip"] == "93.184.216.34" for c in out["clusters"]["common_provider_ip"])
    assert any("common CDN/cloud provider" in w for w in out["warnings"])


def test_is_common_provider_matching():
    assert recon._is_common_provider("Cloudflare, Inc.")
    assert recon._is_common_provider("AMAZON-02")
    assert recon._is_common_provider("Microsoft Corporation")
    assert not recon._is_common_provider("Small Dedicated Hosting LLC")
    assert not recon._is_common_provider("")


# ── time budget degradation ────────────────────────────────────────────────────
def test_recon_degrades_gracefully_when_near_time_budget(monkeypatch):
    monkeypatch.setattr(recon, "_crtsh", lambda d: [])
    monkeypatch.setattr(recon, "_resolve", lambda h: "93.184.0.1")
    called = {"asn": False, "rdap": False, "head": False}
    monkeypatch.setattr(recon, "_asn_batch", lambda ips: called.__setitem__("asn", True) or {})
    monkeypatch.setattr(recon, "_rdap_domain", lambda d: called.__setitem__("rdap", True) or {})
    monkeypatch.setattr(recon, "_head", lambda h: called.__setitem__("head", True) or {})
    # fake a clock that's already eaten almost the whole soft budget by the time crt.sh+resolve finish
    times = iter([0.0] + [recon.SOFT_BUDGET - 1] * 20)
    monkeypatch.setattr(recon.time, "time", lambda: next(times))

    out = recon.recon_domain("example.com")

    assert not any(called.values())
    assert sum("time budget" in w for w in out["warnings"]) == 3   # asn, rdap, live-check all skipped


def test_recon_runs_normally_with_budget_to_spare(monkeypatch):
    monkeypatch.setattr(recon, "_crtsh", lambda d: [])
    monkeypatch.setattr(recon, "_resolve", lambda h: "93.184.0.1")
    monkeypatch.setattr(recon, "_asn_batch", lambda ips: {"93.184.0.1": {"org": "Example Org"}})
    monkeypatch.setattr(recon, "_rdap_domain", lambda d: {"registrar": "X"})
    monkeypatch.setattr(recon, "_head", lambda h: {"alive": True, "scheme": "https", "status": 200, "redirects_to": None, "blocked": False})
    out = recon.recon_domain("example.com")
    assert out["apex"] == {"registrar": "X"} and not any("time budget" in w for w in out["warnings"])
    assert "elapsed_s" in out


def test_crtsh_cap_warning_threshold(monkeypatch):
    monkeypatch.setattr(recon, "_crtsh", lambda d: [f"s{i}.example.com" for i in range(50)])
    monkeypatch.setattr(recon, "_resolve", lambda h: None)
    monkeypatch.setattr(recon, "_rdap_domain", lambda d: {})
    monkeypatch.setattr(recon, "_asn_batch", lambda ips: {})
    out = recon.recon_domain("example.com", probe_live=False)
    assert any("capped at 50" in w for w in out["warnings"])


# ── pipeline integration ───────────────────────────────────────────────────────
def test_deep_domain_scan_includes_recon(monkeypatch):
    from modules import pipeline
    monkeypatch.setattr(pipeline, "recon_domain", lambda d: {"domain": d, "hosts": [], "passive_only": True})
    monkeypatch.setattr(pipeline, "gather", lambda tasks: {n: {"ok": True, "value": (
        {"domain": tasks[n][1][0], "hosts": [], "passive_only": True} if n == "recon" else
        {"hits": [], "sources_checked": []} if n == "feeds" else
        {"error": "skip"} if n == "page" else None), "error": None} for n in tasks})
    fake = lambda q: {"type": "domain", "query": q, "score": 0, "chips": [], "rdap": {}}
    out = pipeline.run_scan(
        {"query": "example.com", "scan_type": "domain", "mode": "deep", "filters": [], "original_url": None},
        {"domain": fake}, lambda d: "sig")
    assert out.get("recon", {}).get("passive_only") is True


def test_fast_domain_scan_has_no_recon(monkeypatch):
    from modules import pipeline
    fake = lambda q: {"type": "domain", "query": q, "score": 0, "chips": [], "rdap": {}}
    out = pipeline.run_scan(
        {"query": "no-recon-fast.example", "scan_type": "domain", "mode": "fast", "filters": [], "original_url": None},
        {"domain": fake}, lambda d: "sig")
    assert "recon" not in out
