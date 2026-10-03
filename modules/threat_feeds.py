"""
modules/threat_feeds.py — live "known bad" lookups for URLs / domains.

Sources (all fail open: an outage never breaks a scan):
  OpenPhish community feed   no key     https://openphish.com/feed.txt  (cached 1h in memory)
  URLhaus (abuse.ch)         free key   env URLHAUS_AUTH_KEY
  Google Safe Browsing v4    free key   env GOOGLE_SAFE_BROWSING_KEY

check(url_or_host) -> {"hits": [{"source", "detail", "reference"}], "sources_checked": [...]}
"""
from __future__ import annotations
import os
import threading
import time
from urllib.parse import urlparse

import requests

OPENPHISH_URL = "https://openphish.com/feed.txt"
_CACHE_TTL = 3600
_UA = {"User-Agent": "GhostTrace/3.1"}
_T = 6

_lock = threading.Lock()
_openphish = {"ts": 0.0, "urls": frozenset(), "hosts": frozenset()}


def _host(u: str) -> str:
    return (urlparse(u if "://" in u else "http://" + u).hostname or "").lower()


def _load_openphish() -> dict:
    with _lock:
        if time.time() - _openphish["ts"] < _CACHE_TTL:
            return _openphish
    try:
        r = requests.get(OPENPHISH_URL, timeout=10, headers=_UA)
        if r.status_code != 200:
            raise ValueError(r.status_code)
        urls = frozenset(l.strip() for l in r.text.splitlines() if l.strip().startswith("http"))
        hosts = frozenset(_host(u) for u in urls)
    except Exception:
        urls, hosts = _openphish["urls"], _openphish["hosts"]   # keep stale data on failure
    with _lock:
        _openphish.update(ts=time.time(), urls=urls, hosts=hosts)
        return _openphish


def _check_openphish(target: str) -> dict | None:
    feed = _load_openphish()
    if not feed["urls"]:
        return None
    h = _host(target)
    if target in feed["urls"] or (h and h in feed["hosts"]):
        return {"source": "OpenPhish", "detail": "Listed in the OpenPhish phishing feed",
                "reference": "https://openphish.com/"}
    return None


def _check_urlhaus(target: str) -> dict | None:
    key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    if not key:
        return None
    try:
        is_url = "://" in target
        r = requests.post("https://urlhaus-api.abuse.ch/v1/" + ("url/" if is_url else "host/"),
                          data={"url": target} if is_url else {"host": _host(target)},
                          headers={**_UA, "Auth-Key": key}, timeout=_T)
        if r.status_code != 200:
            return None
        j = r.json()
        if j.get("query_status") == "ok":
            n = j.get("url_count") or len(j.get("urls") or []) or 1
            return {"source": "URLhaus", "detail": f"Known malware-distribution host/URL ({n} record(s))",
                    "reference": j.get("urlhaus_reference") or "https://urlhaus.abuse.ch/"}
    except Exception:
        pass
    return None


def _check_safebrowsing(target: str) -> dict | None:
    key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "").strip()
    if not key:
        return None
    url = target if "://" in target else "http://" + target
    try:
        r = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": key}, timeout=_T,
            json={"client": {"clientId": "ghosttrace", "clientVersion": "3.1"},
                  "threatInfo": {
                      "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                      "platformTypes": ["ANY_PLATFORM"],
                      "threatEntryTypes": ["URL"],
                      "threatEntries": [{"url": url}]}})
        if r.status_code == 200 and r.json().get("matches"):
            kinds = sorted({m.get("threatType", "?") for m in r.json()["matches"]})
            return {"source": "Google Safe Browsing", "detail": "Flagged: " + ", ".join(kinds),
                    "reference": "https://transparencyreport.google.com/safe-browsing/search"}
    except Exception:
        pass
    return None


_CHECKS = (("OpenPhish", _check_openphish),
           ("URLhaus", _check_urlhaus),
           ("Google Safe Browsing", _check_safebrowsing))


def check(target: str) -> dict:
    hits, checked = [], []
    local_labels: set[str] = set()
    try:
        from modules import feed_db
        stats = feed_db.stats()
        if stats:
            local_labels = set(stats)
            total = sum(stats.values())
            checked.append(f"Local database ({total:,} known-bad hosts)")
            for m in feed_db.lookup(target):
                hits.append({"source": m["label"], "detail":
                             f"Listed in {m['label']} (matched {m['via']})", "reference": ""})
    except Exception:
        pass
    for name, fn in _CHECKS:
        if name in local_labels:        # already covered by the local database
            continue
        if name == "URLhaus" and not os.environ.get("URLHAUS_AUTH_KEY"):
            continue
        if name == "Google Safe Browsing" and not os.environ.get("GOOGLE_SAFE_BROWSING_KEY"):
            continue
        checked.append(name)
        hit = fn(target)
        if hit:
            hits.append(hit)
    return {"hits": hits, "sources_checked": checked}
