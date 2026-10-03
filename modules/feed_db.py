"""
modules/feed_db.py — local bulk "known bad" database built from free public feeds.

Sources:
  phishing_database  Phishing.Database ACTIVE domains (GitHub, no key, ~390k domains)
  openphish          OpenPhish community feed (no key, URLs -> hosts)
  urlhaus            URLhaus online list (needs free abuse.ch key: URLHAUS_AUTH_KEY)

Lookups are local SQLite queries (instant, no per-scan API calls). Refreshed in a daemon
thread when older than 24h; also runnable by hand:  python -m modules.feed_db refresh

Set FEEDS_DB to a path on a mounted volume to keep it across deploys (otherwise it is
simply re-downloaded after each deploy). Set FEED_REFRESH=0 to disable the background job.
"""
from __future__ import annotations
import os
import re
import sqlite3
import sys
import threading
import time
from urllib.parse import urlparse

import requests

SOURCES = {
    "phishing_database": {
        "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "kind": "domains", "label": "Phishing.Database"},
    "openphish": {
        "url": "https://openphish.com/feed.txt", "kind": "urls", "label": "OpenPhish"},
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text_online/", "kind": "urls",
        "label": "URLhaus", "needs_key": "URLHAUS_AUTH_KEY"},
}
REFRESH_EVERY = 24 * 3600
# Shared platforms that appear in phishing feeds because attackers host pages on them.
# A listing of the platform itself says nothing about a given page, so ignore those exact
# matches (a listed *subdomain* like evil.000webhostapp.com still matches).
SHARED_PLATFORMS = {
    "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle", "storage.googleapis.com",
    "github.io", "pages.dev", "web.app", "firebaseapp.com", "blogspot.com", "weebly.com",
    "wixsite.com", "herokuapp.com", "netlify.app", "vercel.app", "workers.dev", "r2.dev",
    "000webhostapp.com", "ipfs.io", "cf-ipfs.com", "s3.amazonaws.com", "azurewebsites.net",
    "onrender.com", "glitch.me", "repl.co", "webflow.io", "carrd.co", "godaddysites.com",
    "mystrikingly.com", "wordpress.com", "tumblr.com", "medium.com", "notion.site",
    "typeform.com", "canva.com", "bit.ly", "t.co", "tinyurl.com", "cutt.ly", "rb.gy",
}
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-\.]{0,251}[a-z0-9])?$")
_lock = threading.Lock()
_inited: set[str] = set()
_refreshing = False


def _path() -> str:
    return os.environ.get("FEEDS_DB", "data/feeds.db")


def _conn() -> sqlite3.Connection:
    path = _path()
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    c = sqlite3.connect(path, timeout=30)
    if path not in _inited:
        with _lock:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS bad (host TEXT NOT NULL, source TEXT NOT NULL,
                                                PRIMARY KEY (host, source)) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS bad_urls (url TEXT NOT NULL, source TEXT NOT NULL,
                                                     PRIMARY KEY (url, source)) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
            """)
            c.commit()
            _inited.add(path)
    return c


def _lines(src: dict):
    headers = {"User-Agent": "GhostTrace/3.1"}
    if src.get("needs_key"):
        headers["Auth-Key"] = os.environ[src["needs_key"]]
    with requests.get(src["url"], headers=headers, stream=True, timeout=(10, 60)) as r:
        r.raise_for_status()
        for line in r.iter_lines(decode_unicode=True):
            if line:
                yield line.strip()


def _host(u: str) -> str:
    return (urlparse(u).hostname or "").lower()


def refresh_source(name: str) -> int:
    """Download one source and replace its rows atomically. Returns row count."""
    src = SOURCES[name]
    if src.get("needs_key") and not os.environ.get(src["needs_key"]):
        return 0
    hosts: set[str] = set()
    urls: set[str] = set()
    for line in _lines(src):
        if line.startswith(("#", "//")):
            continue
        if src["kind"] == "domains":
            h = line.lower().strip(".")
            if _HOST_RE.match(h) and "." in h:
                hosts.add(h)
        elif line.startswith("http"):
            urls.add(line[:2000])
            h = _host(line)
            if h and "." in h:
                hosts.add(h)
    if not hosts and not urls:
        raise ValueError("empty download; keeping old data")
    c = _conn()
    try:
        with c:   # single transaction: readers never see a half-loaded source
            c.execute("DELETE FROM bad WHERE source=?", (name,))
            c.execute("DELETE FROM bad_urls WHERE source=?", (name,))
            c.executemany("INSERT OR IGNORE INTO bad VALUES (?,?)", ((h, name) for h in hosts))
            c.executemany("INSERT OR IGNORE INTO bad_urls VALUES (?,?)", ((u, name) for u in urls))
            c.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (f"ts:{name}", str(int(time.time()))))
    finally:
        c.close()
    return len(hosts)


def refresh_all(force: bool = False) -> dict:
    out = {}
    c = _conn()
    try:
        for name in SOURCES:
            row = c.execute("SELECT v FROM meta WHERE k=?", (f"ts:{name}",)).fetchone()
            if not force and row and time.time() - int(row[0]) < REFRESH_EVERY:
                out[name] = "fresh"
                continue
            try:
                out[name] = refresh_source(name)
            except Exception as e:
                out[name] = f"failed: {type(e).__name__}"
    finally:
        c.close()
    return out


def _bg():
    global _refreshing
    try:
        refresh_all()
    finally:
        _refreshing = False


def start_background_refresh() -> None:
    """Kick off a refresh thread (non-blocking). Safe to call repeatedly."""
    global _refreshing
    if os.environ.get("FEED_REFRESH", "1") == "0" or _refreshing:
        return
    _refreshing = True
    threading.Thread(target=_bg, name="feed-refresh", daemon=True).start()


def stats() -> dict:
    c = _conn()
    try:
        rows = c.execute("SELECT source, COUNT(*) FROM bad GROUP BY source").fetchall()
    finally:
        c.close()
    return {SOURCES[s]["label"]: n for s, n in rows if s in SOURCES}


def lookup(target: str) -> list[dict]:
    """Match host (and listed parent domains) or exact URL. [{source, label, via}]"""
    if "://" in target:
        host, url = _host(target), target
    else:
        host, url = target.lower().strip("."), None
    if not host:
        return []
    labels = host.split(".")
    candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]   # host … 2-label parent
    hits: dict[str, dict] = {}
    c = _conn()
    try:
        q = ",".join("?" * len(candidates))
        for src, h in c.execute(f"SELECT source, host FROM bad WHERE host IN ({q})", candidates):
            if h in SHARED_PLATFORMS:
                continue
            hits[src] = {"source": src, "label": SOURCES[src]["label"], "via": h}
        if url:
            for (src,) in c.execute("SELECT source FROM bad_urls WHERE url=?", (url[:2000],)):
                hits[src] = {"source": src, "label": SOURCES[src]["label"], "via": "exact URL"}
    finally:
        c.close()
    return list(hits.values())


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "refresh":
        print(refresh_all(force=True))
        print(stats())
    else:
        print(stats())
