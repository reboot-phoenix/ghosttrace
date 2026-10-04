"""
modules/reports.py — community scam reports (SQLite, free, no external service).

Privacy / abuse design:
  - Stores only: normalised indicator, category, timestamp, salted hash of reporter IP.
    No free text, no names, no raw IPs.
  - A lookup returns only counts and categories, never who reported.
  - Scoring uses DISTINCT reporters in the last 180 days, so one person can't inflate it.
  - One report per reporter per indicator (duplicates ignored); daily cap per reporter.
Reports are unverified opinions of users and are labelled as such in the UI.

Persistence: set REPORTS_DB to a path on a mounted volume (Railway/Fly volume), otherwise
the file is lost on every redeploy.
"""
from __future__ import annotations
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time

CATEGORIES = {"phishing", "fake_job", "upi_fraud", "lottery_prize", "impersonation",
              "investment_scam", "loan_app", "other"}
WINDOW_DAYS = 180
DAILY_CAP = 30
_lock = threading.Lock()
_inited: set[str] = set()


def _path() -> str:
    return os.environ.get("REPORTS_DB", "data/reports.db")


def _conn() -> sqlite3.Connection:
    path = _path()
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    c = sqlite3.connect(path, timeout=5)
    if path not in _inited:
        with _lock:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT NOT NULL, category TEXT NOT NULL,
                    reporter TEXT NOT NULL, ts INTEGER NOT NULL,
                    UNIQUE(indicator, reporter));
                CREATE INDEX IF NOT EXISTS idx_ind ON reports(indicator);
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT NOT NULL, verdict TEXT NOT NULL, label TEXT NOT NULL,
                    reporter TEXT NOT NULL, ts INTEGER NOT NULL,
                    UNIQUE(indicator, reporter));
                CREATE INDEX IF NOT EXISTS idx_fb ON feedback(label, verdict);
            """)
            c.execute("INSERT OR IGNORE INTO meta VALUES ('salt', ?)", (secrets.token_hex(16),))
            c.commit()
            _inited.add(path)
    return c


def normalize(kind: str, value: str) -> str | None:
    v = value.strip().lower()
    if kind == "phone":
        d = re.sub(r"\D", "", v)
        if len(d) == 12 and d.startswith("91"):
            d = d[2:]
        return f"phone:{d}" if 7 <= len(d) <= 15 else None
    if kind in ("upi", "email"):
        return f"{kind}:{v}" if "@" in v else None
    if kind in ("domain", "url"):
        from urllib.parse import urlparse
        host = (urlparse(v).hostname if "://" in v else v.split("/")[0]) or ""
        return f"domain:{host.strip('.')}" if "." in host else None
    return None


def _reporter(c: sqlite3.Connection, ip: str) -> str:
    salt = c.execute("SELECT v FROM meta WHERE k='salt'").fetchone()[0]
    return hmac.new(salt.encode(), ip.encode(), hashlib.sha256).hexdigest()[:24]


def add_report(kind: str, value: str, category: str, reporter_ip: str) -> dict:
    ind = normalize(kind, value)
    if not ind:
        return {"status": "invalid"}
    if category not in CATEGORIES:
        category = "other"
    now = int(time.time())
    c = _conn()
    try:
        who = _reporter(c, reporter_ip or "unknown")
        today = c.execute("SELECT COUNT(*) FROM reports WHERE reporter=? AND ts>?",
                          (who, now - 86400)).fetchone()[0]
        if today >= DAILY_CAP:
            return {"status": "limit"}
        cur = c.execute("INSERT OR IGNORE INTO reports (indicator, category, reporter, ts) VALUES (?,?,?,?)",
                        (ind, category, who, now))
        c.commit()
        return {"status": "recorded" if cur.rowcount else "duplicate"}
    finally:
        c.close()


def summary(kind: str, value: str) -> dict:
    """{count: distinct reporters in window, categories: {cat: n}, last: ts|None}"""
    ind = normalize(kind, value)
    if not ind:
        return {"count": 0, "categories": {}, "last": None}
    cutoff = int(time.time()) - WINDOW_DAYS * 86400
    c = _conn()
    try:
        rows = c.execute("SELECT category, COUNT(*), MAX(ts) FROM reports "
                         "WHERE indicator=? AND ts>? GROUP BY category", (ind, cutoff)).fetchall()
    finally:
        c.close()
    cats = {r[0]: r[1] for r in rows}
    return {"count": sum(cats.values()), "categories": cats,
            "last": max((r[2] for r in rows), default=None)}
