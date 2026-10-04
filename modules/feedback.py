"""
modules/feedback.py — "was this verdict right?" loop.

Users tell us when a verdict was right, or actually safe, or actually a scam. We store only
(indicator, our verdict, their answer, salted reporter hash, time). Nothing here changes any
score automatically (a scammer could mark their own site "safe"); it feeds a REVIEW list:

  missed scams  : users say scam, we said no_strong_signals       -> add/tune a signal
  false alarms  : users say safe, we said suspicious/likely_scam  -> loosen a signal

Only "actually a scam" also files a community report (same abuse limits as /report).
Review with:  python -m modules.feedback misses     or the token-protected /admin/misses.
Every confirmed miss should become a case in tests/golden_cases.json (see README).
"""
from __future__ import annotations
import sys
import time

from modules import reports as rdb

VERDICTS = {"likely_scam", "suspicious", "no_strong_signals"}
LABELS = {"correct", "safe", "scam"}
DAILY_CAP = 40


def add_feedback(kind: str, value: str, verdict: str, label: str, reporter_ip: str) -> dict:
    ind = rdb.normalize(kind, value)
    if not ind or verdict not in VERDICTS or label not in LABELS:
        return {"status": "invalid"}
    now = int(time.time())
    c = rdb._conn()
    try:
        who = rdb._reporter(c, reporter_ip or "unknown")
        if c.execute("SELECT COUNT(*) FROM feedback WHERE reporter=? AND ts>?",
                     (who, now - 86400)).fetchone()[0] >= DAILY_CAP:
            return {"status": "limit"}
        cur = c.execute("INSERT OR IGNORE INTO feedback (indicator, verdict, label, reporter, ts) VALUES (?,?,?,?,?)",
                        (ind, verdict, label, who, now))
        c.commit()
        status = "recorded" if cur.rowcount else "duplicate"
    finally:
        c.close()
    if status == "recorded" and label == "scam":      # same abuse limits as a normal report
        rdb.add_report(kind, value, "other", reporter_ip)
    return {"status": status}


def stats() -> dict:
    c = rdb._conn()
    try:
        rows = c.execute("SELECT label, verdict, COUNT(*) FROM feedback GROUP BY label, verdict").fetchall()
    finally:
        c.close()
    total = sum(r[2] for r in rows)
    correct = sum(r[2] for r in rows if r[0] == "correct")
    return {"total": total, "correct": correct,
            "agreement_pct": round(100 * correct / total, 1) if total else None,
            "breakdown": [{"label": a, "our_verdict": b, "n": n} for a, b, n in rows]}


def review_queue(min_reporters: int = 1, limit: int = 100) -> dict:
    """Indicators where users disagree with us, most-reported first."""
    c = rdb._conn()
    try:
        def q(label, verdicts):
            ph = ",".join("?" * len(verdicts))
            return [{"indicator": r[0], "our_verdict": r[1], "reporters": r[2], "last": r[3]}
                    for r in c.execute(
                        f"SELECT indicator, verdict, COUNT(DISTINCT reporter) n, MAX(ts) FROM feedback "
                        f"WHERE label=? AND verdict IN ({ph}) GROUP BY indicator, verdict "
                        f"HAVING n>=? ORDER BY n DESC, MAX(ts) DESC LIMIT ?",
                        (label, *verdicts, min_reporters, limit))]
        return {"missed_scams": q("scam", ["no_strong_signals"]),
                "false_alarms": q("safe", ["suspicious", "likely_scam"]),
                "stats": stats()}
    finally:
        c.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "misses":
        import json
        print(json.dumps(review_queue(), indent=2))
    else:
        import json
        print(json.dumps(stats(), indent=2))
