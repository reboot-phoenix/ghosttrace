"""
modules/pipeline.py — the scan pipeline (used by both /scan and background jobs).

Stages report real progress, every external source has a hard timeout, independent checks
run concurrently, and finished results are cached for 10 minutes.
"""
from __future__ import annotations
import logging
import time

from modules.cache import TTLCache
from modules.timeouts import ScanTimeout, run_with_timeout, gather
from modules.correlate import correlate
from modules.report import build_report
from modules.scam import assess as assess_scam
from modules.threat_feeds import check as check_feeds
from modules.page_analysis import analyze as analyze_page, first_seen
from modules.web_mentions import scam_mentions
from modules import reports as report_db

log = logging.getLogger("ghosttrace.pipeline")

_cache = TTLCache(ttl=600, max_items=300)
SCAN_TIMEOUT = {"fast": 60, "deep": 110}
CORR_TIMEOUT = {"fast": 40, "deep": 75}

_STEP = {
    "email":    "Checking Gravatar, breaches, Holehe and web search",
    "username": "Checking developer, social and gaming platforms (Maigret in deep mode)",
    "phone":    "Parsing number and searching the web",
    "name":     "Searching the web for the exact name",
    "ip":       "Geolocating, Shodan InternetDB and RDAP",
    "domain":   "Resolving DNS, certificates, WHOIS/RDAP",
    "upi":      "Validating UPI ID",
}


def clear_cache() -> None:
    _cache.clear()


def run_scan(p: dict, scanners: dict, sign, progress=lambda label: None) -> dict:
    query, st, mode = p["query"], p["scan_type"], p["mode"]
    filters, url = p.get("filters") or [], p.get("original_url")

    key = (st, query, mode, tuple(filters), url)
    hit = _cache.get(key)
    if hit is not None:
        progress("Loaded a recent identical result")
        return hit

    # 1 ── main scan -------------------------------------------------------
    progress(_STEP.get(st, "Running scan"))
    if st == "upi":
        raw = {"type": "upi", "query": query, "score": 0, "chips": []}
    else:
        fn = scanners[st]
        args = (query, filters, mode) if st == "name" else (query,)
        try:
            raw = run_with_timeout(fn, SCAN_TIMEOUT[mode], *args)
        except ScanTimeout:
            raise ScanTimeout("The scan took too long and was stopped. Try Fast mode, or try again.")
    raw["scan_type"], raw["timestamp"], raw["mode"] = st, int(time.time()), mode

    skipped: list[str] = []

    # 2 ── correlation + report -------------------------------------------
    if st == "upi":
        correlation = {"identity": {}, "findings": [], "pivots": []}
    else:
        progress("Correlating findings" + (" and pivoting on discovered identities" if mode == "deep" else ""))
        try:
            correlation = run_with_timeout(correlate, CORR_TIMEOUT[mode], raw, deep=(mode == "deep"))
        except Exception as e:
            log.warning("correlation skipped: %s", type(e).__name__)
            correlation = {"identity": {}, "findings": [], "pivots": []}
            skipped.append("Correlation")
    report = build_report(raw, correlation, scan_mode=mode)

    # 3 ── scam indicators: concurrent, each source on its own deadline ----
    ctx: dict = {}
    feeds = {"hits": [], "sources_checked": []}
    if st in ("phone", "upi", "email", "domain", "ip") or url:
        progress("Checking scam indicators"
                 + (": threat feeds, page contents, site history, web reports" if mode == "deep" else ": threat feeds and community reports"))
    if st in ("phone", "upi", "email", "domain"):
        try:
            ctx["reports"] = report_db.summary(st, query)
        except Exception:
            log.exception("report lookup failed")
    if st == "domain":
        rdap = raw.get("rdap") or {}
        ctx.update(domain_created=rdap.get("registered") or None, has_rdap=bool(rdap))

    tasks: dict = {}
    target = url or query
    if st == "domain":
        tasks["feeds"] = (check_feeds, (target,), 10)
        if mode == "deep":
            tasks["page"] = (analyze_page, (url or f"https://{query}",), 15)
            tasks["history"] = (first_seen, (query,), 8)
    if mode == "deep" and st in ("phone", "upi", "email", "domain"):
        tasks["web"] = (scam_mentions, (st, query), 15)
    res = gather(tasks) if tasks else {}

    LABEL = {"feeds": "Threat feeds", "page": "Page analysis", "history": "Site history", "web": "Web check"}
    for name, r in res.items():
        if not r["ok"]:
            skipped.append(f"{LABEL[name]} ({r['error']})")
    if res.get("feeds", {}).get("ok"):
        feeds = res["feeds"]["value"]
        ctx["feed_hits"] = feeds["hits"]
    if res.get("page", {}).get("ok"):
        ctx["page"] = res["page"]["value"]
        if res.get("history", {}).get("ok"):
            ctx["first_seen"] = res["history"]["value"]
        else:
            ctx["first_seen"] = None
    if res.get("web", {}).get("ok"):
        ctx["web"] = res["web"]["value"]

    # 4 ── verdict ----------------------------------------------------------
    progress("Scoring")
    scam_risk = assess_scam("url" if url else st, target, ctx)
    scam_risk.update(
        feeds=feeds, mode=mode,
        deep_available=st in ("domain", "phone", "upi", "email"),
        indicator={"kind": st, "value": query} if st in ("phone", "upi", "email", "domain") else None,
        reports=ctx.get("reports"), web=ctx.get("web"), skipped=skipped,
    )
    if ctx.get("page"):
        scam_risk["page"] = ctx["page"]
        scam_risk["first_seen"] = ctx.get("first_seen")

    payload = {**raw, "correlation": correlation, "report": report, "scam_risk": scam_risk}
    payload["_sig"] = sign(payload)
    if not skipped:               # never cache a partial result
        _cache.set(key, payload)
    return payload
