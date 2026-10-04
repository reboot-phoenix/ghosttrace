"""
modules/search.py — web search for GhostTrace

Engines (all optional except DuckDuckGo, merged and de-duplicated):
  1. Google CSE   100 queries/day free   GOOGLE_CSE_KEY + GOOGLE_CSE_ID
  2. Brave Search optional key           BRAVE_API_KEY   (check Brave's current free tier)
  3. DuckDuckGo   no key; throttled + retried because cloud IPs get rate-limited quickly

Why this matters: firing 14 parallel DuckDuckGo queries from a server IP gets most of them
silently blocked, which looked like "no results". Concurrency is now capped, failures are
retried once, empty answers are never cached, and good answers are cached for 30 minutes.
"""
from __future__ import annotations
import os
import random
import threading
import time

import requests
from ddgs import DDGS
from config import GOOGLE_CSE_KEY, GOOGLE_CSE_ID
from modules.cache import TTLCache

_cache = TTLCache(ttl=1800, max_items=1000)
_ddg_slots = threading.BoundedSemaphore(3)       # at most 3 concurrent DDG queries
_sleep = time.sleep                               # indirection so tests can skip real waits
MIN_GOOD = 3                                      # below this, ask the next engine too


def clear_cache() -> None:
    _cache.clear()


def search(query: str, max_results: int = 10) -> list[dict]:
    """Return list of {title, link, snippet}. Never raises."""
    key = (query, max_results)
    hit = _cache.get(key)
    if hit is not None:
        return hit
    results: list[dict] = []
    try:
        engines = []
        if GOOGLE_CSE_KEY and GOOGLE_CSE_ID:
            engines.append(_google_cse)
        if os.environ.get("BRAVE_API_KEY"):
            engines.append(_brave)
        engines.append(_ddg)
        for engine in engines:
            results = _merge(results, engine(query, max_results))
            if len(results) >= MIN_GOOD:
                break
    except Exception:
        pass
    results = results[:max_results]
    if results:                                   # never cache a failure
        _cache.set(key, results)
    return results


def _merge(a: list[dict], b: list[dict]) -> list[dict]:
    seen = {r["link"] for r in a if r.get("link")}
    return a + [r for r in b if r.get("link") and r["link"] not in seen]


def _google_cse(query: str, n: int) -> list[dict]:
    try:
        r = requests.get(
            "https://www.googleapis.com/customsearch/v1",
            params={"key": GOOGLE_CSE_KEY, "cx": GOOGLE_CSE_ID, "q": query, "num": min(n, 10)},
            timeout=10,
        )
        items = r.json().get("items", [])
        return [{"title": i.get("title", ""), "link": i.get("link", ""), "snippet": i.get("snippet", "")} for i in items]
    except Exception:
        return []


def _brave(query: str, n: int) -> list[dict]:
    try:
        r = requests.get(
            "https://api.search.brave.com/res/v1/web/search",
            params={"q": query, "count": min(n, 20)},
            headers={"Accept": "application/json", "X-Subscription-Token": os.environ["BRAVE_API_KEY"]},
            timeout=10,
        )
        items = (r.json().get("web") or {}).get("results", [])
        return [{"title": i.get("title", ""), "link": i.get("url", ""), "snippet": i.get("description", "")} for i in items]
    except Exception:
        return []


def _ddg(query: str, n: int) -> list[dict]:
    for attempt in range(2):
        with _ddg_slots:
            _sleep(random.uniform(0.1, 0.35))        # gentle spacing
            try:
                with DDGS(timeout=10) as d:
                    rows = list(d.text(query, max_results=n))
                if rows:
                    return [{"title": r.get("title", ""), "link": r.get("href", ""), "snippet": r.get("body", "")}
                            for r in rows]
            except Exception:
                pass
        _sleep(1.2 * (attempt + 1))                  # back off, then retry once
    return []
