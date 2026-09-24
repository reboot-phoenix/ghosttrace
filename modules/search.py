"""
modules/search.py — web search for GhostTrace v3

Free chain (zero money needed):
  1. Google CSE  — 100 queries/day, free, no card
                   Set GOOGLE_CSE_KEY + GOOGLE_CSE_ID env vars
  2. DuckDuckGo  — unlimited, no key, may be blocked on cloud IPs
"""

import requests
from ddgs import DDGS
from config import GOOGLE_CSE_KEY, GOOGLE_CSE_ID


def search(query: str, max_results: int = 10) -> list[dict]:
    """Return list of {title, link, snippet}. Never raises."""
    results = _google_cse(query, max_results) if (GOOGLE_CSE_KEY and GOOGLE_CSE_ID) else []
    if not results:
        results = _ddg(query, max_results)
    return results[:max_results]


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


def _ddg(query: str, n: int) -> list[dict]:
    try:
        with DDGS() as d:
            return [
                {"title": r.get("title", ""), "link": r.get("href", ""), "snippet": r.get("body", "")}
                for r in d.text(query, max_results=n)
            ]
    except Exception:
        return []
