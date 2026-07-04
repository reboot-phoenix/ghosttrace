"""
modules/search.py — unified web search
----------------------------------------
Priority order (first working source wins):
  1. SerpAPI       — paid key, 100 free searches/month
  2. Google CSE    — free, 100 queries/day (RECOMMENDED free option)
  3. DuckDuckGo    — free, no key, but often blocked on cloud IPs

Both SerpAPI and Google CSE are reliable on Render.com.
DuckDuckGo is a last-resort fallback and may return empty results.

Set in Render environment variables:
  SERPAPI_KEY    — your SerpAPI key
  GOOGLE_CSE_KEY — Google API key with Custom Search enabled
  GOOGLE_CSE_ID  — your Search Engine ID (cx value)
"""

import logging
import urllib.parse

import requests

from config import SERPAPI_KEY, GOOGLE_CSE_KEY, GOOGLE_CSE_ID, SOCIAL_DOMAINS

TIMEOUT = 12
log = logging.getLogger(__name__)


# ── helpers ─────────────────────────────────────────────────

def extract_domain(url: str) -> str:
    try:
        netloc = urllib.parse.urlparse(url).netloc.lower()
        return netloc[4:] if netloc.startswith("www.") else netloc
    except Exception:
        return ""


def _normalise(results: list[dict]) -> list[dict]:
    """Ensure every result has title/link/snippet keys."""
    out = []
    for r in results:
        link = r.get("link") or r.get("href") or r.get("url", "")
        if not link:
            continue
        out.append({
            "title":   r.get("title", ""),
            "link":    link,
            "snippet": r.get("snippet") or r.get("body") or "",
        })
    return out


# ── 1. SerpAPI ───────────────────────────────────────────────

def _serpapi(query: str, num: int = 10) -> list[dict]:
    params = {
        "engine":  "google",
        "q":       query,
        "num":     num,
        "api_key": SERPAPI_KEY,
    }
    resp = requests.get(
        "https://serpapi.com/search.json", params=params, timeout=TIMEOUT
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("error"):
        raise RuntimeError(data["error"])
    return _normalise(data.get("organic_results") or [])


# ── 2. Google Custom Search Engine ───────────────────────────

def _google_cse(query: str, num: int = 10) -> list[dict]:
    """
    Google Custom Search JSON API.
    Free tier: 100 queries/day, no credit card needed.
    Max 10 results per request (Google hard limit).
    Setup:
      1. Go to https://programmablesearchengine.google.com
         Create a search engine, set it to search the entire web.
         Copy the Search Engine ID (cx value) → GOOGLE_CSE_ID
      2. Go to https://console.cloud.google.com
         Enable "Custom Search API", create an API key → GOOGLE_CSE_KEY
    """
    params = {
        "key": GOOGLE_CSE_KEY,
        "cx":  GOOGLE_CSE_ID,
        "q":   query,
        "num": min(num, 10),  # CSE hard limit is 10 per call
    }
    resp = requests.get(
        "https://www.googleapis.com/customsearch/v1",
        params=params,
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    items = resp.json().get("items") or []
    return _normalise([
        {
            "title":   i.get("title", ""),
            "link":    i.get("link", ""),
            "snippet": i.get("snippet", ""),
        }
        for i in items
    ])


# ── 3. DuckDuckGo fallback ───────────────────────────────────

def _ddg(query: str, num: int = 10) -> list[dict]:
    """
    Uses the ddgs package (free, no key).
    Often blocked on shared cloud IPs — treat as last resort.
    """
    try:
        from ddgs import DDGS
    except ImportError:
        from duckduckgo_search import DDGS  # type: ignore

    results = []
    with DDGS() as ddgs:
        for r in ddgs.text(query, max_results=num):
            results.append(r)
    return _normalise(results)


# ── Public interface ─────────────────────────────────────────

def web_search(query: str, num: int = 10) -> tuple[list[dict], str | None]:
    """
    Returns (results, error_string_or_None).

    Tries configured sources in priority order:
      SerpAPI → Google CSE → DuckDuckGo

    num is capped at 10 for Google CSE compatibility.
    SerpAPI and DDG also get 10 to keep quota usage consistent.
    """
    num = min(num, 10)  # cap across all engines to be quota-friendly

    # 1. SerpAPI
    if SERPAPI_KEY:
        try:
            results = _serpapi(query, num)
            if results:
                return results, None
            log.warning("SerpAPI returned empty results, trying next source")
        except Exception as e:
            log.warning("SerpAPI failed (%s), trying Google CSE", e)

    # 2. Google CSE
    if GOOGLE_CSE_KEY and GOOGLE_CSE_ID:
        try:
            results = _google_cse(query, num)
            if results:
                return results, None
            log.warning("Google CSE returned empty results, trying DDG")
        except Exception as e:
            log.warning("Google CSE failed (%s), falling back to DDG", e)

    # 3. DuckDuckGo (last resort)
    try:
        results = _ddg(query, num)
        return results, None
    except Exception as e:
        return [], f"All search sources failed. Last error: {str(e)[:120]}"


def build_result_entry(item: dict) -> dict:
    """Turn a raw search hit into a GhostTrace result dict."""
    link    = item["link"]
    title   = item.get("title", "Result")
    domain  = extract_domain(link)
    platform = SOCIAL_DOMAINS.get(domain)
    return {
        "platform": platform if platform else title[:60],
        "icon":     "🔗" if platform else "🌐",
        "url":      link,
        "status":   "found",
        "type":     "auto",
    }
