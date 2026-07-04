"""
search.py — unified web search module
--------------------------------------
Priority:
  1. SerpAPI  (paid, if SERPAPI_KEY is set)
  2. DuckDuckGo  (free, no key needed, via ddgs package)

Both return a list of dicts: {title, link, snippet}
"""

import logging
import urllib.parse

import requests

from config import SERPAPI_KEY, SOCIAL_DOMAINS

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


# ── SerpAPI ─────────────────────────────────────────────────

def _serpapi(query: str, num: int = 15) -> list[dict]:
    params = {
        "engine": "google",
        "q":      query,
        "num":    num,
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


# ── DuckDuckGo ───────────────────────────────────────────────

def _ddg(query: str, num: int = 15) -> list[dict]:
    """
    Uses the `ddgs` package (free, no key).
    ddgs can throw on rate limits — caller handles that.
    """
    try:
        from ddgs import DDGS
    except ImportError:
        # Try old package name as fallback
        from duckduckgo_search import DDGS  # type: ignore

    results = []
    with DDGS() as ddgs:
        for r in ddgs.text(query, max_results=num):
            results.append(r)
    return _normalise(results)


# ── Public interface ─────────────────────────────────────────

def web_search(query: str, num: int = 15) -> tuple[list[dict], str | None]:
    """
    Returns (results, error_string_or_None).

    Tries SerpAPI first if a key is configured, falls back to DDG.
    """
    if SERPAPI_KEY:
        try:
            return _serpapi(query, num), None
        except Exception as e:
            log.warning("SerpAPI failed (%s), falling back to DDG", e)

    try:
        return _ddg(query, num), None
    except Exception as e:
        return [], str(e)[:150]


def build_result_entry(item: dict) -> dict:
    """Turn a raw search hit into a GhostTrace result dict."""
    link  = item["link"]
    title = item.get("title", "Result")
    domain = extract_domain(link)
    platform = SOCIAL_DOMAINS.get(domain)
    return {
        "platform": platform if platform else title[:60],
        "icon":     "🔗" if platform else "🌐",
        "url":      link,
        "status":   "found",
        "type":     "auto",
    }
