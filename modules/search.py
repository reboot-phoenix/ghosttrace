"""
modules/search.py — unified web search with smart routing
-----------------------------------------------------------
Different scan types need different search engines:

  NAME   → Google CSE  (your 41 curated social sites = perfect for names)
            fallback → SerpAPI → DDG

  PHONE  → SerpAPI first (unrestricted Google, finds phone mentions anywhere)
            fallback → DDG
            NOTE: CSE with specific sites NEVER finds phone numbers, skip it.

  EMAIL  → SerpAPI first (same reason as phone)
            fallback → DDG
            NOTE: CSE skipped for same reason.

Free quotas:
  Google CSE : 100 queries/day  (use only for name)
  SerpAPI    : 100 queries/month (use for phone + email)
  DDG        : unlimited but often blocked on cloud IPs
"""

import logging
import urllib.parse
import requests
from config import SERPAPI_KEY, GOOGLE_CSE_KEY, GOOGLE_CSE_ID, SOCIAL_DOMAINS

TIMEOUT = 12
log = logging.getLogger(__name__)


# ── helpers ──────────────────────────────────────────────────

def extract_domain(url: str) -> str:
    try:
        netloc = urllib.parse.urlparse(url).netloc.lower()
        return netloc[4:] if netloc.startswith("www.") else netloc
    except Exception:
        return ""


def _normalise(results: list) -> list:
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


# ── engines ──────────────────────────────────────────────────

def _google_cse(query: str, num: int = 10) -> list:
    """Best for NAME searches — your 41 social sites are ideal for finding people."""
    params = {
        "key": GOOGLE_CSE_KEY,
        "cx":  GOOGLE_CSE_ID,
        "q":   query,
        "num": min(num, 10),
    }
    resp = requests.get(
        "https://www.googleapis.com/customsearch/v1",
        params=params,
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()
    if "error" in data:
        raise RuntimeError(data["error"].get("message", "Google CSE error"))
    return _normalise([
        {"title": i.get("title", ""), "link": i.get("link", ""), "snippet": i.get("snippet", "")}
        for i in (data.get("items") or [])
    ])


def _serpapi(query: str, num: int = 10) -> list:
    """Unrestricted Google search — essential for phone/email where CSE won't find anything."""
    params = {
        "engine":  "google",
        "q":       query,
        "num":     num,
        "api_key": SERPAPI_KEY,
    }
    resp = requests.get("https://serpapi.com/search.json", params=params, timeout=TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    if data.get("error"):
        raise RuntimeError(data["error"])
    return _normalise(data.get("organic_results") or [])


def _ddg(query: str, num: int = 10) -> list:
    """Free fallback — often blocked on Render's shared IPs but worth trying."""
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

def web_search(query: str, num: int = 10, scan_type: str = "name") -> tuple:
    """
    Smart routing based on scan_type:
      'name'          → CSE → SerpAPI → DDG
      'phone'/'email' → SerpAPI → DDG   (CSE skipped — won't find these on specific sites)

    Returns (results, error_string_or_None).
    """
    num = min(num, 10)
    errors = []

    if scan_type == "name":
        # CSE first — your curated 41 social sites are perfect for finding people
        if GOOGLE_CSE_KEY and GOOGLE_CSE_ID:
            try:
                results = _google_cse(query, num)
                if results:
                    return results, None
                log.warning("CSE: 0 results for name query: %s", query)
            except Exception as e:
                errors.append(f"CSE: {e}")
                log.warning("CSE failed: %s", e)

    # For phone/email: skip CSE entirely, go straight to SerpAPI
    if SERPAPI_KEY:
        try:
            results = _serpapi(query, num)
            if results:
                return results, None
            log.warning("SerpAPI: 0 results for: %s", query)
        except Exception as e:
            errors.append(f"SerpAPI: {e}")
            log.warning("SerpAPI failed: %s", e)

    # Last resort
    try:
        results = _ddg(query, num)
        return results, None
    except Exception as e:
        errors.append(f"DDG: {e}")
        return [], " | ".join(errors[-2:])


def build_result_entry(item: dict) -> dict:
    link     = item["link"]
    title    = item.get("title", "Result")
    domain   = extract_domain(link)
    platform = SOCIAL_DOMAINS.get(domain)
    return {
        "platform": platform if platform else title[:60],
        "icon":     "🔗" if platform else "🌐",
        "url":      link,
        "status":   "found",
        "type":     "auto",
    }
