import urllib.parse

import requests

from config import SERPAPI_KEY, SOCIAL_DOMAINS

TIMEOUT = 10


def _extract_domain(url):
    try:
        netloc = urllib.parse.urlparse(url).netloc.lower()
        return netloc[4:] if netloc.startswith("www.") else netloc
    except Exception:
        return ""


def _serpapi_search(query, num=15):
    """Real search via SerpApi. Returns list of {title, link, snippet}."""
    params = {
        "engine": "google",
        "q": query,
        "num": num,
        "api_key": SERPAPI_KEY,
    }
    resp = requests.get("https://serpapi.com/search.json", params=params, timeout=TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    if data.get("error"):
        raise RuntimeError(data["error"])
    return data.get("organic_results", []) or []


def check_name(name):

    name = name.strip()
    results = []

    if not SERPAPI_KEY:
        # No key configured — fail loudly in the summary rather than
        # silently pretending to have searched anything.
        return (
            [{
                "platform": "Search unavailable",
                "icon": "⚠️",
                "url": f"https://www.google.com/search?q=%22{urllib.parse.quote(name)}%22",
                "status": "error",
                "type": "manual"
            }],
            0,
            {"error": "SERPAPI_KEY not configured on server"}
        )

    try:
        organic = _serpapi_search(f'"{name}"', num=20)
    except (requests.RequestException, RuntimeError) as e:
        return (
            [{
                "platform": "Search failed",
                "icon": "⚠️",
                "url": f"https://www.google.com/search?q=%22{urllib.parse.quote(name)}%22",
                "status": "error",
                "type": "manual"
            }],
            0,
            {"error": str(e)[:150]}
        )

    social_hits = []
    other_hits = []

    for item in organic:
        link = item.get("link")
        title = item.get("title", "Result")
        if not link:
            continue
        domain = _extract_domain(link)
        platform_label = SOCIAL_DOMAINS.get(domain)

        entry = {
            "platform": platform_label if platform_label else title[:60],
            "icon": "🔗" if platform_label else "🌐",
            "url": link,
            "status": "found",
            "type": "auto"
        }

        if platform_label:
            social_hits.append(entry)
        else:
            other_hits.append(entry)

    results = social_hits + other_hits[:8]  # cap generic web hits, keep social ones all

    summary = {
        "query": name,
        "social_matches": len(social_hits),
        "total_results": len(results),
    }

    score = min(100, len(social_hits) * 20)

    return results, score, summary
