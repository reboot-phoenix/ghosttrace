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


def _name_tokens(name):
    """Extract meaningful name tokens (drop quotes, short words, punctuation)."""
    cleaned = name.replace('"', ' ')
    return [t.lower() for t in cleaned.split() if len(t) > 1]


def _text_matches_name(text, tokens):
    """A result is only relevant if the actual name tokens appear in its
    visible text — filters out unrelated people who happen to share a
    generic surname or turn up in noisy generic web results."""
    text_lower = text.lower()
    matches = sum(1 for t in tokens if t in text_lower)
    return matches >= max(1, len(tokens) - 1)  # allow 1 missing token (e.g. middle name)


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
                "url": f"https://www.google.com/search?q={urllib.parse.quote(name)}",
                "status": "error",
                "type": "manual"
            }],
            0,
            {"error": "SERPAPI_KEY not configured on server"}
        )

    try:
        # `name` may already contain multiple quoted phrases built by the
        # frontend, e.g.  "John Doe" "Stanford University" "Bengaluru"
        # — passed through as-is so each phrase filters independently.
        organic = _serpapi_search(name, num=20)
    except (requests.RequestException, RuntimeError) as e:
        return (
            [{
                "platform": "Search failed",
                "icon": "⚠️",
                "url": f"https://www.google.com/search?q={urllib.parse.quote(name)}",
                "status": "error",
                "type": "manual"
            }],
            0,
            {"error": str(e)[:150]}
        )

    # Only the actual person's-name portion is used for relevance checks —
    # filter tokens (college/location/etc.) already narrowed the search
    # itself and shouldn't also gate individual result relevance.
    name_only = name.split('"')[1] if name.count('"') >= 2 else name
    name_tokens = _name_tokens(name_only)

    social_hits = []
    other_hits = []
    discarded = 0

    for item in organic:
        link = item.get("link")
        title = item.get("title", "Result")
        snippet = item.get("snippet", "")
        if not link:
            continue

        combined_text = f"{title} {snippet}"
        if name_tokens and not _text_matches_name(combined_text, name_tokens):
            discarded += 1
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
        "filtered_out": discarded,
    }

    score = min(100, len(social_hits) * 20)

    return results, score, summary
