"""
modules/name.py — name scan
"""

import urllib.parse
from modules.search import web_search, build_result_entry, extract_domain
from config import SOCIAL_DOMAINS


def _name_tokens(name: str) -> list[str]:
    cleaned = name.replace('"', ' ')
    return [t.lower() for t in cleaned.split() if len(t) > 1]


def _matches(text: str, tokens: list[str]) -> bool:
    t = text.lower()
    hits = sum(1 for tok in tokens if tok in t)
    return hits >= max(1, len(tokens) - 1)


def check_name(name: str) -> tuple[list[dict], int, dict]:
    name = name.strip()

    organic, search_error = web_search(name, num=10, scan_type="name")

    if search_error and not organic:
        fallback_url = f"https://www.google.com/search?q={urllib.parse.quote(name)}"
        return (
            [{
                "platform": "Search failed — try Google directly",
                "icon":     "⚠️",
                "url":      fallback_url,
                "status":   "error",
                "type":     "manual",
            }],
            0,
            {"error": search_error},
        )

    # Relevance filter — only keep results that contain the person's name
    name_only = name.split('"')[1] if name.count('"') >= 2 else name
    tokens    = _name_tokens(name_only)

    social_hits, other_hits = [], []
    discarded = 0

    for item in organic:
        link    = item.get("link", "")
        title   = item.get("title", "Result")
        snippet = item.get("snippet", "")
        combined = f"{title} {snippet}"

        if tokens and not _matches(combined, tokens):
            discarded += 1
            continue

        domain   = extract_domain(link)
        platform = SOCIAL_DOMAINS.get(domain)

        entry = {
            "platform": platform if platform else title[:60],
            "icon":     "🔗" if platform else "🌐",
            "url":      link,
            "status":   "found",
            "type":     "auto",
        }
        (social_hits if platform else other_hits).append(entry)

    results = social_hits + other_hits[:8]

    from config import SERPAPI_KEY, GOOGLE_CSE_KEY
    if SERPAPI_KEY:
        engine = "SerpAPI"
    elif GOOGLE_CSE_KEY:
        engine = "Google CSE (free)"
    else:
        engine = "DuckDuckGo (free)"

    summary: dict = {
        "query":          name,
        "social_matches": len(social_hits),
        "total_results":  len(results),
        "filtered_out":   discarded,
        "search_engine":  engine,
    }
    if search_error:
        summary["search_note"] = "Partial results — " + search_error

    score = min(100, len(social_hits) * 20)
    return results, score, summary
