"""
modules/name.py — name OSINT for GhostTrace v3

Runs ALL 14 dork searches in parallel and returns actual results
for each platform — not just links, real data.
"""

import concurrent.futures
from modules.search import search
from modules.name_match import filter_results
from config import SOCIAL_DOMAINS


_DORK_DEFINITIONS = [
    {"label": "LinkedIn profiles",        "icon": "💼", "key": "linkedin",  "query_tpl": '"{name}" site:linkedin.com/in'},
    {"label": "GitHub profiles",          "icon": "🐙", "key": "github",    "query_tpl": '"{name}" site:github.com'},
    {"label": "Twitter / X profiles",     "icon": "🐦", "key": "twitter",   "query_tpl": '"{name}" site:twitter.com OR site:x.com'},
    {"label": "Instagram profiles",       "icon": "📸", "key": "instagram", "query_tpl": '"{name}" site:instagram.com'},
    {"label": "Reddit posts / profile",   "icon": "🤖", "key": "reddit",    "query_tpl": '"{name}" site:reddit.com'},
    {"label": "YouTube channel / videos", "icon": "▶️", "key": "youtube",   "query_tpl": '"{name}" site:youtube.com'},
    {"label": "Medium articles",          "icon": "✍️", "key": "medium",    "query_tpl": '"{name}" site:medium.com'},
    {"label": "News & press coverage",    "icon": "📰", "key": "news",      "query_tpl": '"{name}" news OR interview OR press OR article'},
    {"label": "PDF documents",            "icon": "📄", "key": "pdf",       "query_tpl": '"{name}" filetype:pdf'},
    {"label": "Email address discovery",  "icon": "📧", "key": "email",     "query_tpl": '"{name}" email OR contact "@"'},
    {"label": "Phone number discovery",   "icon": "📱", "key": "phone",     "query_tpl": '"{name}" phone OR tel OR contact'},
    {"label": "About / bio pages",        "icon": "👤", "key": "about",     "query_tpl": '"{name}" inurl:about OR inurl:bio OR inurl:profile'},
    {"label": "Academic papers",          "icon": "🎓", "key": "academic",  "query_tpl": '"{name}" site:researchgate.net OR site:academia.edu OR site:scholar.google.com'},
    {"label": "Images",                   "icon": "🖼️", "key": "images",    "query_tpl": '"{name}"'},
]


# Fast mode spends 5 searches instead of 14, so a 100/day search quota lasts ~20 scans, not ~7.
FAST_DORKS = {"linkedin", "github", "twitter", "instagram", "images"}


def _run_dork(dork_def: dict, name: str, context: str) -> dict:
    """Run a single dork search and return results."""
    query = dork_def["query_tpl"].format(name=name)
    if context:
        query = f"{query} {context}"
    raw = search(query, max_results=10)
    # Keep only results that really contain the full name; search engines return look-alikes
    results, discarded = filter_results(name, raw)
    results = results[:5]
    return {
        "label":   dork_def["label"],
        "icon":    dork_def["icon"],
        "key":     dork_def["key"],
        "query":   query,
        "url":     f"https://www.google.com/search?q={query.replace(' ', '+')}",
        "results": results,
        "found":   len(results) > 0,
        "count":   len(results),
        "discarded": discarded,
    }


def scan_name(name: str, filters: list[str] | None = None, mode: str = "deep") -> dict:
    name    = name.strip()
    filters = filters or []
    context = " ".join(f'"{f}"' for f in filters if f.strip())

    defs = [d for d in _DORK_DEFINITIONS if mode == "deep" or d["key"] in FAST_DORKS]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(defs)) as pool:
        futures = [pool.submit(_run_dork, d, name, context) for d in defs]
        dork_results = [f.result() for f in concurrent.futures.as_completed(futures)]

    # Sort back to original order
    order = {d["key"]: i for i, d in enumerate(defs)}
    dork_results.sort(key=lambda x: order.get(x["key"], 99))

    # Flatten all results for scoring
    all_results = []
    for d in dork_results:
        for r in d["results"]:
            r["_source"] = d["key"]
            all_results.append(r)

    social_hits  = [r for r in all_results if any(dom in r["link"] for dom in SOCIAL_DOMAINS)]
    general_hits = [r for r in all_results if r not in social_hits]
    dorks_with_results = [d for d in dork_results if d["found"]]

    score = min(len(social_hits) * 15 + len(general_hits) * 5 + len(dorks_with_results) * 3, 100)

    chips = []
    if social_hits:         chips.append({"label": f"{len(social_hits)} social profiles found",    "color": "green"})
    if general_hits:        chips.append({"label": f"{len(general_hits)} web mentions",            "color": "blue"})
    if dorks_with_results:  chips.append({"label": f"{len(dorks_with_results)}/{len(defs)} platforms hit",  "color": "orange"})
    discarded_total = sum(d.get("discarded", 0) for d in dork_results)
    if discarded_total:     chips.append({"label": f"{discarded_total} look-alike results discarded", "color": "gray"})
    if filters:             chips.append({"label": f"Context: {', '.join(filters[:2])}",           "color": "gray"})
    if not chips:           chips.append({"label": "No results found",                             "color": "gray"})

    encoded_plus = name.replace(" ", "+")
    encoded      = name.replace(" ", "%20")
    deep_links = [
        {"label": "LinkedIn people search", "url": f"https://www.linkedin.com/search/results/people/?keywords={encoded_plus}"},
        {"label": "Facebook people search", "url": f"https://www.facebook.com/search/people/?q={encoded_plus}"},
        {"label": "X (Twitter) search",     "url": f"https://x.com/search?q=%22{encoded}%22&f=user"},
    ]

    return {
        "type":         "name",
        "query":        name,
        "filters":      filters,
        "score":        score,
        "chips":        chips,
        "discarded":    discarded_total,
        "dork_results": dork_results,
        "social_hits":  social_hits,
        "general_hits": general_hits,
        "all_results":  all_results,
        "deep_links":   deep_links,
    }
