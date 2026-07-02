import urllib.parse


def _q(name):
    """URL-encode a name for use in a query string."""
    return urllib.parse.quote(name)


def build_providers(name):
    q = _q(name)
    quoted_q = _q(f'"{name}"')

    return [
        {
            "name": "Google",
            "icon": "🔍",
            "url": f"https://www.google.com/search?q={quoted_q}"
        },
        {
            "name": "Google Images",
            "icon": "🖼️",
            "url": f"https://www.google.com/search?q={quoted_q}&tbm=isch"
        },
        {
            "name": "Bing",
            "icon": "🅱️",
            "url": f"https://www.bing.com/search?q={quoted_q}"
        },
        {
            "name": "DuckDuckGo",
            "icon": "🦆",
            "url": f"https://duckduckgo.com/?q={quoted_q}"
        },
        {
            "name": "Facebook",
            "icon": "👤",
            "url": f"https://www.facebook.com/search/people/?q={q}"
        },
        {
            "name": "Instagram (via Google)",
            "icon": "📸",
            "url": f"https://www.google.com/search?q=site:instagram.com+{quoted_q}"
        },
        {
            "name": "LinkedIn",
            "icon": "💼",
            "url": f"https://www.linkedin.com/search/results/people/?keywords={q}"
        },
        {
            "name": "X (Twitter)",
            "icon": "🐦",
            "url": f"https://twitter.com/search?q={quoted_q}&f=user"
        },
        {
            "name": "YouTube",
            "icon": "🎥",
            "url": f"https://www.youtube.com/results?search_query={q}"
        },
        {
            "name": "GitHub",
            "icon": "🧑‍💻",
            "url": f"https://github.com/search?q={q}&type=users"
        },
        {
            "name": "TruePeopleSearch (US)",
            "icon": "📇",
            "url": f"https://www.truepeoplesearch.com/results?name={q}"
        },
        {
            "name": "All Socials (Google dork)",
            "icon": "🌐",
            "url": (
                f"https://www.google.com/search?q={quoted_q}+"
                "(site:linkedin.com+OR+site:facebook.com+OR+"
                "site:instagram.com+OR+site:twitter.com)"
            )
        },
    ]


def check_name(name):

    name = name.strip()

    providers = build_providers(name)

    results = []

    for provider in providers:

        results.append({

            "platform": provider["name"],

            "icon": provider["icon"],

            "url": provider["url"],

            "status": "link",

            "type": "manual"

        })

    summary = {

        "query": name,

        "platforms": len(results),

        "mode": "search links (not auto-verified)"

    }

    # Not an exposure score — these are generated search links, not
    # confirmed matches. Score reflects link coverage, shown as
    # "search coverage" on the frontend, not "exposure."
    score = 100

    return results, score, summary
