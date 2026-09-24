"""
modules/name.py — name OSINT for GhostTrace v3

Strategy: Instead of one weak search, generate targeted Google dork queries
for each major platform + general dorks. Each dork is clickable and pre-built
with the person's name. Also run a web search for auto-results.

No API keys needed. Completely free.
"""

from modules.search import search
from config import SOCIAL_DOMAINS


def scan_name(name: str, filters: list[str] | None = None) -> dict:
    """
    name: "First Last"
    filters: optional list of quoted context strings e.g. ["Kolkata", "Python Developer"]
    """
    name    = name.strip()
    filters = filters or []
    quoted  = f'"{name}"'
    context = " ".join(f'"{f}"' for f in filters if f.strip())
    base    = f"{quoted} {context}".strip()

    # ── Generate dork set ────────────────────────────────────────────────────
    dorks = _build_dorks(name, base)

    # ── Run primary web search ───────────────────────────────────────────────
    web_results = search(base, max_results=12)
    social_hits = [r for r in web_results if any(d in r["link"] for d in SOCIAL_DOMAINS)]
    general_hits = [r for r in web_results if r not in social_hits]

    # ── Score ────────────────────────────────────────────────────────────────
    score = min(len(social_hits) * 20 + len(general_hits) * 8, 100)

    # ── Chips ────────────────────────────────────────────────────────────────
    chips = []
    if social_hits:   chips.append({"label": f"{len(social_hits)} social profiles", "color": "green"})
    if general_hits:  chips.append({"label": f"{len(general_hits)} web mentions",   "color": "blue"})
    if filters:       chips.append({"label": f"Filtered: {', '.join(filters[:2])}", "color": "gray"})
    if not chips:     chips.append({"label": "No results found", "color": "gray"})

    # ── Social deep-links ────────────────────────────────────────────────────
    encoded = name.replace(" ", "%20")
    encoded_plus = name.replace(" ", "+")
    deep_links = [
        {"label": "LinkedIn people search",   "url": f"https://www.linkedin.com/search/results/people/?keywords={encoded_plus}"},
        {"label": "Facebook people search",   "url": f"https://www.facebook.com/search/people/?q={encoded_plus}"},
        {"label": "X (Twitter) search",       "url": f"https://x.com/search?q=%22{encoded}%22&f=user"},
        {"label": "Instagram (Google dork)",  "url": f"https://www.google.com/search?q=site%3Ainstagram.com+%22{encoded}%22"},
        {"label": "TikTok (Google dork)",     "url": f"https://www.google.com/search?q=site%3Atiktok.com+%22{encoded}%22"},
        {"label": "GitHub (Google dork)",     "url": f"https://www.google.com/search?q=site%3Agithub.com+%22{encoded}%22"},
        {"label": "Medium (Google dork)",     "url": f"https://www.google.com/search?q=site%3Amedium.com+%22{encoded}%22"},
        {"label": "Pipl people search",       "url": f"https://pipl.com/search/?q={encoded_plus}"},
        {"label": "Spokeo",                   "url": f"https://www.spokeo.com/search?q={encoded_plus}"},
        {"label": "That's Them",              "url": f"https://thatsthem.com/name/{name.replace(' ', '-').lower()}"},
    ]

    return {
        "type": "name",
        "query": name,
        "filters": filters,
        "score": score,
        "chips": chips,
        "dorks": dorks,
        "web_results": web_results,
        "social_hits": social_hits,
        "general_hits": general_hits,
        "deep_links": deep_links,
    }


def _build_dorks(name: str, base_query: str) -> list[dict]:
    """Build 14 targeted Google dork queries."""
    q = f'"{name}"'
    dorks = [
        {
            "label": "LinkedIn profiles",
            "query": f'{q} site:linkedin.com/in',
            "url": f"https://www.google.com/search?q={q}+site%3Alinkedin.com%2Fin",
            "icon": "💼",
        },
        {
            "label": "GitHub profiles",
            "query": f'{q} site:github.com',
            "url": f"https://www.google.com/search?q={q}+site%3Agithub.com",
            "icon": "🐙",
        },
        {
            "label": "Twitter/X profiles",
            "query": f'{q} site:twitter.com OR site:x.com',
            "url": f"https://www.google.com/search?q={q}+site%3Atwitter.com+OR+site%3Ax.com",
            "icon": "🐦",
        },
        {
            "label": "Instagram profiles",
            "query": f'{q} site:instagram.com',
            "url": f"https://www.google.com/search?q={q}+site%3Ainstagram.com",
            "icon": "📸",
        },
        {
            "label": "Medium articles",
            "query": f'{q} site:medium.com',
            "url": f"https://www.google.com/search?q={q}+site%3Amedium.com",
            "icon": "✍️",
        },
        {
            "label": "Reddit posts/profile",
            "query": f'{q} site:reddit.com',
            "url": f"https://www.google.com/search?q={q}+site%3Areddit.com",
            "icon": "🤖",
        },
        {
            "label": "News articles",
            "query": f'{q} news interview OR article OR press',
            "url": f"https://www.google.com/search?q={q}+news+interview+OR+article",
            "icon": "📰",
        },
        {
            "label": "PDF documents",
            "query": f'{q} filetype:pdf',
            "url": f"https://www.google.com/search?q={q}+filetype%3Apdf",
            "icon": "📄",
        },
        {
            "label": "Email address",
            "query": f'{q} email OR contact "@"',
            "url": f"https://www.google.com/search?q={q}+email+OR+contact+%22%40%22",
            "icon": "📧",
        },
        {
            "label": "Phone number",
            "query": f'{q} phone OR contact OR tel',
            "url": f"https://www.google.com/search?q={q}+phone+OR+contact+OR+tel",
            "icon": "📱",
        },
        {
            "label": "About / bio pages",
            "query": f'{q} inurl:about OR inurl:bio OR inurl:profile',
            "url": f"https://www.google.com/search?q={q}+inurl%3Aabout+OR+inurl%3Abio",
            "icon": "👤",
        },
        {
            "label": "YouTube videos / channel",
            "query": f'{q} site:youtube.com',
            "url": f"https://www.google.com/search?q={q}+site%3Ayoutube.com",
            "icon": "▶️",
        },
        {
            "label": "Academic / research papers",
            "query": f'{q} site:researchgate.net OR site:scholar.google.com OR site:academia.edu',
            "url": f"https://www.google.com/search?q={q}+site%3Aresearchgate.net+OR+site%3Aacademia.edu",
            "icon": "🎓",
        },
        {
            "label": "Images of this person",
            "query": f'{q}',
            "url": f"https://www.google.com/search?q={q}&tbm=isch",
            "icon": "🖼️",
        },
    ]
    return dorks
