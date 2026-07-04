import re
import urllib.parse

import requests

from config import SERPAPI_KEY, SOCIAL_DOMAINS

TIMEOUT = 10

SEARCH_PROVIDERS = [
    {
        "name": "Truecaller",
        "icon": "📞",
        "url": "https://www.truecaller.com/search/in/{}"
    },
    {
        "name": "Sync.me",
        "icon": "👤",
        "url": "https://sync.me/search/?number={}"
    },
    {
        "name": "WhatsApp",
        "icon": "💬",
        "url": "https://wa.me/{}"
    },
    {
        "name": "Telegram",
        "icon": "✈️",
        "url": "https://t.me/+{}"
        # NOTE: only resolves if that user enabled phone-number discovery
        # in their Telegram privacy settings — best-effort manual link.
    },
]


def normalize_phone(phone):
    return re.sub(r"[^\d]", "", phone)


def detect_country(phone):
    if phone.startswith("91"):
        return "India"
    if phone.startswith("1"):
        return "United States / Canada"
    if phone.startswith("44"):
        return "United Kingdom"
    if phone.startswith("81"):
        return "Japan"
    if phone.startswith("61"):
        return "Australia"
    return "Unknown"


def _extract_domain(url):
    try:
        netloc = urllib.parse.urlparse(url).netloc.lower()
        return netloc[4:] if netloc.startswith("www.") else netloc
    except Exception:
        return ""


def _serpapi_search(query, num=15):
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


def check_phone(phone):

    cleaned = normalize_phone(phone)
    results = []

    # 1. Real public search hits mentioning this exact number.
    #    This is the honest ceiling here: it surfaces the number if it's
    #    genuinely published somewhere public (a listing, a forum post,
    #    a business card page). It cannot and will not attempt to probe
    #    which private accounts (WhatsApp, Telegram, etc.) are registered
    #    to this number — that requires enumerating auth/signup systems,
    #    which this project deliberately does not do.
    search_error = None
    found_count = 0

    if SERPAPI_KEY:
        try:
            organic = _serpapi_search(f'"{phone}" OR "{cleaned}"', num=15)
            for item in organic:
                link = item.get("link")
                title = item.get("title", "Result")
                if not link:
                    continue
                domain = _extract_domain(link)
                platform_label = SOCIAL_DOMAINS.get(domain)
                results.append({
                    "platform": platform_label if platform_label else title[:60],
                    "icon": "🔗" if platform_label else "🌐",
                    "url": link,
                    "status": "found",
                    "type": "auto"
                })
                found_count += 1
        except (requests.RequestException, RuntimeError) as e:
            search_error = str(e)[:150]

    # 2. Quick manual lookup links — always included as a fallback path
    for provider in SEARCH_PROVIDERS:
        results.append({
            "platform": provider["name"],
            "icon": provider["icon"],
            "url": provider["url"].format(cleaned),
            "status": "link",
            "type": "manual"
        })

    summary = {
        "country": detect_country(cleaned),
        "normalized": cleaned,
        "public_mentions": found_count,
    }

    if search_error:
        summary["search_note"] = "Web search unavailable: " + search_error
    elif not SERPAPI_KEY:
        summary["search_note"] = "Web search not configured (SERPAPI_KEY missing)"

    summary["breach_note"] = "HIBP does not support phone number lookups — email only"

    score = min(100, found_count * 25)

    return results, score, summary
