"""
modules/phone.py — phone number scan
"""

import re

from modules.search import web_search, build_result_entry

TIMEOUT = 12

MANUAL_LINKS = [
    {"name": "Truecaller",  "icon": "📞", "url": "https://www.truecaller.com/search/in/{}"},
    {"name": "Sync.me",     "icon": "👤", "url": "https://sync.me/search/?number={}"},
    {"name": "WhatsApp",    "icon": "💬", "url": "https://wa.me/{}"},
    {"name": "Telegram",    "icon": "✈️",  "url": "https://t.me/+{}"},
]

COUNTRY_CODES = {
    "91": "India",  "1": "United States / Canada",
    "44": "United Kingdom",   "81": "Japan",
    "61": "Australia",        "971": "UAE",
    "65": "Singapore",        "92": "Pakistan",
    "880": "Bangladesh",      "977": "Nepal",
    "94": "Sri Lanka",        "49": "Germany",
    "33": "France",           "86": "China",
    "7":  "Russia",           "55": "Brazil",
    "27": "South Africa",     "234": "Nigeria",
}


def normalize(phone: str) -> str:
    return re.sub(r"[^\d]", "", phone)


def detect_country(phone: str) -> str:
    for code in sorted(COUNTRY_CODES, key=len, reverse=True):
        if phone.startswith(code):
            return COUNTRY_CODES[code]
    return "Unknown"


def check_phone(phone: str) -> tuple[list[dict], int, dict]:
    cleaned = normalize(phone)
    results: list[dict] = []

    # Web search for public mentions of this number
    organic, search_error = web_search(f'"{phone}" OR "{cleaned}"', num=15)
    found_count = 0
    for item in organic:
        results.append(build_result_entry(item))
        found_count += 1

    # Always include manual deep-links
    for p in MANUAL_LINKS:
        results.append({
            "platform": p["name"],
            "icon":     p["icon"],
            "url":      p["url"].format(cleaned),
            "status":   "link",
            "type":     "manual",
        })

    from config import SERPAPI_KEY
    summary: dict = {
        "country":        detect_country(cleaned),
        "normalized":     cleaned,
        "public_mentions": found_count,
        "search_engine":  "SerpAPI" if SERPAPI_KEY else "DuckDuckGo (free)",
        "breach_note":    "HIBP does not support phone lookups (email only)",
    }
    if search_error:
        summary["search_note"] = "Web search error: " + search_error

    score = min(100, found_count * 25)
    return results, score, summary
