"""
modules/phone.py — phone number scan
"""

import re
import urllib.parse

from modules.search import web_search, build_result_entry

TIMEOUT = 12

# Manual deep-links — always included regardless of search results.
# These never fail since they are just pre-filled URLs the user clicks.
MANUAL_LINKS = [
    {"name": "Truecaller",     "icon": "📞", "url": "https://www.truecaller.com/search/in/{}"},
    {"name": "Sync.me",        "icon": "👤", "url": "https://sync.me/search/?number={}"},
    {"name": "NumLookup",      "icon": "🔍", "url": "https://www.numlookup.com/?number={}"},
    {"name": "WhatsApp",       "icon": "💬", "url": "https://wa.me/{}"},
    {"name": "Telegram",       "icon": "✈️",  "url": "https://t.me/+{}"},
    {"name": "PhoneBook (US)", "icon": "📖", "url": "https://www.whitepages.com/phone/1-{}"},
    {"name": "Google Search",  "icon": "🌐", "url": "https://www.google.com/search?q=%22%2B{}%22"},
]

COUNTRY_CODES = {
    "91":  "India",
    "1":   "United States / Canada",
    "44":  "United Kingdom",
    "81":  "Japan",
    "61":  "Australia",
    "971": "UAE",
    "65":  "Singapore",
    "92":  "Pakistan",
    "880": "Bangladesh",
    "977": "Nepal",
    "94":  "Sri Lanka",
    "49":  "Germany",
    "33":  "France",
    "86":  "China",
    "7":   "Russia",
    "55":  "Brazil",
    "27":  "South Africa",
    "234": "Nigeria",
    "20":  "Egypt",
    "62":  "Indonesia",
    "60":  "Malaysia",
    "66":  "Thailand",
    "84":  "Vietnam",
    "82":  "South Korea",
    "886": "Taiwan",
    "63":  "Philippines",
    "64":  "New Zealand",
    "39":  "Italy",
    "34":  "Spain",
    "31":  "Netherlands",
    "32":  "Belgium",
    "41":  "Switzerland",
    "46":  "Sweden",
    "47":  "Norway",
    "45":  "Denmark",
    "358": "Finland",
    "48":  "Poland",
    "380": "Ukraine",
    "90":  "Turkey",
    "972": "Israel",
    "966": "Saudi Arabia",
    "98":  "Iran",
    "93":  "Afghanistan",
}


def normalize(phone: str) -> str:
    """Strip all non-digit characters."""
    return re.sub(r"[^\d]", "", phone)


def detect_country(digits: str) -> str:
    """Match longest prefix first to avoid false matches (e.g. '1' vs '91')."""
    for code in sorted(COUNTRY_CODES, key=len, reverse=True):
        if digits.startswith(code):
            return COUNTRY_CODES[code]
    return "Unknown"


def check_phone(phone: str) -> tuple[list[dict], int, dict]:
    cleaned = normalize(phone)
    # Build a version with leading + for international format
    intl = f"+{cleaned}"

    results: list[dict] = []

    # ── Web search for public mentions ───────────────────────
    # Search for both the raw digits and international format
    query = f'"{intl}" OR "{cleaned}"'
    organic, search_error = web_search(query, num=10)

    found_count = 0
    for item in organic:
        results.append(build_result_entry(item))
        found_count += 1

    # ── Always include manual deep-links ─────────────────────
    for p in MANUAL_LINKS:
        results.append({
            "platform": p["name"],
            "icon":     p["icon"],
            "url":      p["url"].format(cleaned),
            "status":   "link",
            "type":     "manual",
        })

    # ── Summary ───────────────────────────────────────────────
    from config import SERPAPI_KEY, GOOGLE_CSE_KEY
    if SERPAPI_KEY:
        engine = "SerpAPI"
    elif GOOGLE_CSE_KEY:
        engine = "Google CSE (free)"
    else:
        engine = "DuckDuckGo (free)"

    summary: dict = {
        "country":         detect_country(cleaned),
        "normalized":      cleaned,
        "international":   intl,
        "public_mentions": found_count,
        "search_engine":   engine,
        "breach_note":     "HIBP does not support phone lookups (email only)",
    }
    if search_error:
        summary["search_note"] = search_error

    score = min(100, found_count * 25)
    return results, score, summary
