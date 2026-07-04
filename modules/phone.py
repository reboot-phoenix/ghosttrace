"""
modules/phone.py — phone number scan
"""

import re
import urllib.parse

from modules.search import web_search, build_result_entry

TIMEOUT = 12

# Manual deep-links — always shown, always clickable.
# These are the real value of phone search since Google/CSE
# suppresses direct phone number queries as PII.
MANUAL_LINKS = [
    {"name": "Truecaller",        "icon": "📞", "url": "https://www.truecaller.com/search/in/{}"},
    {"name": "Sync.me",           "icon": "👤", "url": "https://sync.me/search/?number={}"},
    {"name": "NumLookup",         "icon": "🔍", "url": "https://www.numlookup.com/?number={}"},
    {"name": "WhatsApp",          "icon": "💬", "url": "https://wa.me/{}"},
    {"name": "Telegram",          "icon": "✈️",  "url": "https://t.me/+{}"},
    {"name": "Google (intl fmt)", "icon": "🌐", "url": "https://www.google.com/search?q=%22%2B{}%22"},
    {"name": "Google (raw)",      "icon": "🌐", "url": "https://www.google.com/search?q=%22{}%22"},
    {"name": "PhoneBook (US)",    "icon": "📖", "url": "https://www.whitepages.com/phone/1-{}"},
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
    """Match longest prefix first to avoid e.g. '1' matching before '91'."""
    for code in sorted(COUNTRY_CODES, key=len, reverse=True):
        if digits.startswith(code):
            return COUNTRY_CODES[code]
    return "Unknown"


def _format_variants(digits: str) -> list[str]:
    """
    Build multiple human-readable formats of the phone number.
    Google/CSE blocks bare phone number queries as PII, but searches
    that include the number alongside context words sometimes get through.
    Returning multiple formats also helps match how numbers appear on web pages.
    e.g. 919876543210 → ["+91 9876543210", "+91-9876543210", "09876543210"]
    """
    variants = []
    # Try to split into country code + subscriber number
    for code_len in [3, 2, 1]:
        code = digits[:code_len]
        if code in COUNTRY_CODES:
            subscriber = digits[code_len:]
            variants.append(f"+{code} {subscriber}")       # +91 9876543210
            variants.append(f"+{code}-{subscriber}")      # +91-9876543210
            variants.append(f"+{code}{subscriber}")       # +919876543210
            # Local format with leading 0 (common in many countries)
            variants.append(f"0{subscriber}")             # 09876543210
            break
    # Always include the raw digit string too
    variants.append(digits)
    return variants


def check_phone(phone: str) -> tuple[list[dict], int, dict]:
    cleaned = normalize(phone)
    variants = _format_variants(cleaned)
    intl = variants[0] if variants else f"+{cleaned}"

    results: list[dict] = []
    found_count = 0
    search_error = None

    # ── Web search ───────────────────────────────────────────
    # Google CSE suppresses bare phone number queries as PII.
    # Best workaround: search for the number with context words that
    # would appear on pages that legitimately mention phone numbers
    # (business listings, contact pages, forums, spam reports, etc.)
    # We try two query styles — whichever gets hits first wins.

    search_queries = [
        # Style 1: number with context words — most likely to get CSE results
        f'"{intl}" contact OR listing OR spam OR reported OR review',
        # Style 2: OR across formats — catches pages written in different styles
        " OR ".join(f'"{v}"' for v in variants[:3]),
    ]

    for query in search_queries:
        organic, search_error = web_search(query, num=10)
        if organic:
            for item in organic:
                results.append(build_result_entry(item))
                found_count += 1
            break  # stop once we have results

    # ── Manual deep-links (always added) ─────────────────────
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
        "note":            "Google suppresses direct phone queries — manual links below are the primary tool for phone OSINT.",
        "breach_note":     "HIBP does not support phone lookups (email only)",
    }
    if search_error and not found_count:
        summary["search_note"] = search_error

    score = min(100, found_count * 25 + (30 if found_count == 0 else 0))
    # Give a base score of 30 just for having manual links available,
    # even if no web results came back
    score = max(30, min(100, found_count * 25))
    return results, score, summary
