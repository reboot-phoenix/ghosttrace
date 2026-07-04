"""
modules/phone.py — phone number scan
"""

import re
import urllib.parse

from modules.search import web_search, build_result_entry

TIMEOUT = 12

COUNTRY_CODES = {
    "91":  ("India",                "in"),
    "1":   ("United States / Canada", "us"),
    "44":  ("United Kingdom",       "gb"),
    "81":  ("Japan",                "jp"),
    "61":  ("Australia",            "au"),
    "971": ("UAE",                  "ae"),
    "65":  ("Singapore",            "sg"),
    "92":  ("Pakistan",             "pk"),
    "880": ("Bangladesh",           "bd"),
    "977": ("Nepal",                "np"),
    "94":  ("Sri Lanka",            "lk"),
    "49":  ("Germany",              "de"),
    "33":  ("France",               "fr"),
    "86":  ("China",                "cn"),
    "7":   ("Russia",               "ru"),
    "55":  ("Brazil",               "br"),
    "27":  ("South Africa",         "za"),
    "234": ("Nigeria",              "ng"),
    "20":  ("Egypt",                "eg"),
    "62":  ("Indonesia",            "id"),
    "60":  ("Malaysia",             "my"),
    "66":  ("Thailand",             "th"),
    "84":  ("Vietnam",              "vn"),
    "82":  ("South Korea",          "kr"),
    "886": ("Taiwan",               "tw"),
    "63":  ("Philippines",          "ph"),
    "64":  ("New Zealand",          "nz"),
    "39":  ("Italy",                "it"),
    "34":  ("Spain",                "es"),
    "31":  ("Netherlands",          "nl"),
    "32":  ("Belgium",              "be"),
    "41":  ("Switzerland",          "ch"),
    "46":  ("Sweden",               "se"),
    "47":  ("Norway",               "no"),
    "45":  ("Denmark",              "dk"),
    "358": ("Finland",              "fi"),
    "48":  ("Poland",               "pl"),
    "380": ("Ukraine",              "ua"),
    "90":  ("Turkey",               "tr"),
    "972": ("Israel",               "il"),
    "966": ("Saudi Arabia",         "sa"),
    "98":  ("Iran",                 "ir"),
    "93":  ("Afghanistan",          "af"),
}


def normalize(phone: str) -> str:
    return re.sub(r"[^\d]", "", phone)


def parse_phone(digits: str) -> tuple:
    """
    Split full digit string into (country_code, local_number, country_name, tc_region).
    Matches longest prefix first to avoid e.g. '1' swallowing '91'.
    Returns ('', digits, 'Unknown', 'us') if no match.
    """
    for code in sorted(COUNTRY_CODES, key=len, reverse=True):
        if digits.startswith(code):
            name, region = COUNTRY_CODES[code]
            return code, digits[len(code):], name, region
    return "", digits, "Unknown", "us"


def check_phone(phone: str) -> tuple:
    full_digits = normalize(phone)          # e.g. "911800114000"
    country_code, local, country_name, tc_region = parse_phone(full_digits)

    intl = f"+{full_digits}"               # e.g. "+911800114000"

    results = []

    # ── Web search ────────────────────────────────────────────
    query = f'"{intl}" OR "{full_digits}"'
    organic, search_error = web_search(query, num=10, scan_type="phone")

    found_count = 0
    for item in organic:
        results.append(build_result_entry(item))
        found_count += 1

    # ── Manual deep-links ─────────────────────────────────────
    # Use correct variables per platform:
    #   full_digits  = country code + local  (for WhatsApp, Telegram, Sync.me)
    #   local        = digits WITHOUT country code  (for Truecaller)
    #   tc_region    = ISO country code  (for Truecaller URL path)

    encoded_intl  = urllib.parse.quote(intl)
    encoded_full  = urllib.parse.quote(full_digits)

    manual_links = [
        {
            "name": "Truecaller",
            "icon": "📞",
            # Truecaller expects local number (no country code) + region path
            "url":  f"https://www.truecaller.com/search/{tc_region}/{local}",
        },
        {
            "name": "Sync.me",
            "icon": "👤",
            "url":  f"https://sync.me/search/?number={encoded_full}",
        },
        {
            "name": "NumLookup",
            "icon": "🔍",
            "url":  f"https://www.numlookup.com/?number={encoded_intl}",
        },
        {
            "name": "WhatsApp",
            "icon": "💬",
            "url":  f"https://wa.me/{full_digits}",
        },
        {
            "name": "Telegram",
            "icon": "✈️",
            "url":  f"https://t.me/+{full_digits}",
        },
        {
            "name": "Google Search",
            "icon": "🌐",
            "url":  f"https://www.google.com/search?q=%22{encoded_intl}%22",
        },
    ]

    # Only add US phonebook link if the number is actually US/Canada
    if country_code == "1":
        manual_links.append({
            "name": "WhitePages (US)",
            "icon": "📖",
            "url":  f"https://www.whitepages.com/phone/1-{local}",
        })

    for p in manual_links:
        results.append({
            "platform": p["name"],
            "icon":     p["icon"],
            "url":      p["url"],
            "status":   "link",
            "type":     "manual",
        })

    # ── Summary ───────────────────────────────────────────────
    from config import SERPAPI_KEY, GOOGLE_CSE_KEY
    engine = "SerpAPI" if SERPAPI_KEY else ("Google CSE" if GOOGLE_CSE_KEY else "DuckDuckGo")

    summary = {
        "country":         country_name,
        "public_mentions": found_count,
        "search_engine":   engine,
    }
    if search_error:
        summary["search_note"] = search_error

    score = min(100, found_count * 25)
    return results, score, summary
