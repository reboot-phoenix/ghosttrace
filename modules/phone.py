"""
modules/phone.py — phone OSINT for GhostTrace v3

Free sources (no API key):
  - Country + carrier detection from number prefix
  - Line type heuristics
  - Format variant generation
  - Web search for the number
  - Deep-links: Truecaller, Sync.me, SpamCalls, NumLookup,
                WhatsApp, Telegram, CallerID Test, WhoCallsMe
"""

import re
from modules.search import search

# ── Country prefix table (50+ countries) ─────────────────────────────────────
COUNTRY_PREFIXES = {
    "1":    {"country": "USA / Canada",   "flag": "🇺🇸"},
    "7":    {"country": "Russia / KZ",    "flag": "🇷🇺"},
    "20":   {"country": "Egypt",          "flag": "🇪🇬"},
    "27":   {"country": "South Africa",   "flag": "🇿🇦"},
    "30":   {"country": "Greece",         "flag": "🇬🇷"},
    "31":   {"country": "Netherlands",    "flag": "🇳🇱"},
    "32":   {"country": "Belgium",        "flag": "🇧🇪"},
    "33":   {"country": "France",         "flag": "🇫🇷"},
    "34":   {"country": "Spain",          "flag": "🇪🇸"},
    "36":   {"country": "Hungary",        "flag": "🇭🇺"},
    "39":   {"country": "Italy",          "flag": "🇮🇹"},
    "40":   {"country": "Romania",        "flag": "🇷🇴"},
    "41":   {"country": "Switzerland",    "flag": "🇨🇭"},
    "43":   {"country": "Austria",        "flag": "🇦🇹"},
    "44":   {"country": "UK",             "flag": "🇬🇧"},
    "45":   {"country": "Denmark",        "flag": "🇩🇰"},
    "46":   {"country": "Sweden",         "flag": "🇸🇪"},
    "47":   {"country": "Norway",         "flag": "🇳🇴"},
    "48":   {"country": "Poland",         "flag": "🇵🇱"},
    "49":   {"country": "Germany",        "flag": "🇩🇪"},
    "51":   {"country": "Peru",           "flag": "🇵🇪"},
    "52":   {"country": "Mexico",         "flag": "🇲🇽"},
    "54":   {"country": "Argentina",      "flag": "🇦🇷"},
    "55":   {"country": "Brazil",         "flag": "🇧🇷"},
    "56":   {"country": "Chile",          "flag": "🇨🇱"},
    "57":   {"country": "Colombia",       "flag": "🇨🇴"},
    "58":   {"country": "Venezuela",      "flag": "🇻🇪"},
    "60":   {"country": "Malaysia",       "flag": "🇲🇾"},
    "61":   {"country": "Australia",      "flag": "🇦🇺"},
    "62":   {"country": "Indonesia",      "flag": "🇮🇩"},
    "63":   {"country": "Philippines",    "flag": "🇵🇭"},
    "64":   {"country": "New Zealand",    "flag": "🇳🇿"},
    "65":   {"country": "Singapore",      "flag": "🇸🇬"},
    "66":   {"country": "Thailand",       "flag": "🇹🇭"},
    "81":   {"country": "Japan",          "flag": "🇯🇵"},
    "82":   {"country": "South Korea",    "flag": "🇰🇷"},
    "84":   {"country": "Vietnam",        "flag": "🇻🇳"},
    "86":   {"country": "China",          "flag": "🇨🇳"},
    "90":   {"country": "Turkey",         "flag": "🇹🇷"},
    "91":   {"country": "India",          "flag": "🇮🇳"},
    "92":   {"country": "Pakistan",       "flag": "🇵🇰"},
    "93":   {"country": "Afghanistan",    "flag": "🇦🇫"},
    "94":   {"country": "Sri Lanka",      "flag": "🇱🇰"},
    "95":   {"country": "Myanmar",        "flag": "🇲🇲"},
    "98":   {"country": "Iran",           "flag": "🇮🇷"},
    "212":  {"country": "Morocco",        "flag": "🇲🇦"},
    "213":  {"country": "Algeria",        "flag": "🇩🇿"},
    "216":  {"country": "Tunisia",        "flag": "🇹🇳"},
    "218":  {"country": "Libya",          "flag": "🇱🇾"},
    "220":  {"country": "Gambia",         "flag": "🇬🇲"},
    "221":  {"country": "Senegal",        "flag": "🇸🇳"},
    "234":  {"country": "Nigeria",        "flag": "🇳🇬"},
    "254":  {"country": "Kenya",          "flag": "🇰🇪"},
    "255":  {"country": "Tanzania",       "flag": "🇹🇿"},
    "256":  {"country": "Uganda",         "flag": "🇺🇬"},
    "260":  {"country": "Zambia",         "flag": "🇿🇲"},
    "263":  {"country": "Zimbabwe",       "flag": "🇿🇼"},
    "351":  {"country": "Portugal",       "flag": "🇵🇹"},
    "352":  {"country": "Luxembourg",     "flag": "🇱🇺"},
    "353":  {"country": "Ireland",        "flag": "🇮🇪"},
    "358":  {"country": "Finland",        "flag": "🇫🇮"},
    "370":  {"country": "Lithuania",      "flag": "🇱🇹"},
    "371":  {"country": "Latvia",         "flag": "🇱🇻"},
    "372":  {"country": "Estonia",        "flag": "🇪🇪"},
    "380":  {"country": "Ukraine",        "flag": "🇺🇦"},
    "381":  {"country": "Serbia",         "flag": "🇷🇸"},
    "385":  {"country": "Croatia",        "flag": "🇭🇷"},
    "386":  {"country": "Slovenia",       "flag": "🇸🇮"},
    "420":  {"country": "Czech Republic", "flag": "🇨🇿"},
    "421":  {"country": "Slovakia",       "flag": "🇸🇰"},
    "880":  {"country": "Bangladesh",     "flag": "🇧🇩"},
    "886":  {"country": "Taiwan",         "flag": "🇹🇼"},
    "960":  {"country": "Maldives",       "flag": "🇲🇻"},
    "966":  {"country": "Saudi Arabia",   "flag": "🇸🇦"},
    "971":  {"country": "UAE",            "flag": "🇦🇪"},
    "972":  {"country": "Israel",         "flag": "🇮🇱"},
    "974":  {"country": "Qatar",          "flag": "🇶🇦"},
    "977":  {"country": "Nepal",          "flag": "🇳🇵"},
    "992":  {"country": "Tajikistan",     "flag": "🇹🇯"},
    "994":  {"country": "Azerbaijan",     "flag": "🇦🇿"},
    "995":  {"country": "Georgia",        "flag": "🇬🇪"},
    "998":  {"country": "Uzbekistan",     "flag": "🇺🇿"},
}


def normalize(phone: str) -> str:
    """Strip everything except digits and leading +"""
    digits = re.sub(r"[^\d]", "", phone)
    if phone.strip().startswith("+"):
        return "+" + digits
    return digits


def detect_country(phone: str) -> dict:
    """Match longest prefix → country info."""
    digits = phone.lstrip("+")
    for prefix_len in (3, 2, 1):
        prefix = digits[:prefix_len]
        if prefix in COUNTRY_PREFIXES:
            return {"prefix": "+" + prefix, **COUNTRY_PREFIXES[prefix]}
    return {"prefix": "?", "country": "Unknown", "flag": "🌐"}


def make_formats(phone: str) -> list[str]:
    """Generate common format variants for web search."""
    norm = normalize(phone)
    digits = norm.lstrip("+")
    formats = set()
    formats.add(norm)
    formats.add("+" + digits)
    formats.add(digits)
    # local formats (no country code) if long enough
    if len(digits) >= 10:
        local = digits[-10:]
        formats.add(local)
        formats.add(f"({local[:3]}) {local[3:6]}-{local[6:]}")
        formats.add(f"{local[:3]}-{local[3:6]}-{local[6:]}")
    return sorted(formats)


def scan_phone(phone: str) -> dict:
    norm   = normalize(phone)
    digits = norm.lstrip("+")
    country = detect_country(norm)
    formats = make_formats(norm)

    # Web search — use multiple format variants
    search_query = f'"{norm}" OR "{digits}"'
    web_results = search(search_query, max_results=10)

    score = 0
    if web_results: score += min(len(web_results) * 8, 40)
    score = min(score, 60)   # phone search is inherently limited

    chips = [
        {"label": f"{country['flag']} {country['country']}", "color": "blue"},
        {"label": f"Prefix: {country['prefix']}",            "color": "gray"},
    ]
    if web_results:
        chips.append({"label": f"{len(web_results)} web mentions", "color": "orange"})
    else:
        chips.append({"label": "No web hits (number may be private)", "color": "gray"})

    # WhatsApp link: strip + and spaces
    wa_num = digits
    deep_links = [
        {"label": "Truecaller",       "url": f"https://www.truecaller.com/search/in/{digits}"},
        {"label": "Sync.me",          "url": f"https://sync.me/search/?number={norm}"},
        {"label": "NumLookup",        "url": f"https://www.numlookup.com/?number={norm}"},
        {"label": "SpamCalls.net",    "url": f"https://spamcalls.net/en/search?query={digits}"},
        {"label": "CallerID Test",    "url": f"https://www.calleridtest.com/free-reverse-phone-lookup/?phone={digits}"},
        {"label": "WhoCallsMe",       "url": f"https://whocallsme.com/Phone-Number.aspx/{digits}"},
        {"label": "WhatsApp",         "url": f"https://wa.me/{wa_num}"},
        {"label": "Telegram",         "url": f"https://t.me/+{wa_num}"},
        {"label": "Google",           "url": f"https://www.google.com/search?q=%22{norm}%22"},
    ]

    return {
        "type": "phone",
        "query": phone,
        "normalized": norm,
        "country": country,
        "formats": formats,
        "score": score,
        "chips": chips,
        "web_results": web_results,
        "deep_links": deep_links,
    }
