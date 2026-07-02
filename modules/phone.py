import re

SEARCH_PROVIDERS = [
    {
        "name": "Google Search",
        "icon": "🔍",
        "url": "https://www.google.com/search?q={}"
    },
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
    }
    # NOTE: t.me/+<number> only resolves if that user has enabled
    # "Find me by phone number" discovery in Telegram privacy settings.
    # It's not a guaranteed match — kept as a best-effort manual link.
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


def check_phone(phone):

    cleaned = normalize_phone(phone)

    results = []

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

        "length": len(cleaned),

        "normalized": cleaned,

        "providers": len(results)

    }

    score = 50

    return results, score, summary
