import requests

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}

AUTO_PLATFORMS = [
    {"name": "GitHub", "url": "https://github.com/{}", "not_found_text": "not found"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}", "not_found_text": "nobody on reddit goes by that name"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{}", "not_found_text": "couldn't find this account"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}", "not_found_text": "sorry! we couldn't find that page"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{}", "not_found_text": "sorry. unless you've got a time machine"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{}", "not_found_text": "this page isn't available"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}", "not_found_text": "hmm, we couldn't find that page"},
    {"name": "Dev.to", "url": "https://dev.to/{}", "not_found_text": "page not found"},
    {"name": "Medium", "url": "https://medium.com/@{}", "not_found_text": "page not found"},
    {"name": "Keybase", "url": "https://keybase.io/{}", "not_found_text": "not found"},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}", "not_found_text": "no such user"},
    {"name": "Replit", "url": "https://replit.com/@{}", "not_found_text": "not found"},
    {"name": "Linktree", "url": "https://linktr.ee/{}", "not_found_text": "sorry, this page isn't available"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{}", "not_found_text": "the specified profile could not be found"},
    {"name": "Pastebin", "url": "https://pastebin.com/u/{}", "not_found_text": "not found"},
]

MANUAL_PLATFORMS = [
    {"name": "Instagram", "icon": "📸", "url": "https://www.instagram.com/{}"},
    {"name": "Facebook", "icon": "👤", "url": "https://www.facebook.com/{}"},
    {"name": "Twitter / X", "icon": "🐦", "url": "https://twitter.com/{}"},
    {"name": "LinkedIn", "icon": "💼", "url": "https://www.linkedin.com/in/{}"},
    {"name": "Snapchat", "icon": "👻", "url": "https://www.snapchat.com/add/{}"},
    {"name": "BeReal", "icon": "📷", "url": "https://bere.al/{}"},
]


def check_username(username):
    results = []
    found_count = 0

    for platform in AUTO_PLATFORMS:
        url = platform["url"].format(username)
        try:
            response = requests.get(url, headers=HEADERS, timeout=6, allow_redirects=True)
            body = response.text.lower()
            not_found_text = platform["not_found_text"].lower()
            if response.status_code == 200 and not_found_text not in body:
                status = "found"
                found_count += 1
            else:
                status = "not_found"
        except requests.exceptions.Timeout:
            status = "error"
        except Exception:
            status = "error"

        results.append({
            "platform": platform["name"],
            "url": url,
            "status": status,
            "type": "auto"
        })

    for platform in MANUAL_PLATFORMS:
        url = platform["url"].format(username)
        results.append({
            "platform": platform["name"],
            "icon": platform["icon"],
            "url": url,
            "status": "manual",
            "type": "manual"
        })

    score = int((found_count / len(AUTO_PLATFORMS)) * 100)
    return results, score


def check_phone(phone):
    results = []
    phone_clean = phone.strip().replace(" ", "").replace("-", "").replace("+", "")

    searches = [
        {"name": "Truecaller", "url": f"https://www.truecaller.com/search/in/{phone_clean}"},
        {"name": "Sync.me", "url": f"https://sync.me/search/?number={phone_clean}"},
        {"name": "Google Search", "url": f"https://www.google.com/search?q={phone_clean}"},
        {"name": "WhatsApp", "url": f"https://wa.me/{phone_clean}"},
        {"name": "Telegram", "url": f"https://t.me/+{phone_clean}"},
    ]

    for s in searches:
        results.append({
            "platform": s["name"],
            "url": s["url"],
            "status": "link",
            "type": "manual",
            "icon": ""
        })

    return results, 50
