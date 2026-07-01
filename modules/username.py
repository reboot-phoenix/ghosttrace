import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 Chrome/137.0 Safari/537.36"
    )
}

AUTO_PLATFORMS = [
    {
        "name": "GitHub",
        "url": "https://github.com/{}",
        "not_found": "not found"
    },
    {
        "name": "Reddit",
        "url": "https://www.reddit.com/user/{}",
        "not_found": "nobody on reddit goes by that name"
    },
    {
        "name": "TikTok",
        "url": "https://www.tiktok.com/@{}",
        "not_found": "couldn't find this account"
    },
    {
        "name": "Pinterest",
        "url": "https://www.pinterest.com/{}",
        "not_found": "sorry! we couldn't find that page"
    },
    {
        "name": "Twitch",
        "url": "https://www.twitch.tv/{}",
        "not_found": "unless you've got a time machine"
    },
    {
        "name": "YouTube",
        "url": "https://www.youtube.com/@{}",
        "not_found": "this page isn't available"
    },
    {
        "name": "Spotify",
        "url": "https://open.spotify.com/user/{}",
        "not_found": "couldn't find that page"
    },
    {
        "name": "Medium",
        "url": "https://medium.com/@{}",
        "not_found": "page not found"
    },
    {
        "name": "Dev.to",
        "url": "https://dev.to/{}",
        "not_found": "page not found"
    },
    {
        "name": "Keybase",
        "url": "https://keybase.io/{}",
        "not_found": "not found"
    },
    {
        "name": "Steam",
        "url": "https://steamcommunity.com/id/{}",
        "not_found": "specified profile could not be found"
    },
    {
        "name": "Replit",
        "url": "https://replit.com/@{}",
        "not_found": "not found"
    },
    {
        "name": "Pastebin",
        "url": "https://pastebin.com/u/{}",
        "not_found": "not found"
    },
    {
        "name": "Hacker News",
        "url": "https://news.ycombinator.com/user?id={}",
        "not_found": "no such user"
    },
    {
        "name": "Linktree",
        "url": "https://linktr.ee/{}",
        "not_found": "sorry, this page isn't available"
    }
]

MANUAL_PLATFORMS = [
    {
        "name": "Instagram",
        "icon": "📸",
        "url": "https://www.instagram.com/{}"
    },
    {
        "name": "Facebook",
        "icon": "👤",
        "url": "https://www.facebook.com/{}"
    },
    {
        "name": "X (Twitter)",
        "icon": "🐦",
        "url": "https://twitter.com/{}"
    },
    {
        "name": "LinkedIn",
        "icon": "💼",
        "url": "https://www.linkedin.com/in/{}"
    },
    {
        "name": "Snapchat",
        "icon": "👻",
        "url": "https://www.snapchat.com/add/{}"
    },
    {
        "name": "BeReal",
        "icon": "📷",
        "url": "https://bere.al/{}"
    }
]


def _scan_platform(platform, username):
    url = platform["url"].format(username)

    try:

        response = requests.get(
            url,
            headers=HEADERS,
            timeout=8,
            allow_redirects=True
        )

        html = response.text.lower()

        if (
            response.status_code == 200 and
            platform["not_found"].lower() not in html
        ):

            status = "found"

        else:

            status = "not_found"

    except requests.Timeout:

        status = "error"

    except Exception:

        status = "error"

    return {
        "platform": platform["name"],
        "url": url,
        "status": status,
        "type": "auto"
    }


def exposure_level(score):

    if score >= 80:
        return "Very High"

    if score >= 60:
        return "High"

    if score >= 40:
        return "Medium"

    if score >= 20:
        return "Low"

    return "Minimal"


def check_username(username):

    username = username.strip()

    results = []

    found = 0

    with ThreadPoolExecutor(max_workers=8) as executor:

        futures = [
            executor.submit(
                _scan_platform,
                platform,
                username
            )
            for platform in AUTO_PLATFORMS
        ]

        for future in as_completed(futures):

            result = future.result()

            if result["status"] == "found":
                found += 1

            results.append(result)

    results.sort(
        key=lambda x: (
            x["status"] != "found",
            x["platform"]
        )
    )

    for platform in MANUAL_PLATFORMS:

        results.append({

            "platform": platform["name"],

            "icon": platform["icon"],

            "url": platform["url"].format(username),

            "status": "manual",

            "type": "manual"

        })

    score = round(
        (found / len(AUTO_PLATFORMS)) * 100
    )

    summary = {

        "found": found,

        "checked": len(AUTO_PLATFORMS),

        "manual": len(MANUAL_PLATFORMS),

        "level": exposure_level(score)

    }

    return results, score, summary
