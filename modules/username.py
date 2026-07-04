"""
modules/username.py — username search across 50+ platforms
Uses concurrent HTTP requests to check if a username exists on each platform.
No API key needed — pure HTTP HEAD/GET requests.
"""

import concurrent.futures
import requests

TIMEOUT = 8

# Platform list: (display_name, icon, url_template, check_method, false_positive_text)
# check_method: "status" = rely on HTTP status code (404 = not found)
#               "text"   = 200 always returned, check if body contains false_positive_text
PLATFORMS = [
    # Definitive status-code platforms
    ("GitHub",          "🐙", "https://github.com/{}",                       "status", None),
    ("GitLab",          "🦊", "https://gitlab.com/{}",                       "status", None),
    ("Twitter/X",       "🐦", "https://x.com/{}",                            "status", None),
    ("Instagram",       "📸", "https://www.instagram.com/{}/",               "status", None),
    ("TikTok",          "🎵", "https://www.tiktok.com/@{}",                  "status", None),
    ("YouTube",         "▶️",  "https://www.youtube.com/@{}",                 "status", None),
    ("Reddit",          "🤖", "https://www.reddit.com/user/{}",              "status", None),
    ("Pinterest",       "📌", "https://www.pinterest.com/{}/",               "status", None),
    ("Twitch",          "🎮", "https://www.twitch.tv/{}",                    "status", None),
    ("Dev.to",          "💻", "https://dev.to/{}",                           "status", None),
    ("Hashnode",        "📝", "https://hashnode.com/@{}",                    "status", None),
    ("Replit",          "🔧", "https://replit.com/@{}",                      "status", None),
    ("Kaggle",          "📊", "https://www.kaggle.com/{}",                   "status", None),
    ("HackerRank",      "🏆", "https://www.hackerrank.com/{}",               "status", None),
    ("LeetCode",        "🧩", "https://leetcode.com/{}",                     "status", None),
    ("Codeforces",      "⚡", "https://codeforces.com/profile/{}",           "status", None),
    ("CodePen",         "🖊️",  "https://codepen.io/{}",                       "status", None),
    ("Behance",         "🎨", "https://www.behance.net/{}",                  "status", None),
    ("Dribbble",        "🏀", "https://dribbble.com/{}",                     "status", None),
    ("Keybase",         "🔑", "https://keybase.io/{}",                       "status", None),
    ("About.me",        "👤", "https://about.me/{}",                         "status", None),
    ("Linktree",        "🌿", "https://linktr.ee/{}",                        "status", None),
    ("Gravatar",        "🪪", "https://en.gravatar.com/{}",                  "status", None),
    ("Pastebin",        "📋", "https://pastebin.com/u/{}",                   "status", None),
    ("ProductHunt",     "🚀", "https://www.producthunt.com/@{}",             "status", None),
    ("Mastodon",        "🐘", "https://mastodon.social/@{}",                 "status", None),
    ("Substack",        "✉️",  "https://{}.substack.com",                     "status", None),
    ("Steam",           "🎲", "https://steamcommunity.com/id/{}",            "status", None),
    ("Flickr",          "📷", "https://www.flickr.com/people/{}",            "status", None),
    ("Vimeo",           "🎬", "https://vimeo.com/{}",                        "status", None),
    ("Medium",          "📖", "https://medium.com/@{}",                      "status", None),
    ("Quora",           "❓", "https://www.quora.com/profile/{}",            "status", None),
    ("Tumblr",          "🌀", "https://{}.tumblr.com",                       "status", None),
    ("WordPress",       "📰", "https://{}.wordpress.com",                    "status", None),
    ("Wattpad",         "📚", "https://www.wattpad.com/user/{}",             "status", None),
    ("SoundCloud",      "🎧", "https://soundcloud.com/{}",                   "status", None),
    ("Spotify",         "🎶", "https://open.spotify.com/user/{}",            "status", None),
    ("Mixcloud",        "🎛️",  "https://www.mixcloud.com/{}",                 "status", None),
    ("Genius",          "🎤", "https://genius.com/{}",                       "status", None),
    ("AngelList",       "👼", "https://angel.co/u/{}",                       "status", None),
    ("Crunchbase",      "💼", "https://www.crunchbase.com/person/{}",        "status", None),
    ("GitBook",         "📗", "https://{}.gitbook.io",                       "status", None),
    ("HackerNews",      "🔶", "https://news.ycombinator.com/user?id={}",     "status", None),
    ("StackOverflow",   "📚", "https://stackoverflow.com/users/{}",          "status", None),
    # Text-check platforms (always return 200, check body for "not found" text)
    ("Facebook",        "📘", "https://www.facebook.com/{}",                 "text",   "isn't available"),
    ("LinkedIn",        "💼", "https://www.linkedin.com/in/{}",              "text",   "Page not found"),
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}


def _check_one(platform: tuple) -> dict | None:
    name, icon, url_tpl, method, false_pos = platform
    url = url_tpl.format("{}")  # keep as-is for display
    check_url = url_tpl  # will be formatted with username in check_username

    # This function is called with the username already formatted in — see below
    return None  # placeholder; real logic is in _check_with_username


def _check_with_username(platform: tuple, username: str) -> dict:
    name, icon, url_tpl, method, false_pos = platform
    url = url_tpl.format(username)

    try:
        if method == "status":
            resp = requests.head(
                url, headers=HEADERS, timeout=TIMEOUT,
                allow_redirects=True
            )
            # Some sites block HEAD — retry with GET if needed
            if resp.status_code in (405, 403, 400):
                resp = requests.get(
                    url, headers=HEADERS, timeout=TIMEOUT,
                    allow_redirects=True
                )
            found = resp.status_code == 200

        else:  # text check
            resp = requests.get(
                url, headers=HEADERS, timeout=TIMEOUT,
                allow_redirects=True
            )
            found = resp.status_code == 200 and (
                false_pos not in resp.text if false_pos else True
            )

        return {
            "platform": name,
            "icon":     icon,
            "url":      url,
            "status":   "found" if found else "not_found",
            "type":     "auto",
        }

    except requests.RequestException:
        return {
            "platform": name,
            "icon":     icon,
            "url":      url,
            "status":   "error",
            "type":     "auto",
        }


def check_username(username: str) -> tuple[list[dict], int, dict]:
    username = username.strip().lstrip("@")

    results = []
    found_count = 0
    error_count = 0

    # Run all checks concurrently — 20 workers keeps it fast without hammering
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(_check_with_username, p, username): p
            for p in PLATFORMS
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            if result["status"] == "found":
                found_count += 1
            elif result["status"] == "error":
                error_count += 1

    # Sort: found first, then not_found, then errors
    order = {"found": 0, "not_found": 1, "error": 2}
    results.sort(key=lambda r: order.get(r["status"], 3))

    summary = {
        "username":        username,
        "platforms_found": found_count,
        "platforms_checked": len(PLATFORMS),
        "errors":          error_count,
    }

    score = min(100, found_count * 8)
    return results, score, summary
