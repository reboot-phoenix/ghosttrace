"""
modules/username.py — username search with proper false-positive filtering
Only returns platforms where the account is CONFIRMED to exist.
Profile data (avatar, bio, stats) fetched where free APIs allow it (GitHub).
"""

import concurrent.futures
import requests

TIMEOUT = 10

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

# Each platform entry:
# (name, icon, url, method, not_found_indicators)
#
# method:
#   "status"  — 404 = not found, 200 = found (reliable for this platform)
#   "text"    — always returns 200, check body for not_found_indicators strings
#   "api"     — use a dedicated free API endpoint (GitHub, HackerNews)
#   "skip"    — skip entirely (too many false positives, no reliable check)
#
# not_found_indicators: list of strings that appear in the page body
# when the user does NOT exist. All must be checked with OR logic.

PLATFORMS = [
    # ── Reliable status-code platforms (404 on missing user) ──
    ("GitHub",      "🐙", "https://github.com/{}",                  "api",    []),
    ("GitLab",      "🦊", "https://gitlab.com/{}",                  "text",   ["404", "Sorry, couldn't find your page", "Not Found"]),
    ("Reddit",      "🤖", "https://www.reddit.com/user/{}/about.json","api",   []),
    ("Dev.to",      "💻", "https://dev.to/{}",                      "text",   ["404 | The page you were looking for doesn't exist"]),
    ("HackerRank",  "🏆", "https://www.hackerrank.com/{}",          "text",   ["Page Not Found", "404"]),
    ("Replit",      "🔧", "https://replit.com/@{}",                 "text",   ["404", "not found", "This user does not exist"]),
    ("Keybase",     "🔑", "https://keybase.io/{}",                  "text",   ["404", "Not found", "isn't on Keybase"]),
    ("Pastebin",    "📋", "https://pastebin.com/u/{}",              "text",   ["404", "Not Found"]),
    ("HackerNews",  "🔶", "https://hacker-news.firebaseio.com/v0/user/{}.json", "api", []),
    ("Gravatar",    "🪪", "https://gravatar.com/{}",                "text",   ["Oops! That page can", "doesn't exist"]),
    ("ProductHunt", "🚀", "https://www.producthunt.com/@{}",        "text",   ["404", "Oops", "Page Not Found"]),
    ("Hashnode",    "📝", "https://hashnode.com/@{}",               "text",   ["404", "doesn't exist"]),
    ("CodePen",     "🖊️", "https://codepen.io/{}",                  "text",   ["404", "Uh oh", "We couldn't find"]),
    ("About.me",    "👤", "https://about.me/{}",                    "text",   ["404", "page not found", "Page not found"]),
    ("Linktree",    "🌿", "https://linktr.ee/{}",                   "text",   ["Sorry, this page isn't available", "404"]),
    ("Substack",    "✉️", "https://{}.substack.com",                "text",   ["This publication does not exist", "404", "doesn't exist"]),
    ("Medium",      "📖", "https://medium.com/@{}",                 "text",   ["PageNotFoundError", "Page not found", "404"]),
    ("Tumblr",      "🌀", "https://{}.tumblr.com",                  "text",   ["There's nothing here", "not found", "404"]),
    ("WordPress",   "📰", "https://{}.wordpress.com",               "text",   ["doesn't exist", "404 Not Found", "This site"]),
    ("Mastodon",    "🐘", "https://mastodon.social/@{}",            "text",   ["The page you are looking for", "404", "doesn't exist"]),
    ("Flickr",      "📷", "https://www.flickr.com/people/{}",       "text",   ["Page Not Found", "Oops!", "404"]),
    ("Vimeo",       "🎬", "https://vimeo.com/{}",                   "text",   ["Page not found", "Sorry", "404"]),
    ("Wattpad",     "📚", "https://www.wattpad.com/user/{}",        "text",   ["404", "not found"]),
    ("Genius",      "🎤", "https://genius.com/{}",                  "text",   ["Page not found", "404"]),
    ("AngelList",   "👼", "https://angel.co/u/{}",                  "text",   ["404", "Page not found"]),
    ("Crunchbase",  "💼", "https://www.crunchbase.com/person/{}",   "text",   ["Page Not Found", "404"]),
    ("Codeforces",  "⚡", "https://codeforces.com/profile/{}",      "text",   ["Error - Codeforces", "not found", "404"]),
    ("LeetCode",    "🧩", "https://leetcode.com/{}",                "text",   ["404 Page Not Found", "does not exist", "page not found"]),
    ("Kaggle",      "📊", "https://www.kaggle.com/{}",              "text",   ["404", "Not Found"]),
    ("Behance",     "🎨", "https://www.behance.net/{}",             "text",   ["404", "Sorry"]),
    ("Dribbble",    "🏀", "https://dribbble.com/{}",                "text",   ["Whoops", "404", "Sorry"]),
    # ── Unreliable — skip (too many false positives, no good check) ──
    # Instagram, TikTok, Twitter, YouTube, Pinterest, Twitch, Steam,
    # Spotify, Mixcloud, SoundCloud, Facebook, LinkedIn, Quora —
    # all either block scraping, always return 200, or require auth.
]


# ── Per-platform API fetchers for profile data ─────────────────────────────

def _github_profile(username: str) -> dict:
    """GitHub public API — no key needed, 60 req/hour per IP."""
    try:
        r = requests.get(
            f"https://api.github.com/users/{username}",
            headers={**HEADERS, "Accept": "application/vnd.github.v3+json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return {"exists": False}
        if r.status_code != 200:
            return {"exists": None}  # uncertain
        d = r.json()
        return {
            "exists":     True,
            "avatar":     d.get("avatar_url", ""),
            "display_name": d.get("name") or d.get("login", username),
            "bio":        d.get("bio") or "",
            "meta":       f"⭐ {d.get('public_repos', 0)} repos · 👥 {d.get('followers', 0)} followers",
        }
    except requests.RequestException:
        return {"exists": None}


def _reddit_profile(username: str) -> dict:
    """Reddit public JSON API."""
    try:
        r = requests.get(
            f"https://www.reddit.com/user/{username}/about.json",
            headers={**HEADERS, "Accept": "application/json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return {"exists": False}
        if r.status_code != 200:
            return {"exists": None}
        d = r.json().get("data", {})
        avatar = d.get("icon_img", "").split("?")[0]  # strip query params
        karma = d.get("total_karma", 0)
        return {
            "exists":       True,
            "avatar":       avatar,
            "display_name": d.get("name", username),
            "bio":          "",
            "meta":         f"🏆 {karma:,} karma",
        }
    except (requests.RequestException, ValueError):
        return {"exists": None}


def _hackernews_profile(username: str) -> dict:
    """HackerNews Firebase API."""
    try:
        r = requests.get(
            f"https://hacker-news.firebaseio.com/v0/user/{username}.json",
            headers=HEADERS,
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return {"exists": None}
        data = r.json()
        if data is None:
            return {"exists": False}
        return {
            "exists":       True,
            "avatar":       "",
            "display_name": data.get("id", username),
            "bio":          "",
            "meta":         f"🏆 {data.get('karma', 0):,} karma",
        }
    except (requests.RequestException, ValueError):
        return {"exists": None}


# ── Generic text-based check ───────────────────────────────────────────────

def _text_check(url: str, not_found_strings: list[str]) -> bool | None:
    """
    Returns True if found, False if not found, None if uncertain/error.
    Fetches the page and looks for not-found indicator strings.
    """
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)

        # Hard 404 = definitely not found
        if r.status_code == 404:
            return False

        # Non-200 and non-404 = uncertain (could be rate limit, Cloudflare, etc.)
        if r.status_code != 200:
            return None

        # Check if any not-found strings appear in the body
        body = r.text
        for indicator in not_found_strings:
            if indicator.lower() in body.lower():
                return False

        return True

    except requests.RequestException:
        return None


# ── Main checker ───────────────────────────────────────────────────────────

def _check_platform(platform: tuple, username: str) -> dict | None:
    """
    Returns a result dict if CONFIRMED found, or None if not found / uncertain.
    Only confirmed found accounts are returned to the caller.
    """
    name, icon, url_tpl, method, not_found = platform
    url = url_tpl.format(username)

    if method == "api":
        # Platform-specific API
        if name == "GitHub":
            profile = _github_profile(username)
        elif name == "Reddit":
            profile = _reddit_profile(username)
        elif name == "HackerNews":
            profile = _hackernews_profile(username)
            url = f"https://news.ycombinator.com/user?id={username}"
        else:
            return None

        if not profile.get("exists"):
            return None  # False or None (uncertain) — don't show

        return {
            "platform":     name,
            "icon":         icon,
            "url":          url,
            "status":       "found",
            "type":         "auto",
            "avatar":       profile.get("avatar", ""),
            "display_name": profile.get("display_name", username),
            "bio":          profile.get("bio", ""),
            "meta":         profile.get("meta", ""),
        }

    elif method == "text":
        found = _text_check(url, not_found)
        if found is True:
            return {
                "platform": name,
                "icon":     icon,
                "url":      url,
                "status":   "found",
                "type":     "auto",
                "avatar":   "",
                "display_name": username,
                "bio":      "",
                "meta":     "",
            }
        return None  # not found or uncertain — don't show

    return None  # skip


def check_username(username: str) -> tuple[list[dict], int, dict]:
    username = username.strip().lstrip("@")

    confirmed: list[dict] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(_check_platform, p, username): p
            for p in PLATFORMS
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                confirmed.append(result)

    # Sort: API-enriched (with avatar/meta) first, then plain text-confirmed
    confirmed.sort(key=lambda r: (0 if r.get("meta") else 1, r["platform"]))

    found_count = len(confirmed)

    summary = {
        "username":        username,
        "platforms_found": found_count,
        "platforms_checked": len(PLATFORMS),
    }

    score = min(100, found_count * 10)
    return confirmed, score, summary
