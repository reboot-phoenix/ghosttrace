"""
modules/username.py — username search

Two-layer approach:
  Layer 1 (existing): 30 hand-picked platforms with API enrichment
                      (GitHub, Reddit, HackerNews get avatars/bios/stats).
  Layer 2 (Sherlock): 300+ additional platforms via sherlock-project.
                      Runs in parallel with Layer 1.

Install Sherlock for Layer 2:  pip install sherlock-project
"""

import concurrent.futures
import requests

from modules.sherlock_runner import run_sherlock

TIMEOUT = 10

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

# Each entry: (name, icon, url_template, method, not_found_indicators)
PLATFORMS = [
    ("GitHub",      "🐙", "https://github.com/{}",                   "api",  []),
    ("GitLab",      "🦊", "https://gitlab.com/{}",                   "text", ["404", "Sorry, couldn't find your page", "Not Found"]),
    ("Reddit",      "🤖", "https://www.reddit.com/user/{}/about.json","api",  []),
    ("Dev.to",      "💻", "https://dev.to/{}",                       "text", ["404 | The page you were looking for doesn't exist"]),
    ("HackerRank",  "🏆", "https://www.hackerrank.com/{}",           "text", ["Page Not Found", "404"]),
    ("Replit",      "🔧", "https://replit.com/@{}",                  "text", ["404", "not found", "This user does not exist"]),
    ("Keybase",     "🔑", "https://keybase.io/{}",                   "text", ["404", "Not found", "isn't on Keybase"]),
    ("Pastebin",    "📋", "https://pastebin.com/u/{}",               "text", ["404", "Not Found"]),
    ("HackerNews",  "🔶", "https://hacker-news.firebaseio.com/v0/user/{}.json", "api", []),
    ("Gravatar",    "🪪", "https://gravatar.com/{}",                 "text", ["Oops! That page can", "doesn't exist"]),
    ("ProductHunt", "🚀", "https://www.producthunt.com/@{}",         "text", ["404", "Oops", "Page Not Found"]),
    ("Hashnode",    "📝", "https://hashnode.com/@{}",                "text", ["404", "doesn't exist"]),
    ("CodePen",     "🖊️", "https://codepen.io/{}",                   "text", ["404", "Uh oh", "We couldn't find"]),
    ("About.me",    "👤", "https://about.me/{}",                     "text", ["404", "page not found", "Page not found"]),
    ("Linktree",    "🌿", "https://linktr.ee/{}",                    "text", ["Sorry, this page isn't available", "404"]),
    ("Substack",    "✉️", "https://{}.substack.com",                 "text", ["This publication does not exist", "404", "doesn't exist"]),
    ("Medium",      "📖", "https://medium.com/@{}",                  "text", ["PageNotFoundError", "Page not found", "404"]),
    ("Tumblr",      "🌀", "https://{}.tumblr.com",                   "text", ["There's nothing here", "not found", "404"]),
    ("WordPress",   "📰", "https://{}.wordpress.com",                "text", ["doesn't exist", "404 Not Found", "This site"]),
    ("Mastodon",    "🐘", "https://mastodon.social/@{}",             "text", ["The page you are looking for", "404", "doesn't exist"]),
    ("Flickr",      "📷", "https://www.flickr.com/people/{}",        "text", ["Page Not Found", "Oops!", "404"]),
    ("Vimeo",       "🎬", "https://vimeo.com/{}",                    "text", ["Page not found", "Sorry", "404"]),
    ("Wattpad",     "📚", "https://www.wattpad.com/user/{}",         "text", ["404", "not found"]),
    ("Genius",      "🎤", "https://genius.com/{}",                   "text", ["Page not found", "404"]),
    ("AngelList",   "👼", "https://angel.co/u/{}",                   "text", ["404", "Page not found"]),
    ("Crunchbase",  "💼", "https://www.crunchbase.com/person/{}",    "text", ["Page Not Found", "404"]),
    ("Codeforces",  "⚡", "https://codeforces.com/profile/{}",       "text", ["Error - Codeforces", "not found", "404"]),
    ("LeetCode",    "🧩", "https://leetcode.com/{}",                 "text", ["404 Page Not Found", "does not exist", "page not found"]),
    ("Kaggle",      "📊", "https://www.kaggle.com/{}",               "text", ["404", "Not Found"]),
    ("Behance",     "🎨", "https://www.behance.net/{}",              "text", ["404", "Sorry"]),
    ("Dribbble",    "🏀", "https://dribbble.com/{}",                 "text", ["Whoops", "404", "Sorry"]),
]


# ── Per-platform API fetchers ───────────────────────────────────────────────

def _github_profile(username: str) -> dict:
    try:
        r = requests.get(
            f"https://api.github.com/users/{username}",
            headers={**HEADERS, "Accept": "application/vnd.github.v3+json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return {"exists": False}
        if r.status_code != 200:
            return {"exists": None}
        d = r.json()
        return {
            "exists":       True,
            "avatar":       d.get("avatar_url", ""),
            "display_name": d.get("name") or d.get("login", username),
            "bio":          d.get("bio") or "",
            "meta":         f"⭐ {d.get('public_repos', 0)} repos · 👥 {d.get('followers', 0)} followers",
        }
    except requests.RequestException:
        return {"exists": None}


def _reddit_profile(username: str) -> dict:
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
        return {
            "exists":       True,
            "avatar":       d.get("icon_img", "").split("?")[0],
            "display_name": d.get("name", username),
            "bio":          "",
            "meta":         f"🏆 {d.get('total_karma', 0):,} karma",
        }
    except (requests.RequestException, ValueError):
        return {"exists": None}


def _hackernews_profile(username: str) -> dict:
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


def _text_check(url: str, not_found_strings: list[str]) -> bool | None:
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        if r.status_code == 404:
            return False
        if r.status_code != 200:
            return None
        body = r.text
        for indicator in not_found_strings:
            if indicator.lower() in body.lower():
                return False
        return True
    except requests.RequestException:
        return None


def _check_platform(platform: tuple, username: str) -> dict | None:
    name, icon, url_tpl, method, not_found = platform
    url = url_tpl.format(username)

    if method == "api":
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
            return None

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
            "source":       "native",
        }

    elif method == "text":
        found = _text_check(url, not_found)
        if found is True:
            return {
                "platform":     name,
                "icon":         icon,
                "url":          url,
                "status":       "found",
                "type":         "auto",
                "avatar":       "",
                "display_name": username,
                "bio":          "",
                "meta":         "",
                "source":       "native",
            }
        return None

    return None


# ── Main ───────────────────────────────────────────────────────────────────

def check_username(username: str) -> tuple[list[dict], int, dict]:
    username = username.strip().lstrip("@")

    confirmed_native: list[dict] = []
    sherlock_results: list[dict] = []
    sherlock_checked = 0
    sherlock_error   = None

    # Run Layer 1 (native) and Layer 2 (Sherlock) concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:

        # Layer 1: native platform checks
        native_futures = {
            executor.submit(_check_platform, p, username): p
            for p in PLATFORMS
        }

        # Layer 2: Sherlock (single long-running task)
        sherlock_future = executor.submit(run_sherlock, username)

        # Collect Layer 1
        for future in concurrent.futures.as_completed(native_futures):
            result = future.result()
            if result is not None:
                confirmed_native.append(result)

        # Collect Layer 2
        sherlock_results, sherlock_checked, sherlock_error = sherlock_future.result()

    # Merge: native API-enriched results first, then Sherlock extras
    # Native API results (with avatar/meta) float to the top
    confirmed_native.sort(key=lambda r: (0 if r.get("meta") else 1, r["platform"]))
    sherlock_results.sort(key=lambda r: r["platform"].lower())

    all_results = confirmed_native + sherlock_results

    found_native   = len(confirmed_native)
    found_sherlock = len(sherlock_results)
    found_total    = len(all_results)

    summary: dict = {
        "username":          username,
        "platforms_found":   found_total,
        "platforms_checked": len(PLATFORMS) + sherlock_checked,
        "native_found":      found_native,
        "sherlock_found":    found_sherlock,
    }
    if sherlock_error:
        summary["sherlock_note"] = sherlock_error
    if found_sherlock == 0 and not sherlock_error:
        summary["sherlock_note"] = "Sherlock: no additional platforms found."

    score = min(100, found_total * 7)
    return all_results, score, summary
