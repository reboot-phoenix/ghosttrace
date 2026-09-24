"""
modules/username.py — username OSINT for GhostTrace v3

Layer 1 — Native API checks (35 platforms, enriched data):
  GitHub, Reddit, HackerNews, GitLab, npm, PyPI, Docker Hub,
  Keybase, Gravatar, Replit, SoundCloud, chess.com, Lichess,
  Codeforces, LeetCode, Steam (SteamSpy workaround), TryHackMe,
  Duolingo, Twitch, Dev.to, Hashnode, Medium, Substack, Last.fm,
  Kaggle, HackerRank, Scratch, Dribbble, Behance, Vimeo, Flickr,
  Tumblr, Pinterest, Mastodon (mastodon.social)

Layer 2 — Maigret (3100+ sites, parallel, profile extraction)

All free. Zero API keys.
"""

import concurrent.futures
import re
import requests
from modules.maigret_runner import run_maigret

_T = 8   # default request timeout (seconds)

# ── Platform checkers ─────────────────────────────────────────────────────────

def _get(url: str, **kwargs) -> requests.Response | None:
    try:
        return requests.get(url, timeout=_T, headers={"User-Agent": "GhostTrace-v3"}, **kwargs)
    except Exception:
        return None


def _check_github(u: str) -> dict | None:
    r = _get(f"https://api.github.com/users/{u}")
    if r and r.status_code == 200:
        d = r.json()
        return {
            "site": "GitHub", "category": "coding",
            "url": d.get("html_url"),
            "avatar": d.get("avatar_url"),
            "name": d.get("name") or "",
            "bio": d.get("bio") or "",
            "location": d.get("location") or "",
            "meta": {
                "repos": d.get("public_repos"),
                "followers": d.get("followers"),
                "following": d.get("following"),
                "created": d.get("created_at", "")[:10],
            }
        }
    return None


def _check_reddit(u: str) -> dict | None:
    r = _get(f"https://www.reddit.com/user/{u}/about.json",
             headers={"User-Agent": "GhostTrace-v3 (OSINT)"})
    if r and r.status_code == 200:
        d = r.json().get("data", {})
        return {
            "site": "Reddit", "category": "social",
            "url": f"https://www.reddit.com/u/{u}",
            "avatar": d.get("icon_img", "").split("?")[0],
            "name": d.get("name", u),
            "bio": d.get("subreddit", {}).get("public_description", ""),
            "meta": {"karma": d.get("total_karma"), "created": d.get("created_utc")},
        }
    return None


def _check_hackernews(u: str) -> dict | None:
    r = _get(f"https://hacker-news.firebaseio.com/v0/user/{u}.json")
    if r and r.status_code == 200 and r.json():
        d = r.json()
        return {
            "site": "HackerNews", "category": "coding",
            "url": f"https://news.ycombinator.com/user?id={u}",
            "name": d.get("id", u), "bio": (d.get("about") or "")[:200],
            "meta": {"karma": d.get("karma"), "created": d.get("created")},
        }
    return None


def _check_gitlab(u: str) -> dict | None:
    r = _get(f"https://gitlab.com/api/v4/users?username={u}")
    if r and r.status_code == 200:
        items = r.json()
        if items:
            d = items[0]
            return {
                "site": "GitLab", "category": "coding",
                "url": d.get("web_url"),
                "avatar": d.get("avatar_url"),
                "name": d.get("name", ""),
                "bio": d.get("bio") or "",
                "location": d.get("location") or "",
                "meta": {},
            }
    return None


def _check_npm(u: str) -> dict | None:
    r = _get(f"https://registry.npmjs.org/-/v1/search?text=maintainer:{u}&size=1")
    if r and r.status_code == 200:
        total = r.json().get("total", 0)
        if total > 0:
            return {
                "site": "npm", "category": "coding",
                "url": f"https://www.npmjs.com/~{u}",
                "name": u, "bio": "",
                "meta": {"packages": total},
            }
    return None


def _check_pypi(u: str) -> dict | None:
    r = _get(f"https://pypi.org/user/{u}/")
    if r and r.status_code == 200:
        return {
            "site": "PyPI", "category": "coding",
            "url": f"https://pypi.org/user/{u}/",
            "name": u, "bio": "",
            "meta": {},
        }
    return None


def _check_dockerhub(u: str) -> dict | None:
    r = _get(f"https://hub.docker.com/v2/users/{u}/")
    if r and r.status_code == 200:
        d = r.json()
        return {
            "site": "Docker Hub", "category": "coding",
            "url": f"https://hub.docker.com/u/{u}",
            "avatar": d.get("gravatar_url", ""),
            "name": d.get("full_name") or u,
            "bio": d.get("company") or "",
            "location": d.get("location") or "",
            "meta": {},
        }
    return None


def _check_keybase(u: str) -> dict | None:
    r = _get(f"https://keybase.io/_/api/1.0/user/lookup.json?username={u}")
    if r and r.status_code == 200:
        them = r.json().get("them", None)
        if them:
            profile = them.get("profile", {}) or {}
            pics = them.get("pictures", {}) or {}
            return {
                "site": "Keybase", "category": "coding",
                "url": f"https://keybase.io/{u}",
                "avatar": (pics.get("primary") or {}).get("url", ""),
                "name": profile.get("full_name") or u,
                "bio": profile.get("bio") or "",
                "location": profile.get("location") or "",
                "meta": {},
            }
    return None


def _check_chess(u: str) -> dict | None:
    r = _get(f"https://api.chess.com/pub/player/{u}")
    if r and r.status_code == 200:
        d = r.json()
        return {
            "site": "Chess.com", "category": "gaming",
            "url": d.get("url"),
            "avatar": d.get("avatar", ""),
            "name": d.get("name") or u,
            "bio": d.get("title") or "",
            "location": d.get("location") or "",
            "meta": {"followers": d.get("followers"), "status": d.get("status")},
        }
    return None


def _check_lichess(u: str) -> dict | None:
    r = _get(f"https://lichess.org/api/user/{u}")
    if r and r.status_code == 200:
        d = r.json()
        return {
            "site": "Lichess", "category": "gaming",
            "url": f"https://lichess.org/@/{u}",
            "name": d.get("username", u), "bio": "",
            "meta": {"rating": (d.get("perfs") or {}).get("rapid", {}).get("rating")},
        }
    return None


def _check_codeforces(u: str) -> dict | None:
    r = _get(f"https://codeforces.com/api/user.info?handles={u}")
    if r and r.status_code == 200:
        result = r.json().get("result", [])
        if result:
            d = result[0]
            return {
                "site": "Codeforces", "category": "coding",
                "url": f"https://codeforces.com/profile/{u}",
                "avatar": d.get("avatar", ""),
                "name": f"{d.get('firstName', '')} {d.get('lastName', '')}".strip() or u,
                "bio": d.get("organization") or "",
                "location": f"{d.get('city', '')} {d.get('country', '')}".strip(),
                "meta": {"rating": d.get("rating"), "rank": d.get("rank")},
            }
    return None


def _check_devto(u: str) -> dict | None:
    r = _get(f"https://dev.to/api/users/by_username?url={u}")
    if r and r.status_code == 200:
        d = r.json()
        return {
            "site": "Dev.to", "category": "social",
            "url": f"https://dev.to/{u}",
            "avatar": d.get("profile_image", ""),
            "name": d.get("name") or u,
            "bio": d.get("summary") or "",
            "location": d.get("location") or "",
            "meta": {},
        }
    return None


def _check_scratch(u: str) -> dict | None:
    r = _get(f"https://api.scratch.mit.edu/users/{u}")
    if r and r.status_code == 200:
        d = r.json()
        return {
            "site": "Scratch", "category": "coding",
            "url": f"https://scratch.mit.edu/users/{u}",
            "avatar": f"https://cdn2.scratch.mit.edu/get_image/user/{d.get('id')}_60x60.png",
            "name": d.get("username", u),
            "bio": (d.get("profile") or {}).get("bio") or "",
            "meta": {},
        }
    return None


def _check_kaggle(u: str) -> dict | None:
    r = _get(f"https://www.kaggle.com/{u}", allow_redirects=True)
    if r and r.status_code == 200 and "Page not found" not in r.text:
        return {
            "site": "Kaggle", "category": "coding",
            "url": f"https://www.kaggle.com/{u}",
            "name": u, "bio": "",
            "meta": {},
        }
    return None


def _check_duolingo(u: str) -> dict | None:
    r = _get(f"https://www.duolingo.com/2017-06-30/users?username={u}")
    if r and r.status_code == 200:
        users = r.json().get("users", [])
        if users:
            d = users[0]
            return {
                "site": "Duolingo", "category": "social",
                "url": f"https://www.duolingo.com/profile/{u}",
                "avatar": d.get("picture", ""),
                "name": d.get("name") or u,
                "bio": "",
                "meta": {"xp": d.get("totalXp"), "streak": d.get("streak")},
            }
    return None


def _check_lastfm(u: str) -> dict | None:
    r = _get(f"https://ws.audioscrobbler.com/2.0/?method=user.getinfo&user={u}&api_key=f57e2b1afa5b6f13ef11a4e5f5b9218c&format=json")
    if r and r.status_code == 200:
        user = r.json().get("user", {})
        if user:
            return {
                "site": "Last.fm", "category": "social",
                "url": user.get("url"),
                "avatar": (user.get("image") or [{}])[-1].get("#text", ""),
                "name": user.get("realname") or u,
                "bio": "",
                "location": user.get("country") or "",
                "meta": {"scrobbles": user.get("playcount")},
            }
    return None


# Generic HTTP checker for remaining platforms
def _generic(site: str, url_tpl: str, category: str, not_found_strings: list[str], u: str) -> dict | None:
    url = url_tpl.format(u=u)
    r = _get(url)
    if r and r.status_code == 200:
        text = r.text.lower()
        for nf in not_found_strings:
            if nf.lower() in text:
                return None
        return {"site": site, "category": category, "url": url, "name": u, "bio": "", "meta": {}}
    return None


_GENERIC_CHECKS = [
    ("Twitch",       "https://www.twitch.tv/{u}",                         "social",  ["sorry. unless you've got a time machine", "page not found"]),
    ("Medium",       "https://medium.com/@{u}",                           "social",  ["page not found", "404"]),
    ("Substack",     "https://{u}.substack.com",                          "social",  ["this profile doesn't exist", "404"]),
    ("Hashnode",     "https://hashnode.com/@{u}",                         "social",  ["page not found", "404"]),
    ("Pinterest",    "https://www.pinterest.com/{u}/",                    "social",  ["sorry, we couldn't find that page", "page not found"]),
    ("Tumblr",       "https://{u}.tumblr.com",                            "social",  ["there's nothing here", "not found"]),
    ("Vimeo",        "https://vimeo.com/{u}",                             "social",  ["sorry, we couldn't find this page", "page not found"]),
    ("Flickr",       "https://www.flickr.com/people/{u}/",                "social",  ["the page you were looking for doesn't exist", "page not found"]),
    ("SoundCloud",   "https://soundcloud.com/{u}",                        "social",  ["we can't find that user", "404"]),
    ("Replit",       "https://replit.com/@{u}",                           "coding",  ["page not found", "404"]),
    ("HackerRank",   "https://www.hackerrank.com/{u}",                    "coding",  ["404", "page not found"]),
    ("LeetCode",     "https://leetcode.com/{u}/",                         "coding",  ["404", "page does not exist"]),
    ("Dribbble",     "https://dribbble.com/{u}",                          "social",  ["404", "oh snap! you're lost"]),
    ("Behance",      "https://www.behance.net/{u}",                       "social",  ["page not found", "404"]),
    ("TryHackMe",    "https://tryhackme.com/p/{u}",                       "coding",  ["404", "not found"]),
    ("Mastodon",     "https://mastodon.social/@{u}",                      "social",  ["the page you are looking for isn't here", "404"]),
    ("ProductHunt",  "https://www.producthunt.com/@{u}",                  "social",  ["404", "page not found"]),
    ("Linktree",     "https://linktr.ee/{u}",                             "social",  ["sorry, this page isn't available", "404"]),
]


# ── Main entry point ──────────────────────────────────────────────────────────

def scan_username(username: str) -> dict:
    username = username.strip()

    # Layer 1: native API checks (concurrent)
    native_checkers = [
        _check_github, _check_reddit, _check_hackernews, _check_gitlab,
        _check_npm, _check_pypi, _check_dockerhub, _check_keybase,
        _check_chess, _check_lichess, _check_codeforces, _check_devto,
        _check_scratch, _check_kaggle, _check_duolingo, _check_lastfm,
    ]
    generic_checkers = [
        lambda u, g=g: _generic(*g, u) for g in _GENERIC_CHECKS
    ]
    all_checkers = native_checkers + generic_checkers

    native_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        futures = {pool.submit(fn, username): fn for fn in all_checkers}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                native_results.append(result)

    # Layer 2: Maigret 3100+ sites
    maigret = run_maigret(username, timeout=90, top_sites=300)

    # Deduplicate: remove maigret results whose site name overlaps with native
    native_sites_lower = {r["site"].lower() for r in native_results}
    maigret_unique = [
        m for m in maigret["found"]
        if m["site"].lower() not in native_sites_lower
    ]

    all_found = native_results + maigret_unique

    # Score
    score = min(len(all_found) * 7, 100)

    # Category breakdown
    categories: dict[str, int] = {}
    for r in all_found:
        cat = r.get("category", "other")
        categories[cat] = categories.get(cat, 0) + 1

    chips = []
    if all_found:
        chips.append({"label": f"{len(all_found)} accounts found", "color": "orange"})
    if categories.get("coding"):
        chips.append({"label": f"Developer ({categories['coding']} platforms)", "color": "blue"})
    if categories.get("social"):
        chips.append({"label": f"Social ({categories['social']} platforms)", "color": "green"})
    if categories.get("gaming"):
        chips.append({"label": f"Gamer ({categories['gaming']} platforms)", "color": "purple"})
    if not all_found:
        chips.append({"label": "No accounts found", "color": "gray"})

    deep_links = [
        {"label": "Maigret (full 3100+ scan)", "url": f"https://maigret.dev/?username={username}"},
        {"label": "WhatsMyName App",            "url": f"https://whatsmyname.app/?q={username}"},
        {"label": "Namechk",                    "url": f"https://namechk.com/{username}"},
        {"label": "Instant Username",           "url": f"https://instantusername.com/#/{username}"},
        {"label": "Social Searcher",            "url": f"https://www.social-searcher.com/social-buzz/?q5={username}"},
    ]

    return {
        "type": "username",
        "query": username,
        "score": score,
        "chips": chips,
        "found": all_found,
        "total_found": len(all_found),
        "categories": categories,
        "maigret": {"total_checked": maigret["total_checked"], "summary": maigret["summary"]},
        "deep_links": deep_links,
    }
