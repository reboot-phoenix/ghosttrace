"""
modules/email.py — email OSINT for GhostTrace v3

Free sources (zero API keys):
  - Gravatar avatar/profile
  - GitHub commit author search (reveals real name + repos)
  - Holehe — 120+ site registration check
  - LeakCheck public — breach data (no key)
  - EmailRep.io — reputation, disposable, spam flag (no key)
  - DuckDuckGo/Google CSE web search
  - Disposable domain detection (500+ domains)
  - Deep-links: HIBP, LeakCheck, Epieos, Hunter.io, etc.

Optional (better data if keys set):
  - HIBP API key → full breach detail
  - LeakCheck paid key → more breach sources
"""

import hashlib
import re
import concurrent.futures
import requests

from config import DISPOSABLE_DOMAINS, SOCIAL_DOMAINS
from modules.search import search
from modules.breach import check_breach
from modules.holehe_runner import run_holehe


# ── Main entry point ──────────────────────────────────────────────────────────

def scan_email(email: str) -> dict:
    email = email.strip().lower()
    domain = email.split("@")[-1]
    is_disposable = domain in DISPOSABLE_DOMAINS

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        f_gravatar  = pool.submit(_gravatar, email)
        f_github    = pool.submit(_github_commits, email)
        f_holehe    = pool.submit(run_holehe, email)
        f_breach    = pool.submit(check_breach, email)
        f_emailrep  = pool.submit(_emailrep, email)

    gravatar  = f_gravatar.result()
    github    = f_github.result()
    holehe    = f_holehe.result()
    breach    = f_breach.result()
    emailrep  = f_emailrep.result()

    web_results = search(f'"{email}"', max_results=10)
    social_hits = [r for r in web_results if any(d in r["link"] for d in SOCIAL_DOMAINS)]

    # ── Score ────────────────────────────────────────────────────────────────
    score = 0
    if gravatar["found"]:        score += 20
    if github["commits"]:        score += 15
    if holehe["found"]:          score += min(len(holehe["found"]) * 5, 25)
    if breach["breached"]:       score += 25
    if social_hits:              score += min(len(social_hits) * 5, 15)
    score = min(score, 100)

    # ── Summary chips ────────────────────────────────────────────────────────
    chips = []
    if is_disposable:              chips.append({"label": "Disposable address", "color": "red"})
    if breach["breached"]:         chips.append({"label": f"Breached ({breach['count']} leaks)", "color": "red"})
    if gravatar["found"]:          chips.append({"label": "Gravatar profile", "color": "green"})
    if github["commits"]:          chips.append({"label": f"GitHub commits ({len(github['commits'])})", "color": "blue"})
    if holehe["found"]:            chips.append({"label": f"Registered on {len(holehe['found'])} sites", "color": "orange"})
    if emailrep.get("suspicious"): chips.append({"label": "Flagged as suspicious", "color": "red"})
    if not chips:                  chips.append({"label": "Low public exposure", "color": "gray"})

    # ── Deep-links ───────────────────────────────────────────────────────────
    deep_links = [
        {"label": "Have I Been Pwned",  "url": f"https://haveibeenpwned.com/account/{email}"},
        {"label": "LeakCheck",          "url": f"https://leakcheck.io/?query={email}"},
        {"label": "Epieos",             "url": f"https://epieos.com/?q={email}&t=email"},
        {"label": "Hunter.io",          "url": f"https://hunter.io/email-verifier/{email}"},
        {"label": "EmailRep",           "url": f"https://emailrep.io/{email}"},
        {"label": "Holehe (online)",    "url": f"https://holehe.netlify.app/?email={email}"},
        {"label": "Google search",      "url": f"https://www.google.com/search?q=%22{email}%22"},
        {"label": "Gravatar",           "url": f"https://gravatar.com/{hashlib.md5(email.encode()).hexdigest()}"},
    ]

    return {
        "type": "email",
        "query": email,
        "score": score,
        "chips": chips,
        "is_disposable": is_disposable,
        "domain": domain,
        "gravatar": gravatar,
        "github": github,
        "holehe": holehe,
        "breach": breach,
        "emailrep": emailrep,
        "web_results": web_results,
        "social_hits": social_hits,
        "deep_links": deep_links,
        "tools_used": _tools_used(gravatar, github, holehe, breach, emailrep),
    }


# ── Sub-scanners ──────────────────────────────────────────────────────────────

def _gravatar(email: str) -> dict:
    h = hashlib.md5(email.encode()).hexdigest()
    profile_url = f"https://gravatar.com/{h}.json"
    avatar_url  = f"https://www.gravatar.com/avatar/{h}?d=404"
    try:
        r = requests.get(profile_url, timeout=8)
        if r.status_code == 200:
            entry = r.json().get("entry", [{}])[0]
            return {
                "found": True,
                "name": entry.get("displayName", ""),
                "bio": entry.get("aboutMe", ""),
                "avatar": f"https://www.gravatar.com/avatar/{h}?s=200",
                "profile_url": f"https://gravatar.com/{h}",
                "urls": [u.get("value", "") for u in entry.get("urls", [])],
                "hash": h,
            }
        # Try if avatar exists even without a profile
        ra = requests.get(avatar_url, timeout=5)
        if ra.status_code == 200:
            return {"found": True, "name": "", "bio": "", "avatar": f"https://www.gravatar.com/avatar/{h}?s=200",
                    "profile_url": f"https://gravatar.com/{h}", "urls": [], "hash": h}
    except Exception:
        pass
    return {"found": False, "hash": h}


def _github_commits(email: str) -> dict:
    """Search GitHub for commits authored by this email — reveals real name + repos."""
    try:
        r = requests.get(
            "https://api.github.com/search/commits",
            params={"q": f"author-email:{email}", "per_page": 10},
            headers={"Accept": "application/vnd.github.cloak-preview"},
            timeout=10,
        )
        if r.status_code != 200:
            return {"commits": [], "author_name": "", "repos": []}
        items = r.json().get("items", [])
        author_name = ""
        repos = []
        commits = []
        for item in items:
            author = item.get("commit", {}).get("author", {})
            if not author_name and author.get("name"):
                author_name = author["name"]
            repo = item.get("repository", {})
            repo_name = repo.get("full_name", "")
            repo_url  = repo.get("html_url", "")
            if repo_name and repo_name not in repos:
                repos.append({"name": repo_name, "url": repo_url})
            commits.append({
                "sha": item.get("sha", "")[:7],
                "message": item.get("commit", {}).get("message", "").split("\n")[0][:80],
                "repo": repo_name,
                "url": item.get("html_url", ""),
            })
        return {"commits": commits, "author_name": author_name, "repos": repos[:5]}
    except Exception:
        return {"commits": [], "author_name": "", "repos": []}


def _emailrep(email: str) -> dict:
    """EmailRep.io — free, no key — reputation, spam, disposable flags."""
    try:
        r = requests.get(
            f"https://emailrep.io/{email}",
            headers={"User-Agent": "GhostTrace-v3"},
            timeout=8,
        )
        if r.status_code == 200:
            d = r.json()
            rep = d.get("reputation", "none")
            details = d.get("details", {})
            return {
                "reputation": rep,
                "suspicious": d.get("suspicious", False),
                "blacklisted": details.get("blacklisted", False),
                "malicious": details.get("malicious_activity", False),
                "spam": details.get("spam", False),
                "data_breach": details.get("data_breach", False),
                "profiles": details.get("profiles", []),
                "days_since_seen": details.get("days_since_domain_creation", None),
            }
    except Exception:
        pass
    return {}


def _tools_used(gravatar, github, holehe, breach, emailrep) -> list[str]:
    tools = ["Web Search (DuckDuckGo/Google CSE)", "Disposable Domain Check"]
    if gravatar.get("found"):  tools.append("Gravatar Profile Lookup")
    if github.get("commits"):  tools.append("GitHub Commit Search")
    if holehe.get("installed"): tools.append("Holehe (120+ sites)")
    if emailrep:               tools.append("EmailRep.io Reputation")
    if breach.get("sources"):  tools.append("LeakCheck Public / HIBP")
    return tools
