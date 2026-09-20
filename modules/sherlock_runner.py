"""
modules/sherlock_runner.py

Runs Sherlock (https://github.com/sherlock-project/sherlock) as a subprocess
and parses its output. Sherlock checks usernames across 300+ platforms.

Install: pip install sherlock-project
Usage:   called by modules/username.py — do not call directly.

Sherlock is used to EXTEND the existing 30-platform checker, not replace it.
Existing API-enriched results (GitHub, Reddit, HackerNews with avatars/bios)
are kept as-is. Sherlock fills in the remaining ~270+ platforms.
"""

import subprocess
import sys
import re
from typing import Optional


# Platforms already covered by the API-enriched checker in username.py.
# Sherlock results for these are dropped to avoid duplicate cards.
_ALREADY_CHECKED = {
    "github", "gitlab", "reddit", "dev.to", "hackerrank", "replit",
    "keybase", "pastebin", "hackernews", "hacker news", "gravatar",
    "producthunt", "product hunt", "hashnode", "codepen", "about.me",
    "linktree", "substack", "medium", "tumblr", "wordpress", "mastodon",
    "flickr", "vimeo", "wattpad", "genius", "angellist", "crunchbase",
    "codeforces", "leetcode", "kaggle", "behance", "dribbble",
}

# Friendly icons for platforms Sherlock commonly finds
_ICONS: dict[str, str] = {
    "twitter": "🐦", "x": "🐦", "instagram": "📸", "facebook": "📘",
    "tiktok": "🎵", "youtube": "▶️", "twitch": "🟣", "discord": "🎮",
    "pinterest": "📌", "snapchat": "👻", "linkedin": "💼",
    "steam": "🎮", "steamcommunity": "🎮", "spotify": "🎧",
    "soundcloud": "🎙️", "lastfm": "🎵", "myspace": "🔵",
    "quora": "❓", "stackoverflow": "💡", "stack overflow": "💡",
    "bitbucket": "🪣", "sourceforge": "🔧", "npm": "📦",
    "pypi": "🐍", "dockerhub": "🐳", "docker hub": "🐳",
    "tryhackme": "🔓", "hackthebox": "📦", "hack the box": "📦",
    "bugcrowd": "🐛", "hackerone": "🏅",
    "duolingo": "🦜", "chess.com": "♟️", "lichess": "♟️",
    "fiverr": "💚", "upwork": "💼",
}


def _icon(name: str) -> str:
    key = name.lower().strip()
    for k, v in _ICONS.items():
        if k in key:
            return v
    return "🔗"


def _sherlock_available() -> bool:
    """Return True if sherlock-project is installed."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "sherlock", "--help"],
            capture_output=True, timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    try:
        result = subprocess.run(
            ["sherlock", "--help"],
            capture_output=True, timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_sherlock(username: str, timeout: int = 180) -> tuple[list[dict], int, Optional[str]]:
    """
    Run Sherlock and return:
        (results, platforms_checked, error_message)

    results: list of GhostTrace-format result dicts (found only)
    platforms_checked: total number of sites Sherlock checked
    error_message: None on success, string on error/warning
    """
    if not _sherlock_available():
        return [], 0, (
            "Sherlock not installed — run `pip install sherlock-project` "
            "then restart the app for 300+ platform username search."
        )

    cmd = [
        sys.executable, "-m", "sherlock",
        "--print-found",    # only print found accounts
        "--no-color",       # plain output for easy parsing
        "--timeout", "10",  # per-site timeout
        username,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return [], 0, f"Sherlock timed out after {timeout}s."
    except FileNotFoundError:
        try:
            cmd[0] = "sherlock"
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return [], 0, f"Sherlock error: {e}"

    output = proc.stdout + proc.stderr
    results: list[dict] = []
    platforms_checked = 0

    # Parse Sherlock output lines:
    # [*] Checking username ashtid on:
    # [+] Twitter: https://twitter.com/ashtid
    # [-] Instagram: Not Found!
    # [!] Wattpad: Illegal Username Format For This Site!
    # [*] Search completed with 1 results

    found_pattern    = re.compile(r"^\[\+\]\s+(.+?):\s+(https?://\S+)", re.IGNORECASE)
    checked_pattern  = re.compile(r"Search completed with \d+ results")
    total_pattern    = re.compile(r"(\d+) results")

    for line in output.splitlines():
        line = line.strip()

        m = found_pattern.match(line)
        if m:
            platform_name = m.group(1).strip()
            url           = m.group(2).strip()

            # Skip platforms already covered by the existing checker
            if platform_name.lower() in _ALREADY_CHECKED:
                continue

            results.append({
                "platform":     platform_name,
                "icon":         _icon(platform_name),
                "url":          url,
                "status":       "found",
                "type":         "auto",
                "avatar":       "",
                "display_name": username,
                "bio":          "",
                "meta":         "🔍 via Sherlock",
            })
            continue

        if checked_pattern.search(line):
            m2 = total_pattern.search(line)
            # Sherlock doesn't print total checked, only found count.
            # We use 300 as a reasonable approximation.
            platforms_checked = 300

    results.sort(key=lambda r: r["platform"].lower())
    return results, platforms_checked or 300, None
