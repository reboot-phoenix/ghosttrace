"""
modules/holehe_runner.py

Runs Holehe (https://github.com/megadose/holehe) as a subprocess and
parses its JSON output. Holehe checks whether an email is registered on
120+ services (Twitter, Adobe, Amazon, Discord, Dropbox, etc.) without
triggering breaches — it uses password-reset / account-exists probes.

Install: pip install holehe
Usage:   called by modules/email.py — do not call directly.
"""

import json
import subprocess
import sys
from typing import Optional


# Icons for well-known platforms returned by Holehe
_ICONS: dict[str, str] = {
    "twitter": "🐦", "adobe": "🎨", "amazon": "📦", "discord": "🎮",
    "dropbox": "📁", "flickr": "📷", "github": "🐙", "imgur": "🖼️",
    "instagram": "📸", "lastfm": "🎵", "linkedin": "💼", "netflix": "🎬",
    "notion": "📝", "paypal": "💳", "pinterest": "📌", "protonmail": "🔒",
    "quora": "❓", "reddit": "🤖", "shopify": "🛒", "signal": "🔐",
    "skype": "📞", "slack": "💬", "snapchat": "👻", "spotify": "🎧",
    "steam": "🎮", "tumblr": "🌀", "twitch": "🟣", "twitter": "🐦",
    "yahoo": "🔵", "youtube": "▶️", "zoom": "📹", "wordpress": "📰",
    "duolingo": "🦜", "soundcloud": "🎙️", "vimeo": "🎬",
}


def _icon(name: str) -> str:
    return _ICONS.get(name.lower(), "🔗")


def _holehe_available() -> bool:
    """Return True if holehe is installed and runnable."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "holehe", "--help"],
            capture_output=True, timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    try:
        result = subprocess.run(
            ["holehe", "--help"],
            capture_output=True, timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_holehe(email: str, timeout: int = 120) -> tuple[list[dict], Optional[str]]:
    """
    Run Holehe against an email and return a list of result dicts
    (matching the GhostTrace result format) and an optional error string.

    Each result dict:
        platform, icon, url, status ("found" | "not_found"), type ("auto")

    Only "found" results are returned — sites where the email is NOT
    registered are silently dropped to keep the UI clean.
    """
    if not _holehe_available():
        return [], (
            "Holehe not installed — run `pip install holehe` "
            "then restart the app for 120+ site email checks."
        )

    cmd = [sys.executable, "-m", "holehe", "--json", "--only-used", email]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return [], f"Holehe timed out after {timeout}s."
    except FileNotFoundError:
        # Fallback: try holehe directly as a script
        try:
            cmd[0] = "holehe"
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return [], f"Holehe error: {e}"

    # Holehe --json writes JSON to stdout, one object per line or as array.
    raw = proc.stdout.strip()
    if not raw:
        return [], None  # No hits — clean result

    results: list[dict] = []
    errors: list[str] = []

    # Holehe JSON output is a list of dicts:
    # [{"name": "twitter", "domain": "twitter.com", "rateLimit": false,
    #   "exists": true, "emailrecovery": null, "phoneNumber": null, "others": null}]
    try:
        # Try parsing as JSON array first
        entries = json.loads(raw)
        if not isinstance(entries, list):
            entries = [entries]
    except json.JSONDecodeError:
        # Fallback: one JSON object per line
        entries = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        if entry.get("rateLimit"):
            errors.append(entry.get("name", "?"))
            continue

        if not entry.get("exists"):
            continue  # not registered — skip

        name   = entry.get("name", "Unknown")
        domain = entry.get("domain", "")
        url    = f"https://{domain}" if domain else f"https://www.google.com/search?q={name}"

        result: dict = {
            "platform": name.title(),
            "icon":     _icon(name),
            "url":      url,
            "status":   "found",
            "type":     "auto",
            "avatar":   "",
            "display_name": email,
            "bio":      "",
            "meta":     "📧 Email registered" + (
                f" · 📞 {entry['phoneNumber']}" if entry.get("phoneNumber") else ""
            ),
        }
        results.append(result)

    error_msg = None
    if errors:
        error_msg = f"Rate-limited on: {', '.join(errors[:5])}" + (
            f" (+{len(errors)-5} more)" if len(errors) > 5 else ""
        )

    # Sort alphabetically by platform name
    results.sort(key=lambda r: r["platform"].lower())
    return results, error_msg
