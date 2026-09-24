"""
modules/maigret_runner.py — run Maigret as subprocess, parse JSON output

Maigret checks 3,100+ sites for a username. It's the most powerful
free username OSINT tool available. Fork of Sherlock with:
  - 3100+ sites (vs Sherlock's ~400)
  - Recursive identity mapping (finds linked accounts)
  - Profile data extraction (bio, name, location, links)
  - No API keys required

We replace Sherlock with Maigret entirely.
"""

import subprocess
import json
import os
import tempfile
import re


def run_maigret(username: str, timeout: int = 120, top_sites: int = 500) -> dict:
    """
    Returns {
        found: [{site, url, category, name, bio, location}],
        total_checked: int,
        summary: str,
        installed: bool,
        raw_tags: {}
    }
    top_sites: how many sites to check (default 500 = top 500 by traffic)
    Full scan (3100+) takes ~5 min; 500 is ~60s
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = os.path.join(tmpdir, f"{username}.json")
        try:
            cmd = [
                "maigret", username,
                "--json", report_path,
                "--no-color",
                "--timeout", "10",
                "--top-sites", str(top_sites),
                "--retries", "1",
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return _parse_json(report_path, username)
        except FileNotFoundError:
            return _not_installed()
        except subprocess.TimeoutExpired:
            # Try to read partial results
            if os.path.exists(report_path):
                return _parse_json(report_path, username, partial=True)
            return {"found": [], "total_checked": 0, "summary": "Maigret timed out", "installed": True, "raw_tags": {}}
        except Exception as e:
            return {"found": [], "total_checked": 0, "summary": f"Maigret error: {e}", "installed": True, "raw_tags": {}}


def _parse_json(path: str, username: str, partial: bool = False) -> dict:
    found = []
    raw_tags = {}
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except Exception:
        return {"found": [], "total_checked": 0, "summary": "Could not read Maigret output", "installed": True, "raw_tags": {}}

    sites = data.get("sites", {}) or data  # maigret JSON structure
    total = 0

    for site_name, info in sites.items():
        total += 1
        status = info.get("status", {})
        if isinstance(status, dict):
            found_flag = status.get("status") == "Claimed"
        else:
            found_flag = str(status).lower() in ("claimed", "found", "exists")

        if not found_flag:
            continue

        url = info.get("url_user", info.get("url", ""))
        category = info.get("tags", ["other"])[0] if info.get("tags") else "other"
        raw_tags[site_name] = info.get("tags", [])

        # Extract profile data if maigret parsed it
        profile = info.get("profile", {}) or {}
        entry = {
            "site": site_name,
            "url": url,
            "category": category,
            "name": profile.get("name", ""),
            "bio": profile.get("bio", ""),
            "location": profile.get("location", ""),
            "avatar": profile.get("image", ""),
            "linked_usernames": profile.get("usernames", []),
        }
        found.append(entry)

    # Sort: social first, then dev, then rest
    _order = {"social": 0, "coding": 1, "gaming": 2, "dating": 3, "other": 99}
    found.sort(key=lambda x: _order.get(x["category"], 50))

    suffix = " (partial scan — timed out)" if partial else ""
    summary = f"Found {len(found)} accounts across {total} sites checked{suffix}"
    return {"found": found, "total_checked": total, "summary": summary, "installed": True, "raw_tags": raw_tags}


def _not_installed() -> dict:
    return {
        "found": [], "total_checked": 0,
        "summary": "Maigret not installed — run: pip install maigret",
        "installed": False, "raw_tags": {}
    }
