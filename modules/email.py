"""
modules/email.py — email scan
"""

import hashlib
import urllib.parse

import requests

from config import HIBP_API_KEY, LEAKCHECK_KEY
from modules.breach import check_breaches
from modules.search import web_search, build_result_entry, extract_domain

TIMEOUT = 12


# ── Gravatar ─────────────────────────────────────────────────

def _gravatar(email: str) -> tuple[list[dict], bool, str]:
    h = hashlib.sha256(email.strip().lower().encode()).hexdigest()
    results: list[dict] = []
    profile_found = False

    try:
        resp = requests.get(f"https://gravatar.com/{h}.json", timeout=TIMEOUT)
        if resp.status_code == 200:
            entries = resp.json().get("entry") or []
            entry = entries[0] if entries else {}
            if entry:
                profile_found = True
                name = (
                    entry.get("displayName")
                    or entry.get("preferredUsername")
                    or "Gravatar Profile"
                )
                url = entry.get("profileUrl") or f"https://gravatar.com/{h}"
                results.append({
                    "platform": f"Gravatar Profile — {name}",
                    "icon": "🪪",
                    "url": url,
                    "status": "found",
                    "type": "auto",
                })
                for acc in entry.get("accounts") or []:
                    label = acc.get("shortname") or acc.get("name") or "Linked Account"
                    acc_url = acc.get("url")
                    if acc_url:
                        results.append({
                            "platform": str(label).title(),
                            "icon": "🔗",
                            "url": acc_url,
                            "status": "found",
                            "type": "auto",
                        })
    except (requests.RequestException, ValueError):
        pass

    if not profile_found:
        try:
            r = requests.get(
                f"https://www.gravatar.com/avatar/{h}?d=404", timeout=TIMEOUT
            )
            results.append({
                "platform": "Gravatar Avatar",
                "icon": "🖼️",
                "url": f"https://www.gravatar.com/avatar/{h}",
                "status": "found" if r.status_code == 200 else "not_found",
                "type": "auto",
            })
        except requests.RequestException:
            pass

    return results, profile_found, h


# ── Main ─────────────────────────────────────────────────────

def check_email(email: str) -> tuple[list[dict], int, dict]:
    email = email.strip()
    encoded = urllib.parse.quote(email)
    results: list[dict] = []

    # 1. Gravatar
    gravatar_results, profile_found, _ = _gravatar(email)
    results.extend(gravatar_results)

    # 2. Breach check (3-tier: HIBP paid → LeakCheck → HIBP k-anon)
    breach_names, breach_source, breach_error = check_breaches(email)

    if breach_names is not None:
        if breach_names:
            preview = ", ".join(breach_names[:5])
            suffix  = f" (+{len(breach_names)-5} more)" if len(breach_names) > 5 else ""
            results.append({
                "platform": f"⚠️ Found in {len(breach_names)} breach(es): {preview}{suffix}",
                "icon":  "🛡️",
                "url":   f"https://haveibeenpwned.com/account/{encoded}",
                "status": "found",
                "type":  "auto",
            })
        else:
            results.append({
                "platform": f"✅ No known breaches ({breach_source})",
                "icon":  "🛡️",
                "url":   f"https://haveibeenpwned.com/account/{encoded}",
                "status": "not_found",
                "type":  "auto",
            })
    else:
        # Check failed — add a deep-link so user can verify manually
        results.append({
            "platform": "Have I Been Pwned — check manually",
            "icon":  "🛡️",
            "url":   f"https://haveibeenpwned.com/account/{encoded}",
            "status": "link",
            "type":  "manual",
        })

    # 3. Web search for public mentions
    search_results, search_error = web_search(f'"{email}"', num=15)
    found_count = 0
    for item in search_results:
        results.append(build_result_entry(item))
        found_count += 1

    # ── Summary ──
    summary: dict = {
        "gravatar_profile": "Found" if profile_found else "Not found",
        "public_mentions":  found_count,
        "breach_source":    breach_source,
    }
    if breach_names is not None:
        summary["breaches"] = len(breach_names)
    if breach_error:
        summary["breach_note"] = breach_error
    if search_error:
        summary["search_note"] = "Web search error: " + search_error

    # Indicate which search engine was used
    from config import SERPAPI_KEY
    summary["search_engine"] = "SerpAPI" if SERPAPI_KEY else "DuckDuckGo (free)"

    score = min(100, found_count * 20 + (20 if breach_names else 0))
    return results, score, summary
