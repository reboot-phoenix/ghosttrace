import hashlib
import urllib.parse

import requests

TIMEOUT = 6


def _hash(email):
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


def check_email(email):

    email = email.strip()
    h = _hash(email)
    results = []
    profile_found = False

    # 1. Gravatar profile — free, unauthenticated legacy JSON endpoint.
    #    Real linked accounts (Twitter, Mastodon, etc.) if the user has
    #    ever set them on their Gravatar profile.
    try:
        resp = requests.get(f"https://gravatar.com/{h}.json", timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            entries = data.get("entry") or []
            entry = entries[0] if entries else {}

            if entry:
                profile_found = True
                display_name = entry.get("displayName") or entry.get("preferredUsername") or "Gravatar Profile"
                profile_url = entry.get("profileUrl") or f"https://gravatar.com/{h}"

                results.append({
                    "platform": f"Gravatar Profile — {display_name}",
                    "icon": "🪪",
                    "url": profile_url,
                    "status": "found",
                    "type": "auto"
                })

                for acc in entry.get("accounts", []) or []:
                    label = acc.get("shortname") or acc.get("name") or "Linked Account"
                    acc_url = acc.get("url")
                    if acc_url:
                        results.append({
                            "platform": str(label).title(),
                            "icon": "🔗",
                            "url": acc_url,
                            "status": "found",
                            "type": "auto"
                        })
    except (requests.RequestException, ValueError):
        pass

    # 2. Gravatar avatar existence — weaker standalone signal (image only,
    #    no profile data) shown only if no full profile was found.
    if not profile_found:
        try:
            avatar_resp = requests.get(
                f"https://www.gravatar.com/avatar/{h}?d=404", timeout=TIMEOUT
            )
            results.append({
                "platform": "Gravatar Avatar",
                "icon": "🖼️",
                "url": f"https://www.gravatar.com/avatar/{h}",
                "status": "found" if avatar_resp.status_code == 200 else "not_found",
                "type": "auto"
            })
        except requests.RequestException:
            results.append({
                "platform": "Gravatar Avatar",
                "icon": "🖼️",
                "url": f"https://www.gravatar.com/avatar/{h}",
                "status": "error",
                "type": "auto"
            })

    encoded_email = urllib.parse.quote(email)

    # 3. Real breach checking requires a paid HIBP API key — deep-link to
    #    their actual site instead of faking an automated result.
    results.append({
        "platform": "Have I Been Pwned — Breach Check",
        "icon": "🛡️",
        "url": f"https://haveibeenpwned.com/account/{encoded_email}",
        "status": "link",
        "type": "manual"
    })

    results.append({
        "platform": "Google (email footprint)",
        "icon": "🔍",
        "url": f'https://www.google.com/search?q=%22{encoded_email}%22',
        "status": "link",
        "type": "manual"
    })

    found_count = len([r for r in results if r.get("status") == "found"])
    auto_checked = len([r for r in results if r.get("type") == "auto"])

    summary = {
        "gravatar_profile": "Found" if profile_found else "Not found",
        "linked_accounts": found_count,
        "checked": auto_checked
    }

    score = min(100, found_count * 25) if auto_checked else 0

    return results, score, summary
