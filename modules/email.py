"""
modules/email.py — email scan
"""

import hashlib
import urllib.parse
import requests

from config import HIBP_API_KEY, LEAKCHECK_KEY
from modules.breach import check_breaches
from modules.search import web_search, build_result_entry

TIMEOUT = 12

DISPOSABLE_DOMAINS = {
    "mailinator.com","tempmail.com","guerrillamail.com","10minutemail.com",
    "throwam.com","yopmail.com","trashmail.com","fakeinbox.com","maildrop.cc",
    "sharklasers.com","guerrillamailblock.com","grr.la","guerrillamail.info",
    "spam4.me","dispostable.com","mailnull.com","spamgourmet.com","spamgourmet.net",
    "spamgourmet.org","trashmail.at","trashmail.io","trashmail.me","trashmail.net",
    "trashmail.org","tempr.email","discard.email","mailnesia.com","mailsac.com",
    "spambox.us","spamfree24.org","spamtrap.ro","tempemail.net","throwam.com",
    "throwam.net","trbvn.com","wegwerfmail.de","wegwerfmail.net","wegwerfmail.org",
    "mohmal.com","temp-mail.org","temp-mail.io","getnada.com","filzmail.com",
    "owlpic.com","crazymailing.com","boun.cr","inoutmail.eu","inoutmail.info",
}


def _is_disposable(email: str) -> bool:
    domain = email.split("@")[-1].lower() if "@" in email else ""
    return domain in DISPOSABLE_DOMAINS


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
                    "icon": "🪪", "url": url,
                    "status": "found", "type": "auto",
                })
                for acc in entry.get("accounts") or []:
                    label = acc.get("shortname") or acc.get("name") or "Linked Account"
                    acc_url = acc.get("url")
                    if acc_url:
                        results.append({
                            "platform": str(label).title(),
                            "icon": "🔗", "url": acc_url,
                            "status": "found", "type": "auto",
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


def _epieos(email: str) -> list[dict]:
    """
    Epieos is a free email OSINT tool — it finds Google account info,
    YouTube channels, Google Maps reviews linked to an email.
    We provide the deep-link so users can check it themselves.
    """
    encoded = urllib.parse.quote(email)
    return [{
        "platform": "Epieos — Google account OSINT",
        "icon": "🕵️",
        "url": f"https://epieos.com/?q={encoded}&t=email",
        "status": "link",
        "type": "manual",
    }]


def _manual_links(email: str, encoded: str) -> list[dict]:
    return [
        {
            "platform": "Have I Been Pwned",
            "icon": "🛡️",
            "url": f"https://haveibeenpwned.com/account/{encoded}",
            "status": "link", "type": "manual",
        },
        {
            "platform": "LeakCheck",
            "icon": "🔍",
            "url": f"https://leakcheck.io/?query={encoded}",
            "status": "link", "type": "manual",
        },
        {
            "platform": "Epieos (Google account lookup)",
            "icon": "🕵️",
            "url": f"https://epieos.com/?q={encoded}&t=email",
            "status": "link", "type": "manual",
        },
        {
            "platform": "Hunter.io — email verification",
            "icon": "📧",
            "url": f"https://hunter.io/email-verifier/{encoded}",
            "status": "link", "type": "manual",
        },
        {
            "platform": "Google — email mentions",
            "icon": "🌐",
            "url": f"https://www.google.com/search?q=%22{encoded}%22",
            "status": "link", "type": "manual",
        },
    ]


def check_email(email: str) -> tuple[list[dict], int, dict]:
    email = email.strip()
    encoded = urllib.parse.quote(email)
    results: list[dict] = []

    # 1. Disposable email check
    disposable = _is_disposable(email)

    # 2. Gravatar
    gravatar_results, profile_found, _ = _gravatar(email)
    results.extend(gravatar_results)

    # 3. Breach check
    breach_names, breach_source, breach_error = check_breaches(email)

    if breach_names is not None:
        if breach_names:
            preview = ", ".join(breach_names[:5])
            suffix  = f" (+{len(breach_names) - 5} more)" if len(breach_names) > 5 else ""
            results.append({
                "platform": f"⚠️ Found in {len(breach_names)} breach(es): {preview}{suffix}",
                "icon": "🛡️",
                "url": f"https://haveibeenpwned.com/account/{encoded}",
                "status": "found", "type": "auto",
            })
        else:
            results.append({
                "platform": "✅ No known breaches found",
                "icon": "🛡️",
                "url": f"https://haveibeenpwned.com/account/{encoded}",
                "status": "not_found", "type": "auto",
            })

    # 4. Web search
    search_results, search_error = web_search(f'"{email}"', num=10)
    found_count = 0
    for item in search_results:
        results.append(build_result_entry(item))
        found_count += 1

    # 5. Manual deep-links
    results.extend(_manual_links(email, encoded))

    from config import SERPAPI_KEY, GOOGLE_CSE_KEY
    engine = "SerpAPI" if SERPAPI_KEY else ("Google CSE" if GOOGLE_CSE_KEY else "DuckDuckGo")

    summary: dict = {
        "gravatar_profile": "Found ✅" if profile_found else "Not found",
        "disposable_email": "⚠️ YES — throwaway domain" if disposable else "No",
        "public_mentions":  found_count,
        "breach_source":    breach_source,
        "search_engine":    engine,
    }
    if breach_names is not None:
        summary["breaches_found"] = len(breach_names)
    if breach_error:
        summary["breach_note"] = breach_error
    if search_error:
        summary["search_note"] = search_error

    score = min(100,
        found_count * 15
        + (20 if breach_names else 0)
        + (15 if profile_found else 0)
        + (10 if disposable else 0)
    )
    return results, score, summary
