import hashlib
import urllib.parse

import requests

from config import SERPAPI_KEY, HIBP_API_KEY, SOCIAL_DOMAINS

TIMEOUT = 10


def _hash(email):
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


def _extract_domain(url):
    try:
        netloc = urllib.parse.urlparse(url).netloc.lower()
        return netloc[4:] if netloc.startswith("www.") else netloc
    except Exception:
        return ""


def _gravatar_lookup(email):
    h = _hash(email)
    results = []
    profile_found = False

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

    return results, profile_found, h


def _hibp_lookup(email):
    """
    Real breach check via HIBP's official v3 API. Requires a paid key —
    see https://haveibeenpwned.com/API/Key. Returns (breach_names, error).
    """
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "GhostTrace-OSINT-Tool",
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}"

    try:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)

        if resp.status_code == 200:
            breaches = resp.json()
            return [b.get("Name", "Unknown breach") for b in breaches], None

        if resp.status_code == 404:
            return [], None  # no breaches found — a real, good result

        if resp.status_code == 401:
            return None, "HIBP key invalid or expired"

        if resp.status_code == 429:
            return None, "HIBP rate limit hit — try again shortly"

        return None, f"HIBP returned HTTP {resp.status_code}"

    except requests.RequestException as e:
        return None, f"HIBP request failed: {str(e)[:100]}"


def _serpapi_search(query, num=15):
    params = {
        "engine": "google",
        "q": query,
        "num": num,
        "api_key": SERPAPI_KEY,
    }
    resp = requests.get("https://serpapi.com/search.json", params=params, timeout=TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    if data.get("error"):
        raise RuntimeError(data["error"])
    return data.get("organic_results", []) or []


def check_email(email):

    email = email.strip()
    encoded_email = urllib.parse.quote(email)
    results = []

    # 1. Gravatar — free, real, always attempted
    gravatar_results, profile_found, h = _gravatar_lookup(email)
    results.extend(gravatar_results)

    if not profile_found:
        try:
            avatar_resp = requests.get(f"https://www.gravatar.com/avatar/{h}?d=404", timeout=TIMEOUT)
            results.append({
                "platform": "Gravatar Avatar",
                "icon": "🖼️",
                "url": f"https://www.gravatar.com/avatar/{h}",
                "status": "found" if avatar_resp.status_code == 200 else "not_found",
                "type": "auto"
            })
        except requests.RequestException:
            pass

    # 2. Real breach check via HIBP, only if a paid key is configured
    breach_names = None
    hibp_error = None
    if HIBP_API_KEY:
        breach_names, hibp_error = _hibp_lookup(email)

        if breach_names is not None:
            if len(breach_names) > 0:
                results.append({
                    "platform": f"⚠️ Found in {len(breach_names)} breach(es): {', '.join(breach_names[:5])}",
                    "icon": "🛡️",
                    "url": f"https://haveibeenpwned.com/account/{encoded_email}",
                    "status": "found",
                    "type": "auto"
                })
            else:
                results.append({
                    "platform": "✅ No known breaches found (HIBP)",
                    "icon": "🛡️",
                    "url": f"https://haveibeenpwned.com/account/{encoded_email}",
                    "status": "not_found",
                    "type": "auto"
                })

    if not HIBP_API_KEY or hibp_error:
        # No key configured, or the real call failed — deep-link instead
        # of ever faking a breach result.
        results.append({
            "platform": "Have I Been Pwned — Breach Check",
            "icon": "🛡️",
            "url": f"https://haveibeenpwned.com/account/{encoded_email}",
            "status": "link",
            "type": "manual"
        })

    # 3. Real search hits mentioning this exact email publicly
    search_error = None
    if SERPAPI_KEY:
        try:
            organic = _serpapi_search(f'"{email}"', num=15)
            for item in organic:
                link = item.get("link")
                title = item.get("title", "Result")
                if not link:
                    continue
                domain = _extract_domain(link)
                platform_label = SOCIAL_DOMAINS.get(domain)
                results.append({
                    "platform": platform_label if platform_label else title[:60],
                    "icon": "🔗" if platform_label else "🌐",
                    "url": link,
                    "status": "found",
                    "type": "auto"
                })
        except (requests.RequestException, RuntimeError) as e:
            search_error = str(e)[:150]

    found_count = len([r for r in results if r.get("status") == "found"])

    summary = {
        "gravatar_profile": "Found" if profile_found else "Not found",
        "public_mentions": found_count,
    }
    if HIBP_API_KEY and breach_names is not None:
        summary["breaches"] = len(breach_names)
    elif hibp_error:
        summary["hibp_note"] = hibp_error
    elif not HIBP_API_KEY:
        summary["hibp_note"] = "Not configured (HIBP_API_KEY missing — showing manual link instead)"

    if search_error:
        summary["search_note"] = "Web search unavailable: " + search_error
    elif not SERPAPI_KEY:
        summary["search_note"] = "Web search not configured (SERPAPI_KEY missing)"

    score = min(100, found_count * 20)

    return results, score, summary
