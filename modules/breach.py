"""
breach.py — unified breach-check module
-----------------------------------------
Priority order (first configured source wins):

  1. HIBP paid API  (best data, $3.50/mo at haveibeenpwned.com/API/Key)
  2. LeakCheck API  (free tier: 50 req/day; paid tiers available)
  3. HIBP k-anonymity range (free, no key — checks if the email string
     itself appears in the Pwned Passwords dataset, i.e. someone used
     their email address as a password. Catches a surprisingly large
     chunk of careless accounts.)

All paths return:
    breach_names  list[str] | None   — None means "check failed / unavailable"
    source        str                — which provider answered
    error         str | None         — human-readable error if anything went wrong
"""

import hashlib
import urllib.parse
import logging

import requests

from config import HIBP_API_KEY, LEAKCHECK_KEY

TIMEOUT = 12
log = logging.getLogger(__name__)


# ── 1. HIBP paid ────────────────────────────────────────────

def _hibp_paid(email: str) -> tuple[list[str] | None, str | None]:
    """
    Official HIBP v3 breachedaccount endpoint.
    Returns (breach_names, error).
    """
    url = (
        "https://haveibeenpwned.com/api/v3/breachedaccount/"
        + urllib.parse.quote(email)
    )
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent":   "GhostTrace-OSINT-Tool",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
    except requests.RequestException as e:
        return None, f"HIBP request failed: {e}"

    if resp.status_code == 200:
        breaches = resp.json()
        return [b.get("Name", "Unknown") for b in breaches], None
    if resp.status_code == 404:
        return [], None          # clean — no breaches
    if resp.status_code == 401:
        return None, "HIBP key invalid or expired"
    if resp.status_code == 429:
        return None, "HIBP rate limit — try again shortly"
    return None, f"HIBP HTTP {resp.status_code}"


# ── 2. LeakCheck ────────────────────────────────────────────

def _leakcheck(email: str) -> tuple[list[str] | None, str | None]:
    """
    LeakCheck API v2.
    Free plan: 50 lookups/day, no credit card needed.
    Sign up at https://leakcheck.io to get a key.
    Returns (source_names, error).
    """
    try:
        resp = requests.get(
            "https://leakcheck.io/api/v2/query/" + urllib.parse.quote(email),
            headers={
                "X-API-Key": LEAKCHECK_KEY,
                "User-Agent": "GhostTrace-OSINT-Tool",
            },
            timeout=TIMEOUT,
        )
    except requests.RequestException as e:
        return None, f"LeakCheck request failed: {e}"

    if resp.status_code == 401:
        return None, "LeakCheck key invalid"
    if resp.status_code == 429:
        return None, "LeakCheck daily limit reached (50/day on free tier)"
    if resp.status_code == 404:
        return [], None   # not found = clean

    try:
        data = resp.json()
    except ValueError:
        return None, "LeakCheck returned invalid JSON"

    if not data.get("success"):
        msg = data.get("message", "unknown error")
        # "Not found" counts as clean, not an error
        if "not found" in msg.lower():
            return [], None
        return None, f"LeakCheck error: {msg}"

    # Each entry has a "sources" list of dicts with "name"
    sources: list[str] = []
    for entry in data.get("result") or []:
        for src in entry.get("sources") or []:
            name = src.get("name", "Unknown")
            if name not in sources:
                sources.append(name)

    return sources, None


# ── 3. HIBP k-anonymity (free, no key) ──────────────────────

def _hibp_kanon(email: str) -> tuple[list[str] | None, str | None]:
    """
    Hashes the email with SHA-1, sends only the first 5 hex chars to
    HIBP's free Pwned Passwords range endpoint, and checks whether the
    full hash appears in the returned bloom.

    This does NOT query breached *accounts* (that requires a paid key).
    It checks whether the email string itself has been seen as a
    *password* in breach dumps — common enough to be worth surfacing.
    """
    sha1 = hashlib.sha1(email.strip().lower().encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true", "User-Agent": "GhostTrace-OSINT-Tool"},
            timeout=TIMEOUT,
        )
    except requests.RequestException as e:
        return None, f"HIBP range request failed: {e}"

    if resp.status_code != 200:
        return None, f"HIBP range API returned HTTP {resp.status_code}"

    for line in resp.text.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[0] == suffix:
            count = parts[1].strip()
            # Return a pseudo-breach name that explains what was found
            return [f"Pwned Passwords ({count}× seen)"], None

    return [], None   # email string not found in password dumps


# ── Public interface ─────────────────────────────────────────

def check_breaches(email: str) -> tuple[list[str] | None, str, str | None]:
    """
    Returns (breach_names, source_label, error).

    breach_names:
        list  → definitive answer (may be empty = clean)
        None  → check failed; error describes why
    source_label: human-readable name of the provider that answered
    error: string or None
    """
    if HIBP_API_KEY:
        names, err = _hibp_paid(email)
        return names, "HIBP", err

    if LEAKCHECK_KEY:
        names, err = _leakcheck(email)
        return names, "LeakCheck", err

    # Free fallback — always runs when no key is configured
    names, err = _hibp_kanon(email)
    return names, "HIBP Pwned Passwords", err
