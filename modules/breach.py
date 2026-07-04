"""
modules/breach.py — unified breach-check module
--------------------------------------------------
Priority order (first configured/working source wins):

  1. HIBP paid API     — best data, $3.50/mo at haveibeenpwned.com/API/Key
  2. LeakCheck paid    — full breach details, plans from $2.99/day
  3. LeakCheck PUBLIC  — completely free, no key, no signup needed.
                         Returns breach source names (not passwords).
                         Only requires a "Powered by LeakCheck" credit.
  4. HIBP k-anonymity  — free, no key. Checks if the email string was
                         used as a password in breach dumps (zero cost).

In practice for GhostTrace: steps 3 and 4 both work out of the box
with no configuration at all. Steps 1 and 2 need env vars set.

All paths return:
    breach_names  list[str] | None   — None means check failed
    source        str                — which provider answered
    error         str | None         — human-readable error or None
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
        return [b.get("Name", "Unknown") for b in resp.json()], None
    if resp.status_code == 404:
        return [], None
    if resp.status_code == 401:
        return None, "HIBP key invalid or expired"
    if resp.status_code == 429:
        return None, "HIBP rate limit — try again shortly"
    return None, f"HIBP HTTP {resp.status_code}"


# ── 2. LeakCheck paid API v2 ─────────────────────────────────

def _leakcheck_paid(email: str) -> tuple[list[str] | None, str | None]:
    """
    LeakCheck Pro API v2. Requires a paid plan key (from $2.99/day).
    Set LEAKCHECK_KEY env var in Render to use this.
    """
    try:
        resp = requests.get(
            "https://leakcheck.io/api/v2/query/" + urllib.parse.quote(email),
            headers={
                "X-API-Key":  LEAKCHECK_KEY,
                "User-Agent": "GhostTrace-OSINT-Tool",
            },
            timeout=TIMEOUT,
        )
    except requests.RequestException as e:
        return None, f"LeakCheck request failed: {e}"

    if resp.status_code == 401:
        return None, "LeakCheck key invalid"
    if resp.status_code == 429:
        return None, "LeakCheck rate limit hit"
    if resp.status_code == 404:
        return [], None

    try:
        data = resp.json()
    except ValueError:
        return None, "LeakCheck returned invalid JSON"

    if not data.get("success"):
        msg = data.get("message", "unknown error")
        if "not found" in msg.lower():
            return [], None
        return None, f"LeakCheck error: {msg}"

    sources: list[str] = []
    for entry in data.get("result") or []:
        src = entry.get("source") or {}
        name = src.get("name", "Unknown")
        if name and name not in sources:
            sources.append(name)

    return sources, None


# ── 3. LeakCheck PUBLIC API (free, no key, no signup) ────────

def _leakcheck_public(email: str) -> tuple[list[str] | None, str | None]:
    """
    LeakCheck's completely free public API.
    No key, no registration, no quota limit documented.
    Returns breach source names only (not passwords — that's paid-only).
    Requires a 'Powered by LeakCheck' credit on any page that displays results.
    Endpoint: https://leakcheck.io/api/public?check=<email>
    """
    try:
        resp = requests.get(
            "https://leakcheck.io/api/public",
            params={
                "check": email,
            },
            headers={"User-Agent": "GhostTrace-OSINT-Tool"},
            timeout=TIMEOUT,
        )
    except requests.RequestException as e:
        return None, f"LeakCheck public API request failed: {e}"

    if resp.status_code == 429:
        return None, "LeakCheck public API rate limited — try again shortly"

    try:
        data = resp.json()
    except ValueError:
        return None, "LeakCheck public API returned invalid JSON"

    if not data.get("success"):
        msg = data.get("message", "")
        # Empty message, "not found" text, or found=0 all mean clean — no breach
        if not msg or "not found" in msg.lower() or data.get("found") == 0:
            return [], None
        return None, f"LeakCheck public error: {msg}"

    # found=0 even on success means clean
    if data.get("found") == 0:
        return [], None

    # Response shape: { "success": true, "found": 3, "sources": [{"name": "...", "date": "..."}, ...] }
    sources = [s.get("name", "Unknown") for s in data.get("sources") or []]
    return sources, None


# ── 4. HIBP k-anonymity (free, no key) ──────────────────────

def _hibp_kanon(email: str) -> tuple[list[str] | None, str | None]:
    """
    Checks whether the email string itself has been used as a password
    in breach dumps (not whether the account was breached).
    Uses HIBP's free Pwned Passwords range endpoint — sends only
    the first 5 chars of the SHA-1 hash, so the full email never leaves.
    """
    sha1   = hashlib.sha1(email.strip().lower().encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

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
            return [f"Pwned Passwords ({count}× seen as a password)"], None

    return [], None


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
    # 1. HIBP paid (best data, requires key)
    if HIBP_API_KEY:
        names, err = _hibp_paid(email)
        return names, "HIBP", err

    # 2. LeakCheck paid (requires key)
    if LEAKCHECK_KEY:
        names, err = _leakcheck_paid(email)
        return names, "LeakCheck Pro", err

    # 3. LeakCheck public (completely free, no key needed — always runs)
    names, err = _leakcheck_public(email)
    if names is not None:
        return names, "LeakCheck (free)", None
    # If public API failed, log and fall through
    log.warning("LeakCheck public API failed: %s — falling back to HIBP k-anon", err)

    # 4. HIBP k-anonymity (free fallback — checks email-as-password only)
    names, err = _hibp_kanon(email)
    return names, "HIBP Pwned Passwords", err
