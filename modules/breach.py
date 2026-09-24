"""
modules/breach.py — data breach lookup for GhostTrace v3

Free chain (no key needed at all):
  1. HIBP paid key  → best data, if HIBP_API_KEY set
  2. LeakCheck paid → if LEAKCHECK_KEY set  
  3. LeakCheck public (FREE, no key) → returns breach names
  4. Nothing else — we removed the k-anon password check (it was misleading)
"""

import hashlib
import requests
from config import HIBP_API_KEY, LEAKCHECK_KEY


def check_breach(email: str) -> dict:
    """Returns {breached: bool, count: int, sources: [str], error: str|None}"""
    if HIBP_API_KEY:
        return _hibp(email)
    if LEAKCHECK_KEY:
        return _leakcheck_paid(email)
    return _leakcheck_public(email)


def _hibp(email: str) -> dict:
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={"hibp-api-key": HIBP_API_KEY, "user-agent": "GhostTrace-v3"},
            params={"truncateResponse": "false"},
            timeout=10,
        )
        if r.status_code == 200:
            breaches = r.json()
            return {
                "breached": True,
                "count": len(breaches),
                "sources": [b.get("Name", "Unknown") for b in breaches],
                "error": None,
            }
        if r.status_code == 404:
            return {"breached": False, "count": 0, "sources": [], "error": None}
        return {"breached": False, "count": 0, "sources": [], "error": f"HIBP HTTP {r.status_code}"}
    except Exception as e:
        return {"breached": False, "count": 0, "sources": [], "error": str(e)}


def _leakcheck_paid(email: str) -> dict:
    try:
        r = requests.get(
            "https://leakcheck.io/api/v2/query/" + email,
            headers={"X-API-Key": LEAKCHECK_KEY},
            timeout=10,
        )
        data = r.json()
        if data.get("success") and data.get("found", 0) > 0:
            sources = [s.get("name", "Unknown") for s in data.get("sources", [])]
            return {"breached": True, "count": data["found"], "sources": sources, "error": None}
        return {"breached": False, "count": 0, "sources": [], "error": None}
    except Exception as e:
        return {"breached": False, "count": 0, "sources": [], "error": str(e)}


def _leakcheck_public(email: str) -> dict:
    """100% free, no key — public endpoint, limited data but real."""
    try:
        r = requests.get(
            f"https://leakcheck.io/api/public?check={email}",
            timeout=10,
        )
        data = r.json()
        if data.get("success") and data.get("found", 0) > 0:
            sources = data.get("sources", [])
            return {
                "breached": True,
                "count": data["found"],
                "sources": sources if isinstance(sources, list) else [],
                "error": None,
            }
        return {"breached": False, "count": 0, "sources": [], "error": None}
    except Exception as e:
        return {"breached": False, "count": 0, "sources": [], "error": str(e)}
