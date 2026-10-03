"""
modules/page_analysis.py — DEEP-mode analysis of the page behind a URL/domain.

Fetches the page SSRF-safely (modules.safe_http) and extracts scam-relevant facts:
redirect chain, title, forms (where they post, what they ask for), hidden iframes,
meta-refresh, urgency language, brand mentions, chat/contact links. Also looks up the
earliest Wayback Machine snapshot as a free proxy for how long the site has existed.
Facts only; scoring lives in modules/scam.py.
"""
from __future__ import annotations
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin

import requests

from modules.safe_http import safe_get, UnsafeURL

_SENSITIVE = {
    "password": "password", "passwd": "password", "otp": "OTP", "pin": "PIN",
    "cvv": "CVV", "cvc": "CVV", "card": "card number", "aadhaar": "Aadhaar",
    "aadhar": "Aadhaar", "pan": "PAN", "upi": "UPI details", "mpin": "PIN",
    "expiry": "card expiry", "netbank": "net-banking login",
}
_URGENT = ("urgent", "immediately", "within 24 hours", "account will be blocked",
           "account suspended", "last chance", "act now", "limited time", "expires today",
           "verify your account", "kyc", "claim your", "you have won", "congratulations")


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self._in_title = "", False
        self.forms, self._form = [], None
        self.iframes, self.scripts, self.links = [], [], []
        self.meta_refresh = None
        self.text = []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "inputs": []}
            self.forms.append(self._form)
        elif tag == "input":
            blob = " ".join(a.get(k, "") for k in ("type", "name", "id", "placeholder", "autocomplete")).lower()
            if self._form is not None:
                self._form["inputs"].append(blob)
            else:   # inputs outside <form> (JS-driven pages) still count
                self.forms.append({"action": "", "inputs": [blob]})
        elif tag == "iframe":
            style = a.get("style", "").replace(" ", "").lower()
            hidden = ("display:none" in style or "visibility:hidden" in style
                      or a.get("width") in ("0", "1") or a.get("height") in ("0", "1"))
            self.iframes.append({"src": a.get("src", ""), "hidden": hidden})
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh = a.get("content", "")

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif sum(len(t) for t in self.text) < 20000:
            self.text.append(data)


def _host(u: str) -> str:
    return (urlparse(u).hostname or "").lower()


def analyze(url: str) -> dict:
    """Return page facts, or {"error": ...}. Never raises."""
    from modules.scam import _registrable, INDIAN_BRANDS
    facts = {"requested": url, "error": None}
    try:
        r = safe_get(url, timeout=8)
    except UnsafeURL as e:
        return {**facts, "error": f"blocked: {e}"}
    except Exception as e:
        return {**facts, "error": f"unreachable ({type(e).__name__})"}

    chain = getattr(r, "chain", [url])
    final = chain[-1]
    pg = _Page()
    try:
        pg.feed(r.text)
    except Exception:
        pass
    text = " ".join(pg.text).lower()
    page_host = _host(final)

    forms = []
    for f in pg.forms:
        act = urljoin(final, f["action"]) if f["action"] else final
        asks = sorted({label for blob in f["inputs"] for key, label in _SENSITIVE.items() if key in blob})
        forms.append({"action_host": _host(act), "asks_for": asks})

    ext_scripts = {h for h in (_host(urljoin(final, s)) for s in pg.scripts) if h and h != page_host}
    contact = sorted({h for h in (_host(urljoin(final, l)) for l in pg.links)
                      if h in ("wa.me", "api.whatsapp.com", "t.me", "telegram.me")})
    brands = [b for b in INDIAN_BRANDS if re.search(r"\b" + re.escape(b) + r"\b", (pg.title + " " + text[:3000]).lower())]

    return {
        **facts,
        "status": r.status_code,
        "final_url": final,
        "chain": chain,
        "cross_domain_redirect": _registrable(_host(chain[0])) != _registrable(page_host),
        "title": pg.title.strip()[:150],
        "forms": forms,
        "hidden_iframes": sum(1 for i in pg.iframes if i["hidden"]),
        "meta_refresh": bool(pg.meta_refresh),
        "external_script_hosts": len(ext_scripts),
        "urgent_phrases": [p for p in _URGENT if p in text][:6],
        "brand_mentions": brands[:4],
        "contact_links": contact,
    }


def first_seen(host: str) -> str | None:
    """ISO date of the earliest Wayback snapshot, or None (never archived / lookup failed)."""
    try:
        r = requests.get("https://archive.org/wayback/available",
                         params={"url": host, "timestamp": "19960101"}, timeout=6,
                         headers={"User-Agent": "GhostTrace/3.1"})
        snap = (r.json().get("archived_snapshots") or {}).get("closest")
        if snap and snap.get("timestamp"):
            ts = snap["timestamp"]
            return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
    except Exception:
        pass
    return None
