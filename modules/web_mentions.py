"""
modules/web_mentions.py — DEEP mode: does the open web already call this indicator a scam?

Searches for the indicator next to scam words and counts only results whose title/snippet
contain BOTH the indicator itself and a scam word. Free (DuckDuckGo / optional Google CSE).
"""
from __future__ import annotations
import re

from modules.search import search

_SCAM_WORDS = ("scam", "fraud", "fraudster", "phishing", "fake", "cheated", "spam",
               "beware", "complaint", "looted", "blacklist", "scammer")


def _variants(kind: str, value: str) -> list[str]:
    v = value.strip().lower()
    if kind == "phone":
        d = re.sub(r"\D", "", v)
        d = d[-10:] if len(d) >= 10 else d
        return [d] if len(d) >= 7 else []
    return [v]


def _text_has(kind: str, text: str, variants: list[str]) -> bool:
    t = text.lower()
    if kind == "phone":
        digits = re.sub(r"\D", "", t)
        return any(x in digits for x in variants)
    return any(x in t for x in variants)


def scam_mentions(kind: str, value: str) -> dict:
    """{"hits": n, "examples": [{title, link}]}. Never raises."""
    variants = _variants(kind, value)
    if not variants:
        return {"hits": 0, "examples": []}
    q = f'"{value.strip()}" scam OR fraud OR phishing OR fake OR complaint'
    hits = []
    for r in search(q, max_results=10):
        blob = f"{r.get('title','')} {r.get('snippet','')}"
        if _text_has(kind, blob, variants) and any(w in blob.lower() for w in _SCAM_WORDS):
            hits.append({"title": r.get("title", "")[:120], "link": r.get("link", "")})
    return {"hits": len(hits), "examples": hits[:3]}
