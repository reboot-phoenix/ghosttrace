"""
modules/name_match.py — strict name verification for web-search results.

Search engines treat quoted names as a hint, not a rule, and happily return "Disha Dutta"
for "Dithsa Dutta". A result only counts as a name match if the FULL name actually appears
in its title, snippet or URL (any token order, any separator, accents ignored).
"""
from __future__ import annotations
import re
import unicodedata
from urllib.parse import urlparse


def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKD", s or "")
    s = "".join(c for c in s if not unicodedata.combining(c)).lower()
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", s)).strip()


def _phrase_in(phrase: str, text: str) -> bool:
    return bool(phrase) and re.search(r"(?<![a-z0-9])" + re.escape(phrase) + r"(?![a-z0-9])", text) is not None


def matches_name(name: str, title: str = "", snippet: str = "", url: str = "") -> bool:
    toks = _norm(name).split()
    if not toks:
        return False
    forward = " ".join(toks)
    backward = " ".join(reversed(toks))
    text = _norm(f"{title} {snippet}")
    path = _norm(urlparse(url).path.replace("/", " ") + " " + (urlparse(url).hostname or "")) if url else ""
    for hay in (text, path):
        if _phrase_in(forward, hay) or (len(toks) > 1 and _phrase_in(backward, hay)):
            return True
    # handles like linkedin.com/in/dithsadutta97 or @dithsa.dutta
    if len(toks) > 1 and url:
        compact = "".join(toks)
        compact_rev = "".join(reversed(toks))
        u = re.sub(r"[^a-z0-9]", "", url.lower())
        if compact in u or compact_rev in u:
            return True
    return False


def filter_results(name: str, results: list[dict]) -> tuple[list[dict], int]:
    """Return (verified results, number discarded)."""
    kept = [r for r in results
            if matches_name(name, r.get("title", ""), r.get("snippet", ""), r.get("link", ""))]
    return kept, len(results) - len(kept)
