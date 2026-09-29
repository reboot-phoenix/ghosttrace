"""
modules/social_pivot.py — deep-mode social profile pivoting

Finds *candidate* Instagram / Facebook / X / TikTok profiles for a target using
only public, unauthenticated checks (Maigret site probes). No logins, no
account-recovery or contact-sync lookups.

Candidate handles come from evidence already in the scan:
  linked        handles found inside profiles we already discovered  (strongest)
  input         the username the user searched
  email_local   local-part of a scanned email
  name_variant  first.last / firstlast / flast ... from a known real name (weakest)

Every hit is scored and labelled PROBABLE or LINKED — never CONFIRMED. A handle
existing on a platform does not prove it belongs to the target.
"""

from __future__ import annotations
import re
import difflib
import concurrent.futures

from modules.maigret_runner import run_maigret

SOCIAL_SITES = ["Instagram", "Facebook", "Twitter", "TikTok"]
MAX_CANDIDATES = 6
_GENERIC_LOCALPARTS = {"info", "admin", "contact", "hello", "support", "mail", "office", "sales", "team", "noreply", "no-reply"}
_ORIGIN_WEIGHT = {"linked": 0.55, "input": 0.50, "email_local": 0.35, "name_variant": 0.20}


def _clean(handle: str) -> str:
    return re.sub(r"[^a-z0-9._]", "", (handle or "").strip().lower().lstrip("@"))


def _name_variants(full_name: str) -> list[str]:
    parts = [re.sub(r"[^a-z]", "", p.lower()) for p in (full_name or "").split()]
    parts = [p for p in parts if p]
    if len(parts) < 2:
        return []
    first, last = parts[0], parts[-1]
    return [f"{first}.{last}", f"{first}{last}", f"{first}_{last}", f"{first[0]}{last}", f"{first}{last[0]}"]


def candidate_handles(scan_type: str, data: dict, identity: dict) -> list[dict]:
    """Return de-duplicated [{handle, origin}] ordered strongest-first, capped."""
    raw: list[tuple[str, str]] = []

    if scan_type == "username":
        raw.append((data.get("query", ""), "input"))
        for acc in data.get("found", []):
            for u in acc.get("linked_usernames", []) or []:
                raw.append((u, "linked"))

    elif scan_type == "email":
        email = data.get("query", "")
        local = email.split("@")[0] if "@" in email else ""
        for key in ("username", "login", "preferred_username"):
            for src in (data.get("gravatar", {}), data.get("github", {})):
                if src.get(key):
                    raw.append((src[key], "linked"))
        if local and local.lower() not in _GENERIC_LOCALPARTS:
            raw.append((local, "email_local"))

    if scan_type in ("name", "email", "username"):
        real_name = (identity.get("real_name") or {}).get("value")
        if scan_type == "name":
            real_name = data.get("query", "")
        for v in _name_variants(real_name or ""):
            raw.append((v, "name_variant"))

    seen, out = set(), []
    for handle, origin in raw:
        h = _clean(handle)
        if len(h) < 4 or h.isdigit() or h in seen:
            continue
        seen.add(h)
        out.append({"handle": h, "origin": origin})
    out.sort(key=lambda c: -_ORIGIN_WEIGHT[c["origin"]])
    return out[:MAX_CANDIDATES]


def score_hit(origin: str, profile_name: str, real_name: str | None) -> tuple[float, list[str]]:
    score = _ORIGIN_WEIGHT[origin]
    reasons = [f"handle source: {origin.replace('_', ' ')}"]
    if profile_name and real_name:
        ratio = difflib.SequenceMatcher(None, profile_name.lower(), real_name.lower()).ratio()
        if ratio >= 0.8:
            score += 0.35
            reasons.append(f"profile name matches known name ({ratio:.0%})")
        elif ratio < 0.4:
            score -= 0.20
            reasons.append(f"profile name '{profile_name}' does not match known name")
    return max(0.0, min(score, 0.95)), reasons


def _label(score: float) -> str:
    return "PROBABLE" if score >= 0.7 else "LINKED"


def _probe(cand: dict) -> list[dict]:
    res = run_maigret(cand["handle"], timeout=45, sites=SOCIAL_SITES)
    return [{**hit, "handle": cand["handle"], "origin": cand["origin"]} for hit in res.get("found", [])]


def find_social_profiles(scan_type: str, data: dict, identity: dict) -> list[dict]:
    cands = candidate_handles(scan_type, data, identity)
    if not cands:
        return []
    real_name = (identity.get("real_name") or {}).get("value")

    hits: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for result in pool.map(_probe, cands):
            hits.extend(result)

    out = []
    for h in hits:
        score, reasons = score_hit(h["origin"], h.get("name", ""), real_name)
        out.append({
            "platform":   h["site"],
            "url":        h["url"],
            "handle":     h["handle"],
            "profile_name": h.get("name", ""),
            "score":      round(score, 2),
            "confidence": _label(score),
            "reasons":    reasons,
            "note":       "Unverified — a matching handle does not prove identity. Confirm manually.",
        })
    out.sort(key=lambda x: -x["score"])
    return out
