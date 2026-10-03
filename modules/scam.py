"""
modules/scam.py — scam-indicator risk engine (India-focused).

The unit of analysis is an INDICATOR (number, UPI ID, URL/domain, email), not a person.
Output is a verdict + the evidence behind it. Pure functions, no network: pass in any
enrichment already gathered (e.g. domain age from RDAP) via `context`.

assess(kind, query, context=None) -> {
    "verdict": "likely_scam" | "suspicious" | "no_strong_signals",
    "score": 0-100,
    "signals": [{"id", "weight", "detail"}],
    "disclaimer": str
}
"""
from __future__ import annotations
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

# ── Reference data ────────────────────────────────────────────────────────────
# brand -> legitimate registrable domains
INDIAN_BRANDS = {
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"],
    "hdfcbank": ["hdfcbank.com"], "icicibank": ["icicibank.com"],
    "axisbank": ["axisbank.com"], "kotak": ["kotak.com"], "pnb": ["pnbindia.in"],
    "paytm": ["paytm.com"], "phonepe": ["phonepe.com"], "gpay": ["pay.google.com"],
    "irctc": ["irctc.co.in"], "uidai": ["uidai.gov.in"], "aadhaar": ["uidai.gov.in"],
    "incometax": ["incometax.gov.in"], "epfo": ["epfindia.gov.in"],
    "indiapost": ["indiapost.gov.in"], "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"], "jio": ["jio.com"], "airtel": ["airtel.in"],
    "bsnl": ["bsnl.co.in"], "fedex": ["fedex.com"], "dhl": ["dhl.com"],
    "bluedart": ["bluedart.com"], "tcs": ["tcs.com"], "infosys": ["infosys.com"],
}

SUSPICIOUS_TLDS = {"xyz", "top", "click", "shop", "online", "site", "icu", "work",
                   "support", "live", "vip", "buzz", "rest", "cfd", "sbs", "monster"}

SCAM_KEYWORDS = ("kyc", "verify", "update", "refund", "reward", "lottery", "prize",
                 "claim", "free", "bonus", "winner", "cashback", "suspend", "blocked",
                 "urgent", "customer-care", "customercare", "helpline", "support",
                 "recharge", "offer", "gift", "login", "secure", "otp", "pan-update")

JOB_SCAM_WORDS = ("registration-fee", "work-from-home", "wfh", "earn", "daily-income",
                  "part-time", "task", "hiring", "offer-letter", "internship-fee")

# Real UPI PSP handles (not exhaustive; unknown != scam, just a weak signal)
KNOWN_UPI_HANDLES = {
    "oksbi", "okhdfcbank", "okicici", "okaxis", "ybl", "ibl", "axl", "paytm", "apl",
    "upi", "sbi", "hdfcbank", "icici", "axisbank", "kotak", "pnb", "boi", "cnrb",
    "idfcbank", "indus", "federal", "yesbank", "rbl", "aubank", "fbl", "sib",
    "postbank", "ikwik", "freecharge", "airtel", "jio", "slice", "jupiter",
}

DISPOSABLE_EMAIL = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
                    "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com",
                    "temp-mail.org", "dispostable.com", "maildrop.cc", "throwawaymail.com"}
FREE_EMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com", "proton.me"}

DISCLAIMER = ("Heuristic risk assessment from public indicators, not proof of fraud. "
              "Verify with the official source before acting; report suspected fraud at "
              "cybercrime.gov.in or call 1930.")


# ── helpers ───────────────────────────────────────────────────────────────────
def _sig(sid: str, weight: int, detail: str) -> dict:
    return {"id": sid, "weight": weight, "detail": detail}


def _lev(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _registrable(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "gov", "ac", "org", "net") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _verdict(score: int) -> str:
    if score >= 60:
        return "likely_scam"
    if score >= 30:
        return "suspicious"
    return "no_strong_signals"


def _finish(signals: list[dict]) -> dict:
    # diminishing returns so many weak signals can't equal one strong one
    score = 0
    for w in sorted((s["weight"] for s in signals), reverse=True):
        score += w if score < 60 else w * 0.5
    score = int(min(100, round(score)))
    return {"verdict": _verdict(score), "score": score,
            "signals": sorted(signals, key=lambda s: -s["weight"]),
            "disclaimer": DISCLAIMER}


# ── per-type assessors ────────────────────────────────────────────────────────
def assess_domain(host: str, url: str | None = None, context: dict | None = None) -> list[dict]:
    ctx = context or {}
    s: list[dict] = []
    host = host.lower().strip(".")
    # Live feed hits override the "genuine brand" shortcut and are the strongest evidence
    for hit in ctx.get("feed_hits", []):
        s.append(_sig("feed_" + hit["source"].lower().replace(" ", "_"), 85,
                      f"{hit['source']}: {hit['detail']}"))
    reg = _registrable(host)
    label = reg.split(".")[0]
    tld = reg.split(".")[-1]

    # brand impersonation
    deleet = host.translate(_LEET)
    for brand, legit in INDIAN_BRANDS.items():
        if reg in legit or any(host.endswith("." + l) for l in legit):
            return s  # genuine brand domain: heuristics skipped (feed hits, if any, still count)
    tokens = set(re.split(r"[.\-_]", deleet))
    flat = deleet.replace("-", "").replace(".", "")
    for brand in INDIAN_BRANDS:
        # short brands (sbi, jio, tcs…) must match a whole token to avoid false positives
        if (brand in flat) if len(brand) >= 5 else (brand in tokens):
            s.append(_sig("brand_in_domain", 40,
                          f"Contains brand '{brand}' but is not an official {brand} domain"))
            break
    else:
        for brand in INDIAN_BRANDS:
            if len(brand) >= 4 and 0 < _lev(label.translate(_LEET), brand) <= 1:
                s.append(_sig("typosquat", 45, f"Looks like a typo of '{brand}'"))
                break

    if host.startswith("xn--") or ".xn--" in host:
        s.append(_sig("punycode", 35, "Punycode (possible look-alike characters)"))
    if tld in SUSPICIOUS_TLDS:
        s.append(_sig("risky_tld", 15, f".{tld} is heavily abused for throwaway scam sites"))
    if label.count("-") >= 2:
        s.append(_sig("hyphen_heavy", 10, "Multiple hyphens in the domain name"))
    if host.count(".") >= 4:
        s.append(_sig("deep_subdomain", 10, "Unusually deep subdomain nesting"))
    if re.search(r"\d{4,}", label):
        s.append(_sig("digit_run", 8, "Long run of digits in the name"))

    path = (urlparse(url).path + "?" + (urlparse(url).query or "")).lower() if url else ""
    hits = [k for k in SCAM_KEYWORDS if k in host or k in path]
    if hits:
        s.append(_sig("scam_keywords", min(30, 8 * len(hits)),
                      "Pressure/credential keywords: " + ", ".join(hits[:5])))
    jobs = [k for k in JOB_SCAM_WORDS if k in host or k in path]
    if jobs:
        s.append(_sig("job_scam_terms", 20, "Fake job/internship-style terms: " + ", ".join(jobs[:4])))
    if url and url.lower().startswith("http://"):
        s.append(_sig("no_https", 8, "Page served without HTTPS"))
    if url and re.search(r"https?://[^/]*@", url):
        s.append(_sig("userinfo_trick", 30, "Credentials-style '@' used to disguise the real host"))

    # DEEP-mode page analysis (only present when the caller ran it)
    if ctx.get("page"):
        s.extend(assess_page(ctx["page"], reg))
    fs = ctx.get("first_seen")          # earliest Wayback snapshot, ISO date
    if ctx.get("page") is not None and "first_seen" in ctx:
        if not fs:
            s.append(_sig("never_archived", 8, "No history in the Wayback Machine (brand-new or obscure site)"))
        else:
            try:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(fs).replace(tzinfo=timezone.utc)).days
                if age < 90:
                    s.append(_sig("recently_first_seen", 15, f"First archived only {age} days ago"))
            except ValueError:
                pass

    # enrichment-driven signals (only if caller supplied them)
    created = ctx.get("domain_created")  # ISO date string
    if created:
        try:
            dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - dt).days
            if age < 30:
                s.append(_sig("new_domain", 35, f"Registered only {max(age, 0)} days ago"))
            elif age < 180:
                s.append(_sig("young_domain", 15, f"Registered {age} days ago"))
        except ValueError:
            pass
    if ctx.get("has_rdap") is False:
        s.append(_sig("no_whois", 8, "No public registration data found"))
    return s


def assess_page(page: dict, reg_domain: str) -> list[dict]:
    """Signals from the fetched page (DEEP mode)."""
    s: list[dict] = []
    if page.get("error"):
        return s
    asks = sorted({a for f in page.get("forms", []) for a in f.get("asks_for", [])})
    risky = [a for a in asks if a in ("OTP", "PIN", "CVV", "card number", "Aadhaar", "PAN",
                                       "UPI details", "card expiry", "net-banking login")]
    if risky:
        s.append(_sig("collects_sensitive", 35, "Page asks for: " + ", ".join(risky)))
    elif "password" in asks:
        s.append(_sig("login_form", 12, "Page has a login form"))
    foreign = {f["action_host"] for f in page.get("forms", [])
               if f.get("asks_for") and f.get("action_host") and _registrable(f["action_host"]) != reg_domain}
    if foreign:
        s.append(_sig("form_posts_elsewhere", 30,
                      "Form sends entered data to a different site: " + ", ".join(sorted(foreign)[:3])))
    brands = page.get("brand_mentions") or []
    if brands:
        s.append(_sig("page_impersonates_brand", 40,
                      "Page presents itself as " + ", ".join(brands[:3]) + " but is not that brand's domain"))
    if page.get("cross_domain_redirect"):
        s.append(_sig("redirects_away", 15, "Link redirects to a different site: " + page.get("final_url", "")[:80]))
    if page.get("hidden_iframes"):
        s.append(_sig("hidden_iframe", 15, f"{page['hidden_iframes']} hidden iframe(s)"))
    if page.get("meta_refresh"):
        s.append(_sig("meta_refresh", 8, "Page auto-redirects via meta refresh"))
    if len(page.get("urgent_phrases", [])) >= 2:
        s.append(_sig("urgency_language", 15, "Pressure language: " + ", ".join(page["urgent_phrases"][:3])))
    if page.get("contact_links"):
        s.append(_sig("chat_contact", 10, "Pushes you to WhatsApp/Telegram: " + ", ".join(page["contact_links"])))
    return s


def assess_upi(vpa: str) -> list[dict]:
    s: list[dict] = []
    local, _, handle = vpa.lower().partition("@")
    if handle not in KNOWN_UPI_HANDLES:
        s.append(_sig("unknown_psp", 25, f"'@{handle}' is not a recognised UPI handle"))
    hits = [k for k in ("refund", "kyc", "support", "care", "reward", "lottery", "prize",
                        "claim", "cashback", "helpdesk", "customer", "verify", "official")
            if k in local]
    if hits:
        s.append(_sig("upi_keywords", 30, "Handle name uses scam-style words: " + ", ".join(hits)))
    for brand in INDIAN_BRANDS:
        if brand in local.translate(_LEET):
            s.append(_sig("upi_brand", 25, f"Handle name impersonates '{brand}'"))
            break
    if re.fullmatch(r"\d{10}", local) is None and re.search(r"\d{6,}", local):
        s.append(_sig("upi_digit_run", 10, "Long digit run (auto-generated look)"))
    return s


def assess_phone(number: str) -> list[dict]:
    s: list[dict] = []
    digits = re.sub(r"\D", "", number)
    national = digits[2:] if digits.startswith("91") and len(digits) == 12 else digits
    if digits.startswith("91") and len(digits) == 12 or len(digits) == 10:
        if national[0] not in "6789":
            s.append(_sig("invalid_in_mobile", 30, "Not a valid Indian mobile prefix (must start 6–9)"))
        if re.search(r"(\d)\1{5,}", national):
            s.append(_sig("repeating_digits", 15, "Long run of repeated digits (vanity/burner pattern)"))
        if national in "01234567890123456789" or national in "98765432109876543210":
            s.append(_sig("sequential", 20, "Sequential digits"))
    elif not number.startswith("+"):
        s.append(_sig("odd_length", 10, "Unusual number length / missing country code"))
    if number.startswith("+") and not digits.startswith("91"):
        s.append(_sig("foreign_caller", 12,
                      "International number; common in 'job offer' and 'courier' scam calls to India"))
    if digits.startswith("140") or digits.startswith("1409"):
        s.append(_sig("telemarketing_series", 6, "140-series telemarketing range"))
    return s


def assess_email(email: str, context: dict | None = None) -> list[dict]:
    ctx = context or {}
    s: list[dict] = []
    local, _, dom = email.lower().partition("@")
    if dom in DISPOSABLE_EMAIL:
        s.append(_sig("disposable_email", 40, "Disposable/temporary email provider"))
    if dom in FREE_EMAIL:
        for brand in INDIAN_BRANDS:
            if brand in local.translate(_LEET):
                s.append(_sig("brand_on_free_mail", 35,
                              f"'{brand}' used in a free-mail address (real companies use their own domain)"))
                break
        if any(k in local for k in ("hr", "recruit", "career", "hiring", "support", "care", "kyc", "refund")):
            s.append(_sig("official_sounding_free_mail", 20,
                          "Official-sounding role on a free mail provider"))
    if dom not in FREE_EMAIL and dom not in DISPOSABLE_EMAIL:
        s.extend(assess_domain(dom, context=ctx.get("domain_context")))
    return s


def assess_community(rep: dict | None, web: dict | None) -> list[dict]:
    """Signals from user reports and web mentions (any indicator type)."""
    s: list[dict] = []
    n = (rep or {}).get("count", 0)
    if n:
        w = 10 if n == 1 else 25 if n == 2 else 45 if n < 5 else 65 if n < 10 else 85
        top = max(rep["categories"], key=rep["categories"].get).replace("_", " ")
        s.append(_sig("community_reports", w,
                      f"{n} independent user report(s) in the last 6 months, mostly '{top}' (unverified)"))
    h = (web or {}).get("hits", 0)
    if h:
        s.append(_sig("web_scam_mentions", min(15 + 10 * h, 45),
                      f"{h} web result(s) mention this together with scam/fraud wording"))
    return s


# ── public entry ──────────────────────────────────────────────────────────────
def assess(kind: str, query: str, context: dict | None = None) -> dict:
    q = query.strip()
    if kind == "domain":
        host = (urlparse(q).hostname if "://" in q else q.split("/")[0]).lower()
        sigs = assess_domain(host, url=q if "://" in q else None, context=context)
    elif kind == "url":
        sigs = assess_domain(urlparse(q).hostname or "", url=q, context=context)
    elif kind == "upi":
        sigs = assess_upi(q)
    elif kind == "phone":
        sigs = assess_phone(q)
    elif kind == "email":
        sigs = assess_email(q, context)
    else:
        return {"verdict": "not_applicable", "score": 0, "signals": [], "disclaimer": DISCLAIMER}
    ctx = context or {}
    return _finish(sigs + assess_community(ctx.get("reports"), ctx.get("web")))
