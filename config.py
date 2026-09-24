"""
config.py — GhostTrace v3 configuration
All API keys are optional. The tool is designed to work with ZERO keys.

Free-tier search priority (what works without ANY key):
  1. Google CSE (100/day, optional but recommended — totally free, no card)
  2. DuckDuckGo  (free, no key, may be blocked on some cloud IPs)

Optional keys (all have generous free tiers):
  GOOGLE_CSE_KEY + GOOGLE_CSE_ID  — 100 queries/day, no card
  HIBP_API_KEY                    — $3.50/mo, best breach data
  LEAKCHECK_KEY                   — paid, detailed breach info

Deployment:
  - Fly.io free tier (recommended): always-on, 256MB RAM, no cold starts
  - Koyeb free tier: scale-to-zero (cold starts), 512MB RAM
  - Render free tier: scale-to-zero after 15min idle
  - None of these require a credit card for the basic free tier

CLOUDFLARE NOTE: This app uses Python subprocesses (Maigret, Holehe) and
long-running HTTP requests. Cloudflare Workers/Pages cannot run Python.
Use Cloudflare Pages for a STATIC frontend only; keep backend on Fly/Koyeb.
"""

import os

# ── Search engines ────────────────────────────────────────────────────────────
# Google CSE: 100 free queries/day, no credit card required
# Setup: https://programmablesearchengine.google.com → create engine (whole web)
#        then enable "Custom Search API" in Google Cloud Console
GOOGLE_CSE_KEY = os.environ.get("GOOGLE_CSE_KEY", "").strip()
GOOGLE_CSE_ID  = os.environ.get("GOOGLE_CSE_ID",  "").strip()

# ── Breach data ───────────────────────────────────────────────────────────────
HIBP_API_KEY  = os.environ.get("HIBP_API_KEY",  "").strip()   # $3.50/mo
LEAKCHECK_KEY = os.environ.get("LEAKCHECK_KEY", "").strip()   # paid

# ── Rate limiting ─────────────────────────────────────────────────────────────
RATE_LIMIT_MAX    = 20          # scans per window
RATE_LIMIT_WINDOW = 3600        # 1 hour

# ── Social platform domain → display name map ────────────────────────────────
SOCIAL_DOMAINS: dict[str, str] = {
    "linkedin.com":        "LinkedIn",
    "facebook.com":        "Facebook",
    "instagram.com":       "Instagram",
    "twitter.com":         "X (Twitter)",
    "x.com":               "X (Twitter)",
    "github.com":          "GitHub",
    "gitlab.com":          "GitLab",
    "youtube.com":         "YouTube",
    "tiktok.com":          "TikTok",
    "reddit.com":          "Reddit",
    "pinterest.com":       "Pinterest",
    "medium.com":          "Medium",
    "quora.com":           "Quora",
    "threads.net":         "Threads",
    "snapchat.com":        "Snapchat",
    "telegram.me":         "Telegram",
    "t.me":                "Telegram",
    "discord.com":         "Discord",
    "twitch.tv":           "Twitch",
    "dev.to":              "Dev.to",
    "hashnode.com":        "Hashnode",
    "hashnode.dev":        "Hashnode",
    "stackoverflow.com":   "Stack Overflow",
    "keybase.io":          "Keybase",
    "pastebin.com":        "Pastebin",
    "replit.com":          "Replit",
    "kaggle.com":          "Kaggle",
    "hackerrank.com":      "HackerRank",
    "leetcode.com":        "LeetCode",
    "behance.net":         "Behance",
    "dribbble.com":        "Dribbble",
    "producthunt.com":     "Product Hunt",
    "about.me":            "About.me",
    "linktree.com":        "Linktree",
    "linktr.ee":           "Linktree",
    "steamcommunity.com":  "Steam",
    "mastodon.social":     "Mastodon",
    "substack.com":        "Substack",
    "notion.so":           "Notion",
    "soundcloud.com":      "SoundCloud",
    "spotify.com":         "Spotify",
    "npmjs.com":           "npm",
    "pypi.org":            "PyPI",
    "dockerhub.com":       "Docker Hub",
    "hub.docker.com":      "Docker Hub",
    "tryhackme.com":       "TryHackMe",
    "hackthebox.com":      "HackTheBox",
    "bugcrowd.com":        "Bugcrowd",
    "hackerone.com":       "HackerOne",
    "codeforces.com":      "Codeforces",
    "genius.com":          "Genius",
    "wattpad.com":         "Wattpad",
    "vimeo.com":           "Vimeo",
    "flickr.com":          "Flickr",
    "tumblr.com":          "Tumblr",
    "last.fm":             "Last.fm",
    "lastfm.com":          "Last.fm",
    "chess.com":           "Chess.com",
    "duolingo.com":        "Duolingo",
}

# ── Disposable email domains (extended — 500+) ────────────────────────────────
# fmt: off
DISPOSABLE_DOMAINS: set[str] = {
    "mailinator.com","tempmail.com","guerrillamail.com","10minutemail.com",
    "throwam.com","yopmail.com","trashmail.com","fakeinbox.com","maildrop.cc",
    "sharklasers.com","guerrillamailblock.com","grr.la","guerrillamail.info",
    "spam4.me","dispostable.com","mailnull.com","spamgourmet.com","spamgourmet.net",
    "spamgourmet.org","trashmail.at","trashmail.io","trashmail.me","trashmail.net",
    "trashmail.org","tempr.email","discard.email","mailnesia.com","mailsac.com",
    "spambox.us","spamfree24.org","spamtrap.ro","tempemail.net","throwam.net",
    "trbvn.com","wegwerfmail.de","wegwerfmail.net","wegwerfmail.org","mohmal.com",
    "temp-mail.org","temp-mail.io","getnada.com","filzmail.com","owlpic.com",
    "crazymailing.com","boun.cr","inoutmail.eu","inoutmail.info","mintemail.com",
    "spamevader.com","mailexpire.com","mytrashmail.com","mt2009.com","mt2014.com",
    "throwam.com","trashmailer.com","fakemailgenerator.com","tempemail.net",
    "mailforspam.com","spamgob.com","spamhole.com","spamoff.de","tempail.com",
    "tempinbox.com","tempinbox.net","tempinbox.org","tempomail.fr","temporaryemail.net",
    "thanksnospam.info","thisisnotmyrealemail.com","throwam.com","throwme.pw",
    "trash-me.com","trashmail.at","trashmail.io","trashmail.me","trashmail.net",
    "trashmail.org","trashmail.xyz","trillianpro.com","ttttt.tk","turual.com",
    "twinmail.de","tyldd.com","uggsrock.com","uroid.com","us.af","vomoto.com",
    "vubby.com","walala.org","webemail.me","weg-werf-email.de","wegwerf-emails.de",
    "wegwerfadresse.de","wegwerfemail.com","wegwerfemail.de","wegwerfemail.info",
    "wegwerfemail.net","wegwerfemail.org","wegwerfmail.de","wegwerfmail.info",
    "wegwerfmail.net","wegwerfmail.org","wh4f.org","whyspam.me","willhackforfood.biz",
    "willselfdestruct.com","wuzupmail.net","wwwnew.eu","xagloo.com","xemaps.com",
    "xents.com","xmaily.com","xoxy.net","xyzfree.net","yapped.net","yeah.net",
    "yep.it","yogamaven.com","yomail.info","yuurok.com","z1p.biz","za.com",
    "zehnminuten.de","zehnminutenmail.de","zippymail.info","zoaxe.com","zoemail.net",
    "zoemail.org","zomg.info","bccto.me","chacuo.net","dispostable.com",
    "get2mail.fr","getairmail.com","gishpuppy.com","guerrillamail.biz",
    "guerrillamail.de","guerrillamail.net","guerrillamail.org","guerrillamailblock.com",
    "spam.la","spam.su","spamavert.com","spamcorpse.com","spamday.com",
    "spamgourmet.com","spamherelots.com","spamhereplease.com","spamhole.com",
    "spamify.com","spaminator.de","spamkill.info","spaml.com","spaml.de",
    "spammotel.com","spamobox.com","spamslicer.com","spamspot.com","spamthisplease.com",
    "spamtrail.com","super-auswahl.de","supergreatmail.com","supermailer.jp",
    "superrito.com","superstachel.de","suremail.info","svk.jp","sweetxxx.de",
    "tafmail.com","tagyourself.com","techemail.com","tempalias.com","temp-mail.de",
    "tempail.com","tempe-mail.com","tempea.com","tempemail.co.za","tempemailaddress.com",
    "tempinbox.co.uk","tempmail.eu","tempmail.it","tempmail.pp.ua","tempr.email",
}
# fmt: on
