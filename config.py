import os

# ── Search ──────────────────────────────────────────────────
# SerpAPI (paid, optional). If absent, falls back to DuckDuckGo (free).
SERPAPI_KEY = os.environ.get("SERPAPI_KEY", "").strip()

# ── Breach checking ─────────────────────────────────────────
# Priority order:
#   1. HIBP paid key  →  full breach-account lookup (best, $3.50/mo)
#   2. LeakCheck key  →  free tier 50 req/day, paid tiers available
#   3. No key         →  HIBP k-anonymity on the SHA-1 of the email
#                        (checks if the email itself was used as a password —
#                         surprisingly common, zero cost, no key needed)
HIBP_API_KEY    = os.environ.get("HIBP_API_KEY", "").strip()
LEAKCHECK_KEY   = os.environ.get("LEAKCHECK_KEY", "").strip()

# ── Social domain map ────────────────────────────────────────
SOCIAL_DOMAINS = {
    "linkedin.com":   "LinkedIn",
    "facebook.com":   "Facebook",
    "instagram.com":  "Instagram",
    "twitter.com":    "X (Twitter)",
    "x.com":          "X (Twitter)",
    "github.com":     "GitHub",
    "youtube.com":    "YouTube",
    "tiktok.com":     "TikTok",
    "reddit.com":     "Reddit",
    "pinterest.com":  "Pinterest",
    "medium.com":     "Medium",
    "quora.com":      "Quora",
    "threads.net":    "Threads",
    "snapchat.com":   "Snapchat",
    "telegram.me":    "Telegram",
    "t.me":           "Telegram",
    "discord.com":    "Discord",
    "twitch.tv":      "Twitch",
}
