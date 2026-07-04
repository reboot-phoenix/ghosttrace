import os

# ── Search ──────────────────────────────────────────────────
# SerpAPI (100 free searches/month — use sparingly)
SERPAPI_KEY = os.environ.get("SERPAPI_KEY", "").strip()

# Google Custom Search Engine (100 free queries/day — primary free fallback)
# Setup: https://programmablesearchengine.google.com → create engine (search entire web)
# Then enable "Custom Search API" in Google Cloud Console and grab an API key.
GOOGLE_CSE_KEY = os.environ.get("GOOGLE_CSE_KEY", "").strip()
GOOGLE_CSE_ID  = os.environ.get("GOOGLE_CSE_ID", "").strip()

# ── Breach checking ─────────────────────────────────────────
# Priority: HIBP paid ($3.50/mo) → LeakCheck free (50 req/day) → HIBP k-anon (free, no key)
HIBP_API_KEY  = os.environ.get("HIBP_API_KEY", "").strip()
LEAKCHECK_KEY = os.environ.get("LEAKCHECK_KEY", "").strip()

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
    "dev.to":         "Dev.to",
    "hashnode.com":   "Hashnode",
    "stackoverflow.com": "Stack Overflow",
    "keybase.io":     "Keybase",
    "pastebin.com":   "Pastebin",
    "replit.com":     "Replit",
    "kaggle.com":     "Kaggle",
    "hackerrank.com": "HackerRank",
    "leetcode.com":   "LeetCode",
    "behance.net":    "Behance",
    "dribbble.com":   "Dribbble",
    "producthunt.com":"Product Hunt",
    "about.me":       "About.me",
    "linktree.com":   "Linktree",
    "linktr.ee":      "Linktree",
    "steam":          "Steam",
    "steamcommunity.com": "Steam",
    "mastodon.social":"Mastodon",
    "substack.com":   "Substack",
    "notion.so":      "Notion",
}
