import os

SERPAPI_KEY = os.environ.get("SERPAPI_KEY", "").strip()

# Domains we treat as "real profile" hits when they show up in search results.
SOCIAL_DOMAINS = {
    "linkedin.com": "LinkedIn",
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "twitter.com": "X (Twitter)",
    "x.com": "X (Twitter)",
    "github.com": "GitHub",
    "youtube.com": "YouTube",
    "tiktok.com": "TikTok",
    "reddit.com": "Reddit",
    "pinterest.com": "Pinterest",
    "medium.com": "Medium",
    "quora.com": "Quora",
    "threads.net": "Threads",
}
