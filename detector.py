"""
detector.py — input type detection for GhostTrace v3

Detected types: email, phone, ip, url, domain, hash_md5, hash_sha1,
                hash_sha256, username, name, unknown

Supported by the scanner: email, phone, username, name, ip, domain
"""

import re

_PATTERNS = [
    ("email",       r"^[\w\.\+\-]+@[\w\.\-]+\.\w{2,}$"),
    ("phone",       r"^\+?[0-9\s\-\(\)]{7,20}$"),
    ("ip",          r"^(?:\d{1,3}\.){3}\d{1,3}$"),
    ("url",         r"^https?://"),
    ("domain",      r"^(?!https?://)([A-Za-z0-9\-]+\.)+[A-Za-z]{2,}$"),
    ("hash_md5",    r"^[a-fA-F0-9]{32}$"),
    ("hash_sha1",   r"^[a-fA-F0-9]{40}$"),
    ("hash_sha256", r"^[a-fA-F0-9]{64}$"),
    ("username",    r"^[A-Za-z0-9][A-Za-z0-9._\-]{1,29}$"),
]


def detect_input(text: str) -> str:
    text = text.strip()
    for kind, pattern in _PATTERNS:
        if re.match(pattern, text):
            return kind
    if " " in text and re.match(r"^[A-Za-z\s\.\-']+$", text):
        return "name"
    return "unknown"


SUPPORTED_TYPES = {"name", "email", "phone", "username", "ip", "domain"}
