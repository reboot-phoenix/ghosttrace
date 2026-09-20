import re

# Patterns are checked in order — put more specific ones first.
# Email must come before username since a valid email also matches the
# username pattern.
_PATTERNS = [
    ("email",      r"^[\w\.-]+@[\w\.-]+\.\w+$"),
    ("phone",      r"^\+?[0-9]{7,15}$"),
    ("ip",         r"^(?:\d{1,3}\.){3}\d{1,3}$"),
    ("url",        r"^https?:\/\/"),
    ("domain",     r"^(?!https?:\/\/)([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$"),
    ("hash_md5",   r"^[a-fA-F0-9]{32}$"),
    ("hash_sha1",  r"^[a-fA-F0-9]{40}$"),
    ("hash_sha256",r"^[a-fA-F0-9]{64}$"),
    ("username",   r"^[A-Za-z0-9._-]{3,30}$"),
]


def detect_input(text: str) -> str:
    """
    Returns the best-guess type for the given input string.
    Possible values: email, phone, ip, url, domain, hash_md5,
    hash_sha1, hash_sha256, username, name, unknown.

    Note: only email, phone, username, and name are handled by the
    scanner. Everything else is detected here for informational
    purposes but will be rejected at the /scan endpoint.
    """
    text = text.strip()

    for kind, pattern in _PATTERNS:
        if re.match(pattern, text):
            return kind

    # Multi-word input with no special chars → likely a name
    if " " in text and re.match(r"^[A-Za-z\s\.\-']+$", text):
        return "name"

    return "unknown"
