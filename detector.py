import re


def detect_input(text: str):

    text = text.strip()

    patterns = {

        "email":
            r"^[\w\.-]+@[\w\.-]+\.\w+$",

        "phone":
            r"^\+?[0-9]{7,15}$",

        "ip":
            r"^(?:\d{1,3}\.){3}\d{1,3}$",

        "url":
            r"^https?:\/\/",

        "domain":
            r"^(?!https?:\/\/)([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$",

        "hash_md5":
            r"^[a-fA-F0-9]{32}$",

        "hash_sha1":
            r"^[a-fA-F0-9]{40}$",

        "hash_sha256":
            r"^[a-fA-F0-9]{64}$",

        "username":
            r"^[A-Za-z0-9._-]{3,30}$"
    }

    for kind, regex in patterns.items():

        if re.match(regex, text):
            return kind

    return "unknown"
