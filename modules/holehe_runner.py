"""
modules/holehe_runner.py — run holehe as subprocess, parse output

Holehe checks 120+ sites to see if an email is registered
by using password-reset probes (doesn't log in, doesn't alert).
No API keys. Completely free.
"""

import subprocess
import re


def run_holehe(email: str, timeout: int = 60) -> dict:
    """
    Returns {
        found: [{site, url}],
        not_found: [str],
        errors: [str],
        summary: str,
        installed: bool
    }
    """
    try:
        result = subprocess.run(
            ["holehe", "--only-used", "--no-color", email],
            capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout + result.stderr
        return _parse(output, email)
    except FileNotFoundError:
        return {"found": [], "not_found": [], "errors": [], "summary": "Holehe not installed", "installed": False}
    except subprocess.TimeoutExpired:
        return {"found": [], "not_found": [], "errors": [], "summary": "Holehe timed out", "installed": True}
    except Exception as e:
        return {"found": [], "not_found": [], "errors": [str(e)], "summary": "Holehe error", "installed": True}


def _parse(output: str, email: str) -> dict:
    found = []
    not_found = []
    errors = []

    for line in output.splitlines():
        line = line.strip()
        # [+] Site (https://...)
        m = re.match(r"\[\+\]\s+(\S+)(?:\s+\((https?://[^\)]+)\))?", line)
        if m:
            site = m.group(1)
            url  = m.group(2) or f"https://{site.lower()}.com"
            found.append({"site": site, "url": url})
            continue
        # [-] Site — not registered
        m2 = re.match(r"\[\-\]\s+(\S+)", line)
        if m2:
            not_found.append(m2.group(1))
            continue
        # [x] errors
        m3 = re.match(r"\[x\]\s+(.+)", line)
        if m3:
            errors.append(m3.group(1))

    summary = f"Found on {len(found)} sites" if found else "Not found on any checked site"
    return {"found": found, "not_found": not_found, "errors": errors, "summary": summary, "installed": True}
