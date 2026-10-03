"""
modules/safe_http.py — SSRF-safe outbound HTTP.

Use safe_get() for any URL that originates from scraped or user-supplied data.
It refuses non-http(s) schemes, non-standard ports, and any host that resolves to a
private / loopback / link-local / reserved address, and it re-validates every
redirect hop instead of letting requests follow them blindly.
"""
from __future__ import annotations
import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests

MAX_REDIRECTS = 4
MAX_BYTES = 512 * 1024
_ALLOWED_PORTS = {None, 80, 443}


class UnsafeURL(ValueError):
    pass


def _host_is_public(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return False
    return True


def validate_url(url: str) -> str:
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise UnsafeURL("only http(s) URLs are allowed")
    if p.port not in _ALLOWED_PORTS:
        raise UnsafeURL("non-standard port blocked")
    if p.username or p.password:
        raise UnsafeURL("credentials in URL blocked")
    if not _host_is_public(p.hostname):
        raise UnsafeURL("host does not resolve to a public address")
    return url


def safe_get(url: str, timeout: int = 8, headers: dict | None = None):
    """GET with per-hop validation and a capped body. Returns a Response (body capped)."""
    headers = headers or {"User-Agent": "GhostTrace/3.1"}
    current = url
    chain = [url]
    for _ in range(MAX_REDIRECTS + 1):
        validate_url(current)
        r = requests.get(current, timeout=timeout, headers=headers,
                         allow_redirects=False, stream=True)
        if r.is_redirect or r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location")
            r.close()
            if not loc:
                raise UnsafeURL("redirect without Location")
            current = urljoin(current, loc)
            chain.append(current)
            continue
        body = b""
        for chunk in r.iter_content(8192):
            body += chunk
            if len(body) >= MAX_BYTES:
                break
        r._content = body
        r.close()
        r.chain = chain          # every URL visited, in order
        return r
    raise UnsafeURL("too many redirects")
