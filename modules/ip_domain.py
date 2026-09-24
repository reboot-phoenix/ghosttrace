"""
modules/ip_domain.py — IP & domain OSINT for GhostTrace v3

All 100% free, zero API keys:
  - ip-api.com        → geolocation, ASN, ISP, timezone (free, 45 req/min)
  - Shodan InternetDB → open ports, CVEs, CPEs, hostnames, tags (no key!)
  - RDAP              → modern WHOIS replacement, returns JSON (no key)
  - crt.sh            → SSL certificate transparency → all subdomains
  - Cloudflare DoH    → DNS A/AAAA/MX/TXT/NS records (free, unlimited)
  - ip-api.com        → abuse contact, mobile detection

NEW in v3: domain input also resolves to IP first, then enriches both.
"""

import re
import socket
import requests
import json

_T = 8


def _get(url: str, params: dict = None) -> dict | None:
    try:
        r = requests.get(url, params=params, timeout=_T, headers={"User-Agent": "GhostTrace-v3"})
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


# ── IP geolocation via ip-api.com ─────────────────────────────────────────────
def _ipapi(ip: str) -> dict:
    data = _get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query")
    if data and data.get("status") == "success":
        return {
            "ip": data.get("query", ip),
            "country": data.get("country", ""),
            "country_code": data.get("countryCode", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "zip": data.get("zip", ""),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone", ""),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "asn": data.get("as", ""),
            "asname": data.get("asname", ""),
            "reverse_dns": data.get("reverse", ""),
            "mobile": data.get("mobile", False),
            "proxy": data.get("proxy", False),
            "hosting": data.get("hosting", False),
        }
    return {}


# ── Shodan InternetDB (completely free, no key) ───────────────────────────────
def _internetdb(ip: str) -> dict:
    data = _get(f"https://internetdb.shodan.io/{ip}")
    if data:
        return {
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "cpes": data.get("cpes", []),
            "vulns": data.get("vulns", []),
            "tags": data.get("tags", []),
        }
    return {}


# ── crt.sh certificate transparency → subdomains ─────────────────────────────
def _crtsh(domain: str) -> list[str]:
    try:
        r = requests.get(
            f"https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=15,
            headers={"User-Agent": "GhostTrace-v3"}
        )
        if r.status_code != 200:
            return []
        items = r.json()
        subs = set()
        for item in items:
            name = item.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if domain in sub and sub not in subs:
                    subs.add(sub)
        return sorted(subs)[:50]  # cap at 50
    except Exception:
        return []


# ── DNS via Cloudflare DoH (free, unlimited) ──────────────────────────────────
def _dns(domain: str) -> dict:
    record_types = {"A": 1, "AAAA": 28, "MX": 15, "TXT": 16, "NS": 2}
    results = {}
    for rtype, rcode in record_types.items():
        try:
            r = requests.get(
                "https://cloudflare-dns.com/dns-query",
                params={"name": domain, "type": rtype},
                headers={"Accept": "application/dns-json"},
                timeout=5,
            )
            if r.status_code == 200:
                answers = r.json().get("Answer", [])
                results[rtype] = [a.get("data", "") for a in answers if a.get("type") == rcode]
        except Exception:
            results[rtype] = []
    return results


# ── RDAP (modern WHOIS) ───────────────────────────────────────────────────────
def _rdap_domain(domain: str) -> dict:
    data = _get(f"https://rdap.org/domain/{domain}")
    if not data:
        return {}
    events = {e.get("eventAction"): e.get("eventDate", "")[:10]
              for e in data.get("events", [])}
    entities = data.get("entities", [])
    registrar = ""
    for ent in entities:
        for role in ent.get("roles", []):
            if role == "registrar":
                registrar = ent.get("vcardArray", [None, []])[1]
                if isinstance(registrar, list):
                    for field in registrar:
                        if field[0] == "fn":
                            registrar = field[3]
                            break
                break
    return {
        "name": data.get("ldhName", domain),
        "status": data.get("status", []),
        "registrar": registrar if isinstance(registrar, str) else "",
        "registered": events.get("registration", ""),
        "updated": events.get("last changed", ""),
        "expiry": events.get("expiration", ""),
        "nameservers": [ns.get("ldhName", "") for ns in data.get("nameservers", [])],
    }


def _rdap_ip(ip: str) -> dict:
    data = _get(f"https://rdap.org/ip/{ip}")
    if not data:
        return {}
    return {
        "name": data.get("name", ""),
        "type": data.get("type", ""),
        "country": data.get("country", ""),
        "cidr": str((data.get("cidr0_cidrs") or [{}])[0].get("v4prefix", "")),
        "start_address": data.get("startAddress", ""),
        "end_address": data.get("endAddress", ""),
    }


# ── Resolve domain to IP ──────────────────────────────────────────────────────
def _resolve(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


# ── Main scanners ─────────────────────────────────────────────────────────────

def scan_ip(ip: str) -> dict:
    geo      = _ipapi(ip)
    shodan   = _internetdb(ip)
    rdap     = _rdap_ip(ip)

    score = 0
    if geo:                          score += 20
    if shodan.get("ports"):          score += min(len(shodan["ports"]) * 5, 30)
    if shodan.get("vulns"):          score += min(len(shodan["vulns"]) * 10, 30)
    if geo.get("proxy"):             score += 10
    if geo.get("hosting"):           score += 5
    score = min(score, 100)

    chips = []
    if geo:
        chips.append({"label": f"📍 {geo.get('city')}, {geo.get('country')}", "color": "blue"})
        chips.append({"label": f"🏢 {geo.get('isp')}", "color": "gray"})
    if shodan.get("ports"):
        chips.append({"label": f"{len(shodan['ports'])} open ports", "color": "orange"})
    if shodan.get("vulns"):
        chips.append({"label": f"⚠️ {len(shodan['vulns'])} CVEs found", "color": "red"})
    if geo.get("proxy"):
        chips.append({"label": "VPN / Proxy detected", "color": "red"})
    if geo.get("hosting"):
        chips.append({"label": "Hosting / Datacenter IP", "color": "purple"})
    if geo.get("mobile"):
        chips.append({"label": "Mobile carrier", "color": "green"})

    deep_links = [
        {"label": "Shodan full search",    "url": f"https://www.shodan.io/host/{ip}"},
        {"label": "VirusTotal",            "url": f"https://www.virustotal.com/gui/ip-address/{ip}"},
        {"label": "AbuseIPDB",             "url": f"https://www.abuseipdb.com/check/{ip}"},
        {"label": "GreyNoise",             "url": f"https://viz.greynoise.io/ip/{ip}"},
        {"label": "IPInfo",                "url": f"https://ipinfo.io/{ip}"},
        {"label": "Censys",                "url": f"https://search.censys.io/hosts/{ip}"},
        {"label": "BGP.he.net",            "url": f"https://bgp.he.net/ip/{ip}"},
    ]

    return {
        "type": "ip",
        "query": ip,
        "score": score,
        "chips": chips,
        "geo": geo,
        "shodan": shodan,
        "rdap": rdap,
        "deep_links": deep_links,
    }


def scan_domain(domain: str) -> dict:
    # Strip protocol
    domain = re.sub(r"^https?://", "", domain).split("/")[0].strip()

    resolved_ip = _resolve(domain)
    dns     = _dns(domain)
    rdap    = _rdap_domain(domain)
    subdomains = _crtsh(domain)
    geo     = _ipapi(resolved_ip) if resolved_ip else {}
    shodan  = _internetdb(resolved_ip) if resolved_ip else {}

    score = 0
    if rdap:                score += 20
    if dns.get("A"):        score += 10
    if dns.get("MX"):       score += 10
    if subdomains:          score += min(len(subdomains) * 2, 20)
    if shodan.get("ports"): score += min(len(shodan["ports"]) * 5, 25)
    if shodan.get("vulns"): score += min(len(shodan["vulns"]) * 5, 15)
    score = min(score, 100)

    chips = []
    if rdap.get("registrar"):  chips.append({"label": f"Registrar: {rdap['registrar']}", "color": "blue"})
    if rdap.get("registered"): chips.append({"label": f"Registered: {rdap['registered']}", "color": "gray"})
    if rdap.get("expiry"):     chips.append({"label": f"Expires: {rdap['expiry']}", "color": "gray"})
    if subdomains:             chips.append({"label": f"{len(subdomains)} subdomains found", "color": "orange"})
    if shodan.get("ports"):    chips.append({"label": f"{len(shodan['ports'])} open ports", "color": "orange"})
    if shodan.get("vulns"):    chips.append({"label": f"⚠️ {len(shodan['vulns'])} CVEs", "color": "red"})
    if resolved_ip:            chips.append({"label": f"IP: {resolved_ip}", "color": "gray"})

    deep_links = [
        {"label": "Shodan domain search",  "url": f"https://www.shodan.io/search?query=hostname%3A{domain}"},
        {"label": "VirusTotal",            "url": f"https://www.virustotal.com/gui/domain/{domain}"},
        {"label": "SecurityTrails",        "url": f"https://securitytrails.com/domain/{domain}/dns"},
        {"label": "DNSDumpster",           "url": f"https://dnsdumpster.com/"},
        {"label": "crt.sh (certificates)", "url": f"https://crt.sh/?q={domain}"},
        {"label": "Wayback Machine",       "url": f"https://web.archive.org/web/*/{domain}"},
        {"label": "URLScan",               "url": f"https://urlscan.io/search/#domain:{domain}"},
        {"label": "Google Transparency",   "url": f"https://transparencyreport.google.com/safe-browsing/search?url={domain}"},
    ]

    return {
        "type": "domain",
        "query": domain,
        "resolved_ip": resolved_ip,
        "score": score,
        "chips": chips,
        "dns": dns,
        "rdap": rdap,
        "subdomains": subdomains,
        "geo": geo,
        "shodan": shodan,
        "deep_links": deep_links,
    }
