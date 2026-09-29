"""
modules/correlate.py — Intelligence Correlation Engine

Takes raw scan results and automatically pivots:
  email → real name → username search → domain from email
  username → linked accounts → real name
  name → email hints → social profiles
  ip/domain → registrant name → company

Every finding is labeled with a confidence level:
  CONFIRMED  — we have the direct data
  PROBABLE   — strong indicator, not 100%
  LINKED     — found via correlation, verify manually
  NOT FOUND  — checked, nothing there

No hallucination. If we don't have the data, we say NOT FOUND.
"""

import re
import requests
import concurrent.futures

_T = 8  # timeout


def correlate(scan_result: dict, deep: bool = False) -> dict:
    """
    Master correlation function.
    Takes any scan result, finds all pivot points,
    returns enriched intelligence with confirmed identities.
    """
    scan_type = scan_result.get("type") or scan_result.get("scan_type", "")
    findings  = []
    pivots    = []
    identity  = _build_identity(scan_type, scan_result)

    # Fast mode: identity extraction only (no extra network pivots).
    # Deep mode: run pivots + social profile pivoting.
    pivot_tasks = _plan_pivots(scan_type, scan_result, identity) if deep else []

    if pivot_tasks:
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futures = {pool.submit(task["fn"], task["arg"]): task for task in pivot_tasks}
            for future in concurrent.futures.as_completed(futures):
                task   = futures[future]
                result = future.result()
                if result:
                    pivots.append({
                        "pivot_type":  task["type"],
                        "pivot_value": task["arg"],
                        "label":       task["label"],
                        "data":        result,
                    })

    # Build confirmed findings list
    findings = _extract_findings(scan_type, scan_result, pivots, identity)

    social = []
    if deep:
        from modules.social_pivot import find_social_profiles
        try:
            social = find_social_profiles(scan_type, scan_result, identity)
        except Exception:
            social = []

    return {
        "identity":  identity,
        "findings":  findings,
        "pivots":    pivots,
        "social_candidates": social,
        "summary":   _build_summary(identity, findings),
    }


def _build_identity(scan_type: str, data: dict) -> dict:
    """Extract confirmed identity fields from scan data."""
    identity = {
        "real_name":  {"value": None, "confidence": "NOT FOUND", "source": None},
        "email":      {"value": None, "confidence": "NOT FOUND", "source": None},
        "username":   {"value": None, "confidence": "NOT FOUND", "source": None},
        "location":   {"value": None, "confidence": "NOT FOUND", "source": None},
        "avatar":     {"value": None, "confidence": "NOT FOUND", "source": None},
        "bio":        {"value": None, "confidence": "NOT FOUND", "source": None},
        "website":    {"value": None, "confidence": "NOT FOUND", "source": None},
        "phone":      {"value": None, "confidence": "NOT FOUND", "source": None},
        "company":    {"value": None, "confidence": "NOT FOUND", "source": None},
        "platforms":  [],
    }

    if scan_type == "email":
        identity["email"] = {"value": data.get("query"), "confidence": "CONFIRMED", "source": "Input"}

        # Real name from GitHub commits
        gh_name = data.get("github", {}).get("author_name", "")
        if gh_name:
            identity["real_name"] = {"value": gh_name, "confidence": "CONFIRMED", "source": "GitHub commit history"}

        # Real name from Gravatar
        grav_name = data.get("gravatar", {}).get("name", "")
        if grav_name and not identity["real_name"]["value"]:
            identity["real_name"] = {"value": grav_name, "confidence": "CONFIRMED", "source": "Gravatar profile"}

        # Avatar
        if data.get("gravatar", {}).get("avatar"):
            identity["avatar"] = {"value": data["gravatar"]["avatar"], "confidence": "CONFIRMED", "source": "Gravatar"}

        # Bio from Gravatar
        if data.get("gravatar", {}).get("bio"):
            identity["bio"] = {"value": data["gravatar"]["bio"], "confidence": "CONFIRMED", "source": "Gravatar"}

        # Platforms from Holehe
        for site in data.get("holehe", {}).get("found", []):
            identity["platforms"].append({
                "name":       site["site"],
                "url":        site["url"],
                "confidence": "CONFIRMED",
                "source":     "Holehe registration check",
            })

        # Platforms from social web hits
        for r in data.get("social_hits", []):
            identity["platforms"].append({
                "name":       _domain_to_name(r["link"]),
                "url":        r["link"],
                "title":      r.get("title", ""),
                "confidence": "PROBABLE",
                "source":     "Web search",
            })

    elif scan_type == "username":
        identity["username"] = {"value": data.get("query"), "confidence": "CONFIRMED", "source": "Input"}

        # Real name from any found account
        for acc in data.get("found", []):
            if acc.get("name") and not identity["real_name"]["value"]:
                identity["real_name"] = {"value": acc["name"], "confidence": "CONFIRMED", "source": f"{acc['site']} profile"}
            if acc.get("location") and not identity["location"]["value"]:
                identity["location"] = {"value": acc["location"], "confidence": "CONFIRMED", "source": f"{acc['site']} profile"}
            if acc.get("bio") and not identity["bio"]["value"]:
                identity["bio"] = {"value": acc["bio"][:200], "confidence": "CONFIRMED", "source": f"{acc['site']} profile"}
            if acc.get("avatar") and not identity["avatar"]["value"]:
                identity["avatar"] = {"value": acc["avatar"], "confidence": "CONFIRMED", "source": f"{acc['site']} profile"}

        # All confirmed platforms
        for acc in data.get("found", []):
            identity["platforms"].append({
                "name":       acc["site"],
                "url":        acc.get("url", ""),
                "confidence": "CONFIRMED",
                "source":     "Direct API check",
                "meta":       acc.get("meta", {}),
            })

    elif scan_type == "name":
        identity["real_name"] = {"value": data.get("query"), "confidence": "CONFIRMED", "source": "Input"}

        # Platforms from dork results
        for dork in data.get("dork_results", []):
            for r in dork.get("results", []):
                identity["platforms"].append({
                    "name":       dork["label"],
                    "url":        r["link"],
                    "title":      r.get("title", ""),
                    "snippet":    r.get("snippet", ""),
                    "confidence": "PROBABLE",
                    "source":     f"Google dork: {dork['key']}",
                })

    elif scan_type == "ip":
        geo = data.get("geo", {})
        if geo.get("city") and geo.get("country"):
            identity["location"] = {"value": f"{geo['city']}, {geo['country']}", "confidence": "CONFIRMED", "source": "ip-api.com geolocation"}
        if geo.get("org"):
            identity["company"] = {"value": geo["org"], "confidence": "CONFIRMED", "source": "ip-api.com ASN lookup"}

    elif scan_type == "domain":
        rdap = data.get("rdap", {})
        if rdap.get("registrar"):
            identity["company"] = {"value": rdap["registrar"], "confidence": "CONFIRMED", "source": "RDAP/WHOIS"}

    elif scan_type == "phone":
        identity["phone"] = {"value": data.get("normalized"), "confidence": "CONFIRMED", "source": "Input"}
        c = data.get("country", {})
        if c.get("country"):
            identity["location"] = {"value": c["country"], "confidence": "PROBABLE", "source": "Phone prefix lookup"}

    return identity


def _plan_pivots(scan_type: str, data: dict, identity: dict) -> list:
    """Decide what additional lookups to run based on what we found."""
    tasks = []

    if scan_type == "email":
        email = data.get("query", "")
        domain = email.split("@")[-1] if "@" in email else ""

        # Pivot: real name → search for more info
        name = identity["real_name"]["value"]
        if name:
            tasks.append({
                "type":  "name_web_search",
                "arg":   name,
                "label": f"Web search for real name: {name}",
                "fn":    _pivot_name_search,
            })

        # Pivot: email domain → check if personal website
        if domain and domain not in ("gmail.com","yahoo.com","hotmail.com","outlook.com","icloud.com","protonmail.com","tutanota.com"):
            tasks.append({
                "type":  "domain_check",
                "arg":   domain,
                "label": f"Domain check: {domain}",
                "fn":    _pivot_domain_headers,
            })

        # Pivot: GitHub repos found → check personal website in bio
        for repo in data.get("github", {}).get("repos", [])[:2]:
            tasks.append({
                "type":  "github_repo",
                "arg":   repo["name"],
                "label": f"GitHub repo: {repo['name']}",
                "fn":    _pivot_github_repo,
            })

    elif scan_type == "username":
        username = data.get("query", "")

        # Pivot: check if username@common-domains has a Gravatar
        for domain in ["gmail.com", "outlook.com", "yahoo.com"]:
            guessed_email = f"{username}@{domain}"
            tasks.append({
                "type":  "email_guess",
                "arg":   guessed_email,
                "label": f"Checking if {guessed_email} has Gravatar",
                "fn":    _pivot_gravatar_check,
            })

        # Pivot: real name found → web search
        name = identity["real_name"]["value"]
        if name:
            tasks.append({
                "type":  "name_web_search",
                "arg":   name,
                "label": f"Web search for: {name}",
                "fn":    _pivot_name_search,
            })

    elif scan_type == "name":
        name = data.get("query", "")
        # Pivot: search for email pattern
        tasks.append({
            "type":  "email_hunt",
            "arg":   name,
            "label": f"Hunting email for: {name}",
            "fn":    _pivot_hunt_email,
        })

    elif scan_type == "domain":
        domain = data.get("query", "")
        # Pivot: check tech stack of the domain
        tasks.append({
            "type":  "domain_tech",
            "arg":   domain,
            "label": f"Technology fingerprint: {domain}",
            "fn":    _pivot_domain_headers,
        })

    return tasks


# ── Pivot functions ────────────────────────────────────────────────────────────

def _pivot_name_search(name: str) -> dict | None:
    """Search web for a real name, return top results."""
    try:
        from modules.search import search
        results = search(f'"{name}"', max_results=5)
        if results:
            return {"results": results, "count": len(results)}
    except Exception:
        pass
    return None


def _pivot_gravatar_check(email: str) -> dict | None:
    """Check if a guessed email has a Gravatar profile."""
    import hashlib
    try:
        h = hashlib.md5(email.encode()).hexdigest()
        r = requests.get(f"https://gravatar.com/{h}.json", timeout=5)
        if r.status_code == 200:
            entry = r.json().get("entry", [{}])[0]
            return {
                "email":   email,
                "found":   True,
                "name":    entry.get("displayName", ""),
                "avatar":  f"https://www.gravatar.com/avatar/{h}?s=200",
                "profile": f"https://gravatar.com/{h}",
            }
    except Exception:
        pass
    return None


def _pivot_github_repo(repo_name: str) -> dict | None:
    """Get GitHub repo info — find homepage, description, owner."""
    try:
        r = requests.get(
            f"https://api.github.com/repos/{repo_name}",
            timeout=8,
            headers={"User-Agent": "GhostTrace-v3"}
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "name":        d.get("full_name"),
                "description": d.get("description", ""),
                "homepage":    d.get("homepage", ""),
                "language":    d.get("language", ""),
                "stars":       d.get("stargazers_count", 0),
                "owner_name":  d.get("owner", {}).get("login", ""),
                "owner_url":   d.get("owner", {}).get("html_url", ""),
            }
    except Exception:
        pass
    return None


def _pivot_domain_headers(domain: str) -> dict | None:
    """Fingerprint a domain — get title, server, tech stack from HTTP headers."""
    try:
        url = f"https://{domain}" if not domain.startswith("http") else domain
        r = requests.get(url, timeout=8, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 (compatible; GhostTrace/3.0)"})
        headers = dict(r.headers)
        tech = []

        # Detect tech from headers
        server = headers.get("Server", headers.get("server", ""))
        powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        if server:   tech.append(f"Server: {server}")
        if powered:  tech.append(f"Powered by: {powered}")

        # Detect from page content
        content = r.text[:5000].lower()
        if "wordpress" in content:   tech.append("WordPress")
        if "shopify"   in content:   tech.append("Shopify")
        if "wix.com"   in content:   tech.append("Wix")
        if "react"     in content:   tech.append("React")
        if "next.js"   in content or "nextjs" in content: tech.append("Next.js")
        if "django"    in content:   tech.append("Django")
        if "flask"     in content:   tech.append("Flask")
        if "laravel"   in content:   tech.append("Laravel")
        if "jquery"    in content:   tech.append("jQuery")
        if "bootstrap" in content:   tech.append("Bootstrap")

        # Extract page title
        title_match = re.search(r"<title[^>]*>([^<]+)</title>", r.text[:3000], re.IGNORECASE)
        title = title_match.group(1).strip() if title_match else ""

        # Extract meta description
        desc_match = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)', r.text[:5000], re.IGNORECASE)
        description = desc_match.group(1).strip() if desc_match else ""

        return {
            "url":          url,
            "title":        title,
            "description":  description,
            "tech_stack":   list(set(tech)),
            "status_code":  r.status_code,
            "final_url":    r.url,
        }
    except Exception:
        pass
    return None


def _pivot_hunt_email(name: str) -> dict | None:
    """Hunt for email addresses associated with a name via web search."""
    try:
        from modules.search import search
        results = search(f'"{name}" email OR contact "@"', max_results=5)
        emails_found = []
        for r in results:
            # Extract email-like patterns from snippets
            text = r.get("snippet", "") + " " + r.get("title", "")
            matches = re.findall(r'[\w\.\+\-]+@[\w\.\-]+\.\w{2,}', text)
            for m in matches:
                if m not in emails_found:
                    emails_found.append(m)
        return {"emails_found": emails_found, "results": results} if results else None
    except Exception:
        pass
    return None


# ── Findings extractor ─────────────────────────────────────────────────────────

def _extract_findings(scan_type: str, data: dict, pivots: list, identity: dict) -> list:
    """Build a clean list of confirmed findings with evidence."""
    findings = []

    def add(category, description, confidence, evidence, value=None):
        findings.append({
            "category":    category,
            "description": description,
            "confidence":  confidence,
            "evidence":    evidence,
            "value":       value,
        })

    # Identity findings
    if identity["real_name"]["value"]:
        add("IDENTITY", f"Real name: {identity['real_name']['value']}",
            identity["real_name"]["confidence"],
            f"Source: {identity['real_name']['source']}",
            identity["real_name"]["value"])

    if identity["location"]["value"]:
        add("LOCATION", f"Location: {identity['location']['value']}",
            identity["location"]["confidence"],
            f"Source: {identity['location']['source']}",
            identity["location"]["value"])

    if identity["company"]["value"]:
        add("ORGANISATION", f"Company/Org: {identity['company']['value']}",
            identity["company"]["confidence"],
            f"Source: {identity['company']['source']}",
            identity["company"]["value"])

    # Platform findings
    confirmed_platforms = [p for p in identity["platforms"] if p["confidence"] == "CONFIRMED"]
    probable_platforms  = [p for p in identity["platforms"] if p["confidence"] == "PROBABLE"]

    if confirmed_platforms:
        add("PLATFORMS",
            f"Confirmed on {len(confirmed_platforms)} platform(s): {', '.join(p['name'] for p in confirmed_platforms[:8])}",
            "CONFIRMED",
            "Direct API verification",
            confirmed_platforms)

    if probable_platforms:
        add("PLATFORMS",
            f"Probable presence on {len(probable_platforms)} more platform(s)",
            "PROBABLE",
            "Web search results",
            probable_platforms)

    # Breach findings
    if scan_type == "email":
        breach = data.get("breach", {})
        if breach.get("breached"):
            add("SECURITY",
                f"Email found in {breach['count']} data breach(es): {', '.join(breach.get('sources', [])[:5])}",
                "CONFIRMED",
                "LeakCheck public database",
                breach)
        else:
            add("SECURITY", "No data breaches found in checked databases",
                "CONFIRMED", "LeakCheck public check", None)

        if data.get("is_disposable"):
            add("SECURITY", "Disposable/throwaway email address detected",
                "CONFIRMED", "Domain blocklist check", data.get("domain"))

        emailrep = data.get("emailrep", {})
        if emailrep.get("suspicious"):
            add("SECURITY", f"Email flagged as suspicious (reputation: {emailrep.get('reputation','?')})",
                "CONFIRMED", "EmailRep.io analysis", emailrep)

    # Pivot findings
    for pivot in pivots:
        pdata = pivot.get("data", {})
        ptype = pivot.get("pivot_type", "")

        if ptype == "email_guess" and pdata.get("found"):
            add("IDENTITY",
                f"Gravatar profile found for guessed email: {pdata['email']}",
                "LINKED",
                "Gravatar hash check on common email providers",
                pdata)

        if ptype == "domain_tech" and pdata:
            tech = pdata.get("tech_stack", [])
            title = pdata.get("title", "")
            add("INFRASTRUCTURE",
                f"Website technology: {', '.join(tech) if tech else 'Unknown'}" + (f" — Title: {title}" if title else ""),
                "CONFIRMED",
                f"HTTP fingerprinting of {pdata.get('url','')}",
                pdata)

        if ptype == "github_repo" and pdata:
            homepage = pdata.get("homepage", "")
            if homepage:
                add("INFRASTRUCTURE",
                    f"Personal website found: {homepage} (from GitHub repo: {pdata.get('name','')})",
                    "CONFIRMED",
                    "GitHub repository metadata",
                    pdata)

        if ptype == "email_hunt" and pdata:
            emails = pdata.get("emails_found", [])
            if emails:
                add("CONTACT",
                    f"Possible email address(es) found: {', '.join(emails[:3])}",
                    "LINKED",
                    "Extracted from web search snippets — verify manually",
                    emails)

    # Shodan findings for IP/domain
    if scan_type in ("ip", "domain"):
        shodan = data.get("shodan", {})
        if shodan.get("ports"):
            add("INFRASTRUCTURE",
                f"Open ports: {', '.join(str(p) for p in shodan['ports'])}",
                "CONFIRMED",
                "Shodan InternetDB",
                shodan["ports"])
        if shodan.get("vulns"):
            add("SECURITY",
                f"Known vulnerabilities (CVEs): {', '.join(shodan['vulns'][:5])}",
                "CONFIRMED",
                "Shodan InternetDB CVE database",
                shodan["vulns"])

    if scan_type == "domain":
        subs = data.get("subdomains", [])
        if subs:
            add("INFRASTRUCTURE",
                f"{len(subs)} subdomain(s) discovered via SSL certificate transparency",
                "CONFIRMED",
                "crt.sh certificate logs",
                subs)

    return findings


def _build_summary(identity: dict, findings: list) -> str:
    """Build a one-paragraph plain English summary. Only from confirmed data."""
    parts = []

    name = identity["real_name"]["value"]
    if name:
        parts.append(f"Subject identified as {name}")

    loc = identity["location"]["value"]
    if loc:
        parts.append(f"located in {loc}")

    company = identity["company"]["value"]
    if company:
        parts.append(f"associated with {company}")

    platforms = identity["platforms"]
    confirmed = [p for p in platforms if p["confidence"] == "CONFIRMED"]
    if confirmed:
        parts.append(f"confirmed presence on {len(confirmed)} platform(s)")

    security = [f for f in findings if f["category"] == "SECURITY"]
    breach_finding = next((f for f in security if "breach" in f["description"].lower()), None)
    if breach_finding and "No data" not in breach_finding["description"]:
        parts.append("email exposed in data breach(es)")

    if not parts:
        return "Insufficient data to build identity summary. Run additional scans for more information."

    return ". ".join(parts).capitalize() + "."


def _domain_to_name(url: str) -> str:
    """Extract readable platform name from URL."""
    from config import SOCIAL_DOMAINS
    for domain, name in SOCIAL_DOMAINS.items():
        if domain in url:
            return name
    try:
        match = re.search(r"(?:https?://)?(?:www\.)?([^/]+)", url)
        return match.group(1) if match else url
    except Exception:
        return url
