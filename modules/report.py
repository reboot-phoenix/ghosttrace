"""
modules/report.py — Intelligence Report Builder

Takes scan result + correlation data and builds a structured
investigation report. Two modes:
  - fast: just the scan data
  - deep: scan + correlation + AI narrative

Every field has a confidence label. No hallucination.
"""

import time
from datetime import datetime, timezone


CONFIDENCE_ICONS = {
    "CONFIRMED":  "✅",
    "PROBABLE":   "⚠️",
    "LINKED":     "🔗",
    "NOT FOUND":  "❌",
}

CONFIDENCE_COLORS = {
    "CONFIRMED":  "green",
    "PROBABLE":   "orange",
    "LINKED":     "blue",
    "NOT FOUND":  "gray",
}


def build_report(scan_result: dict, correlation: dict, scan_mode: str = "fast") -> dict:
    """
    Build a full intelligence report.

    scan_result:  raw scan output from any scanner
    correlation:  output from correlate.correlate()
    scan_mode:    "fast" or "deep"

    Returns a structured report dict ready for the frontend.
    """
    scan_type = scan_result.get("type") or scan_result.get("scan_type", "unknown")
    query     = scan_result.get("query", "")
    identity  = correlation.get("identity", {})
    findings  = correlation.get("findings", [])
    pivots    = correlation.get("pivots", [])

    # ── Identity card ────────────────────────────────────────────────────────
    identity_card = _build_identity_card(identity)

    # ── Platform breakdown ───────────────────────────────────────────────────
    platforms = _build_platform_list(identity, scan_result)

    # ── Security assessment ──────────────────────────────────────────────────
    security = _build_security_assessment(scan_result, findings)

    # ── Infrastructure (for IP/domain) ──────────────────────────────────────
    infrastructure = _build_infrastructure(scan_result, findings, scan_type)

    # ── Timeline ────────────────────────────────────────────────────────────
    timeline = _build_timeline(scan_result, scan_type)

    # ── Investigation notes ──────────────────────────────────────────────────
    notes = _build_investigation_notes(scan_type, scan_result, identity, findings)

    # ── Overall risk score ───────────────────────────────────────────────────
    risk = _calculate_risk(scan_result, findings, identity)

    return {
        "report_id":       f"GT-{int(time.time())}",
        "generated_at":    datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scan_type":       scan_type,
        "query":           query,
        "scan_mode":       scan_mode,
        "summary":         correlation.get("summary", ""),
        "identity_card":   identity_card,
        "platforms":       platforms,
        "security":        security,
        "infrastructure":  infrastructure,
        "timeline":        timeline,
        "notes":           notes,
        "findings":        findings,
        "risk":            risk,
        "pivot_count":     len([p for p in pivots if p.get("data")]),
        "social_candidates": correlation.get("social_candidates", []),
    }


def _build_identity_card(identity: dict) -> list:
    """Build identity fields with confidence labels."""
    fields = [
        ("Real Name",    "real_name"),
        ("Email",        "email"),
        ("Username",     "username"),
        ("Location",     "location"),
        ("Company/Org",  "company"),
        ("Bio",          "bio"),
        ("Phone",        "phone"),
        ("Website",      "website"),
    ]
    card = []
    for label, key in fields:
        field = identity.get(key, {})
        value      = field.get("value")
        confidence = field.get("confidence", "NOT FOUND")
        source     = field.get("source", "")
        card.append({
            "label":      label,
            "value":      value,
            "confidence": confidence,
            "icon":       CONFIDENCE_ICONS.get(confidence, "❓"),
            "color":      CONFIDENCE_COLORS.get(confidence, "gray"),
            "source":     source,
            "found":      value is not None,
        })
    return card


def _build_platform_list(identity: dict, scan_result: dict) -> dict:
    """Build confirmed and probable platform lists."""
    platforms = identity.get("platforms", [])
    confirmed = [p for p in platforms if p.get("confidence") == "CONFIRMED"]
    probable  = [p for p in platforms if p.get("confidence") == "PROBABLE"]
    linked    = [p for p in platforms if p.get("confidence") == "LINKED"]

    # Deduplicate by URL
    def dedup(lst):
        seen = set()
        out  = []
        for p in lst:
            url = p.get("url", "")
            if url and url not in seen:
                seen.add(url)
                out.append(p)
        return out

    return {
        "confirmed": dedup(confirmed),
        "probable":  dedup(probable),
        "linked":    dedup(linked),
        "total":     len(dedup(confirmed + probable + linked)),
    }


def _build_security_assessment(scan_result: dict, findings: list) -> dict:
    """Build security section."""
    scan_type = scan_result.get("type") or scan_result.get("scan_type", "")
    items = []

    if scan_type == "email":
        breach = scan_result.get("breach", {})
        if breach.get("breached"):
            items.append({
                "level":       "HIGH",
                "icon":        "💀",
                "title":       f"Data breach exposure ({breach['count']} breach{'es' if breach['count']!=1 else ''})",
                "detail":      f"Found in: {', '.join(breach.get('sources', [])[:8])}",
                "confidence":  "CONFIRMED",
                "action":      "Change password immediately on all platforms. Enable 2FA.",
            })
        else:
            items.append({
                "level":      "LOW",
                "icon":       "✅",
                "title":      "No data breaches found",
                "detail":     "Not found in LeakCheck public database",
                "confidence": "CONFIRMED",
                "action":     None,
            })

        emailrep = scan_result.get("emailrep", {})
        if emailrep.get("suspicious"):
            items.append({
                "level":      "HIGH",
                "icon":       "⚠️",
                "title":      "Email flagged as suspicious",
                "detail":     f"Reputation: {emailrep.get('reputation','?')} | Blacklisted: {emailrep.get('blacklisted')} | Spam: {emailrep.get('spam')}",
                "confidence": "CONFIRMED",
                "action":     "Treat communications from this address with caution.",
            })

        if scan_result.get("is_disposable"):
            items.append({
                "level":      "MEDIUM",
                "icon":       "🗑️",
                "title":      "Disposable/throwaway email address",
                "detail":     f"Domain {scan_result.get('domain')} is a known disposable email provider",
                "confidence": "CONFIRMED",
                "action":     "High likelihood of anonymous/fraudulent use.",
            })

    if scan_type in ("ip", "domain"):
        shodan = scan_result.get("shodan", {})
        if shodan.get("vulns"):
            items.append({
                "level":      "CRITICAL",
                "icon":       "💀",
                "title":      f"{len(shodan['vulns'])} known CVE(s) detected",
                "detail":     ", ".join(shodan["vulns"][:5]),
                "confidence": "CONFIRMED",
                "action":     "Patch immediately. These are public vulnerabilities.",
            })
        if shodan.get("ports"):
            risky_ports = [p for p in shodan["ports"] if p in (21,22,23,25,445,3389,5900,6379,27017)]
            if risky_ports:
                items.append({
                    "level":      "HIGH",
                    "icon":       "🔓",
                    "title":      f"Sensitive ports exposed: {', '.join(str(p) for p in risky_ports)}",
                    "detail":     _port_descriptions(risky_ports),
                    "confidence": "CONFIRMED",
                    "action":     "Review firewall rules. These ports should not be publicly accessible.",
                })

        geo = scan_result.get("geo", {})
        if geo.get("proxy"):
            items.append({
                "level":      "MEDIUM",
                "icon":       "🎭",
                "title":      "VPN/Proxy/Tor detected",
                "detail":     "This IP is associated with a VPN, proxy, or anonymisation service",
                "confidence": "CONFIRMED",
                "action":     "Real origin location may differ. Investigate further.",
            })

    # Security findings from correlation
    for f in findings:
        if f["category"] == "SECURITY" and not any(i["title"] in f["description"] for i in items):
            items.append({
                "level":      "MEDIUM" if "suspicious" in f["description"].lower() else "INFO",
                "icon":       "🔍",
                "title":      f["description"],
                "detail":     f["evidence"],
                "confidence": f["confidence"],
                "action":     None,
            })

    if not items:
        items.append({
            "level":      "INFO",
            "icon":       "ℹ️",
            "title":      "No security issues detected in available data",
            "detail":     "This does not guarantee the subject is clean — only what was checked",
            "confidence": "CONFIRMED",
            "action":     None,
        })

    return {
        "items":          items,
        "highest_level":  _highest_level(items),
        "breach_count":   scan_result.get("breach", {}).get("count", 0) if scan_type == "email" else 0,
    }


def _build_infrastructure(scan_result: dict, findings: list, scan_type: str) -> dict | None:
    """Build infrastructure section for IP/domain scans."""
    if scan_type not in ("ip", "domain"):
        # Check if any pivot found a website
        infra_findings = [f for f in findings if f["category"] == "INFRASTRUCTURE"]
        if not infra_findings:
            return None
        return {"items": infra_findings}

    items = []
    shodan = scan_result.get("shodan", {})
    geo    = scan_result.get("geo", {})

    if shodan.get("ports"):
        items.append({"label": "Open Ports", "value": ", ".join(str(p) for p in shodan["ports"]), "confidence": "CONFIRMED"})
    if shodan.get("hostnames"):
        items.append({"label": "Hostnames", "value": ", ".join(shodan["hostnames"][:5]), "confidence": "CONFIRMED"})
    if geo.get("isp"):
        items.append({"label": "ISP", "value": geo["isp"], "confidence": "CONFIRMED"})
    if geo.get("asn"):
        items.append({"label": "ASN", "value": geo["asn"], "confidence": "CONFIRMED"})
    if scan_type == "domain":
        rdap = scan_result.get("rdap", {})
        if rdap.get("registered"):
            items.append({"label": "Registered", "value": rdap["registered"], "confidence": "CONFIRMED"})
        if rdap.get("expiry"):
            items.append({"label": "Expires", "value": rdap["expiry"], "confidence": "CONFIRMED"})
        if rdap.get("registrar"):
            items.append({"label": "Registrar", "value": rdap["registrar"], "confidence": "CONFIRMED"})
        subs = scan_result.get("subdomains", [])
        if subs:
            items.append({"label": "Subdomains", "value": f"{len(subs)} discovered", "confidence": "CONFIRMED"})
        dns = scan_result.get("dns", {})
        if dns.get("MX"):
            items.append({"label": "Mail Server", "value": ", ".join(dns["MX"][:3]), "confidence": "CONFIRMED"})
        if dns.get("TXT"):
            spf = next((t for t in dns["TXT"] if "spf" in t.lower()), None)
            if spf:
                items.append({"label": "SPF Record", "value": spf[:80], "confidence": "CONFIRMED"})

    return {"items": items} if items else None


def _build_timeline(scan_result: dict, scan_type: str) -> list:
    """Build a timeline of discovered dates."""
    events = []

    if scan_type == "email":
        for commit in scan_result.get("github", {}).get("commits", [])[:3]:
            events.append({
                "date":   "Recent",
                "event":  f"GitHub commit: {commit.get('message','')[:60]}",
                "source": "GitHub",
            })

    if scan_type == "username":
        for acc in scan_result.get("found", []):
            created = (acc.get("meta") or {}).get("created")
            if created:
                events.append({
                    "date":   str(created)[:10],
                    "event":  f"Account created on {acc['site']}",
                    "source": acc["site"],
                })

    if scan_type == "domain":
        rdap = scan_result.get("rdap", {})
        if rdap.get("registered"):
            events.append({"date": rdap["registered"], "event": "Domain registered", "source": "WHOIS/RDAP"})
        if rdap.get("updated"):
            events.append({"date": rdap["updated"],    "event": "Domain last updated", "source": "WHOIS/RDAP"})
        if rdap.get("expiry"):
            events.append({"date": rdap["expiry"],     "event": "Domain expires", "source": "WHOIS/RDAP"})

    return sorted(events, key=lambda x: x.get("date", ""), reverse=False)


def _build_investigation_notes(scan_type, scan_result, identity, findings) -> list:
    """Build actionable next steps for an investigator. Only real suggestions."""
    notes = []

    name = identity.get("real_name", {}).get("value")
    email_val = identity.get("email", {}).get("value") or (scan_result.get("query") if scan_type == "email" else None)
    username_val = identity.get("username", {}).get("value") or (scan_result.get("query") if scan_type == "username" else None)

    if scan_type == "email":
        if name:
            notes.append(f"Run a Name scan for '{name}' to find additional social profiles and web presence.")
        if not scan_result.get("holehe", {}).get("installed"):
            notes.append("Install Holehe (pip install holehe) on your server to check 120+ site registrations.")
        if scan_result.get("breach", {}).get("breached"):
            notes.append("Check full breach details at leakcheck.io for exposed passwords and personal data.")
        notes.append(f"Search Epieos (epieos.com) for deeper Google account data linked to this email.")

    if scan_type == "username":
        if not scan_result.get("maigret", {}).get("total_checked", 0):
            notes.append("Install Maigret (pip install maigret) to check 3,100+ platforms automatically.")
        if name:
            notes.append(f"Run a Name scan for '{name}' to cross-reference web presence.")
        notes.append(f"Check WhatsMyName (whatsmyname.app) for additional platform coverage.")
        notes.append(f"Search Namechk (namechk.com/{username_val}) for username availability (taken = registered).")

    if scan_type == "name":
        notes.append("Try running Email and Username scans with any addresses/handles found above.")
        notes.append("Check court records and public databases for this name in the relevant jurisdiction.")
        notes.append("Search LinkedIn directly for the most accurate professional information.")

    if scan_type == "ip":
        notes.append("Run a full Shodan search (shodan.io) for complete historical port and banner data.")
        notes.append("Check AbuseIPDB (abuseipdb.com) for reported malicious activity from this IP.")
        geo = scan_result.get("geo", {})
        if geo.get("hosting"):
            notes.append("This is a hosting/datacenter IP. Check the provider's abuse contact for account info.")

    if scan_type == "domain":
        notes.append("Run DNSDumpster (dnsdumpster.com) for a complete DNS map including historical records.")
        notes.append("Check Wayback Machine (web.archive.org) to see historical versions of this site.")
        subs = scan_result.get("subdomains", [])
        if subs:
            notes.append(f"Scan the {len(subs)} discovered subdomains individually for additional infrastructure.")

    if not notes:
        notes.append("No specific follow-up actions identified. Review the findings above manually.")

    return notes


def _calculate_risk(scan_result: dict, findings: list, identity: dict) -> dict:
    """Calculate overall investigation risk/exposure score."""
    score = 0
    factors = []

    # Breach
    breach = scan_result.get("breach", {})
    if breach.get("breached"):
        pts = min(breach.get("count", 0) * 10, 30)
        score += pts
        factors.append({"factor": "Data breach exposure", "points": pts, "level": "HIGH"})

    # Platform count
    platforms = identity.get("platforms", [])
    confirmed = len([p for p in platforms if p.get("confidence") == "CONFIRMED"])
    if confirmed:
        pts = min(confirmed * 3, 20)
        score += pts
        factors.append({"factor": f"Confirmed on {confirmed} platforms", "points": pts, "level": "MEDIUM"})

    # Shodan CVEs
    vulns = scan_result.get("shodan", {}).get("vulns", [])
    if vulns:
        pts = min(len(vulns) * 10, 25)
        score += pts
        factors.append({"factor": f"{len(vulns)} CVE(s) found", "points": pts, "level": "CRITICAL"})

    # Open risky ports
    ports = scan_result.get("shodan", {}).get("ports", [])
    risky = [p for p in ports if p in (21,22,23,25,445,3389,5900,6379,27017)]
    if risky:
        pts = min(len(risky) * 5, 15)
        score += pts
        factors.append({"factor": f"Risky ports open: {risky}", "points": pts, "level": "HIGH"})

    # Proxy/VPN
    if scan_result.get("geo", {}).get("proxy"):
        score += 10
        factors.append({"factor": "VPN/Proxy detected", "points": 10, "level": "MEDIUM"})

    # Suspicious email
    if scan_result.get("emailrep", {}).get("suspicious"):
        score += 15
        factors.append({"factor": "Suspicious email reputation", "points": 15, "level": "HIGH"})

    score = min(score, 100)
    level = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"

    return {
        "score":   score,
        "level":   level,
        "factors": factors,
        "color":   {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "orange", "LOW": "green"}.get(level, "gray"),
    }


def _port_descriptions(ports: list) -> str:
    desc = {
        21: "FTP (file transfer)", 22: "SSH (remote access)",
        23: "Telnet (unencrypted)", 25: "SMTP (mail server)",
        445: "SMB (Windows file sharing)", 3389: "RDP (remote desktop)",
        5900: "VNC (remote desktop)", 6379: "Redis (database)",
        27017: "MongoDB (database)",
    }
    return " | ".join(f":{p} {desc.get(p,'')}" for p in ports)


def _highest_level(items: list) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for level in order:
        if any(i.get("level") == level for i in items):
            return level
    return "INFO"
