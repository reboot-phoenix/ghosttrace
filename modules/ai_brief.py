"""
modules/ai_brief.py — AI Intelligence Brief Generator

Uses Claude claude-sonnet-4-6 to generate a classified-style intelligence
report from any scan result. Called after a scan completes.

Requires ANTHROPIC_API_KEY environment variable.
Falls back gracefully if not set.
"""

import os
import json
import requests

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()


def generate_brief(scan_result: dict) -> dict:
    """
    Takes any scan result dict and returns an AI intelligence brief.
    Returns {brief: str, generated: bool, error: str|None}
    """
    if not ANTHROPIC_API_KEY:
        return {
            "brief": None,
            "generated": False,
            "error": "ANTHROPIC_API_KEY not set"
        }

    scan_type = scan_result.get("type") or scan_result.get("scan_type", "unknown")
    query     = scan_result.get("query", "unknown")
    prompt    = _build_prompt(scan_type, query, scan_result)

    try:
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-6",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": prompt}]
            },
            timeout=30,
        )

        if response.status_code != 200:
            return {"brief": None, "generated": False, "error": f"API error {response.status_code}"}

        content = response.json().get("content", [])
        text = "".join(block.get("text", "") for block in content if block.get("type") == "text")

        return {"brief": text.strip(), "generated": True, "error": None}

    except Exception as e:
        return {"brief": None, "generated": False, "error": str(e)}


def _build_prompt(scan_type: str, query: str, data: dict) -> str:
    """Build a concise prompt for the intelligence brief."""

    # Summarise the scan data into key facts
    facts = _extract_facts(scan_type, data)

    return f"""You are an OSINT intelligence analyst. Write a concise, professional intelligence brief based on the following scan data.

SUBJECT: {query}
SCAN TYPE: {scan_type.upper()}

RAW INTELLIGENCE DATA:
{facts}

Write a classified-style intelligence brief with these exact sections:

SUBJECT: [name/email/username/ip]
SCAN TYPE: [type]
CONFIDENCE: [LOW/MEDIUM/HIGH based on data quality]

EXECUTIVE SUMMARY:
[2-3 sentences summarising the most important findings]

KEY FINDINGS:
[Bullet points of the most significant findings only — be specific, cite actual data]

DIGITAL FOOTPRINT ASSESSMENT:
[1-2 sentences on overall online presence level]

RISK INDICATORS:
[Any red flags — breaches, VPN use, suspicious patterns. Write NONE if nothing found]

RECOMMENDED FOLLOW-UP:
[2-3 specific next steps an investigator should take]

---
Keep it factual, concise and professional. Do not invent information not present in the data. If data is limited, say so."""


def _extract_facts(scan_type: str, data: dict) -> str:
    """Extract key facts from scan data as a readable summary."""
    lines = []

    if scan_type == "name":
        dorks = data.get("dork_results", [])
        hits  = [d for d in dorks if d.get("found")]
        lines.append(f"Platforms with results: {len(hits)}/14")
        for d in hits:
            lines.append(f"  [{d['label']}]: {d['count']} results")
            for r in d.get("results", [])[:2]:
                lines.append(f"    - {r.get('title','')} | {r.get('link','')}")
                if r.get("snippet"):
                    lines.append(f"      {r['snippet'][:120]}")

    elif scan_type == "email":
        if data.get("gravatar", {}).get("found"):
            g = data["gravatar"]
            lines.append(f"Gravatar profile found: name={g.get('name')}, bio={g.get('bio','')[:80]}")
        gh = data.get("github", {})
        if gh.get("commits"):
            lines.append(f"GitHub commits found: author={gh.get('author_name')}, repos={[r['name'] for r in gh.get('repos',[])[:3]]}")
        holehe = data.get("holehe", {})
        if holehe.get("found"):
            lines.append(f"Registered on {len(holehe['found'])} sites: {[f['site'] for f in holehe['found'][:10]]}")
        breach = data.get("breach", {})
        if breach.get("breached"):
            lines.append(f"DATA BREACH: found in {breach['count']} breaches: {breach.get('sources', [])[:5]}")
        emailrep = data.get("emailrep", {})
        if emailrep:
            lines.append(f"Email reputation: {emailrep.get('reputation','?')}, suspicious={emailrep.get('suspicious')}, spam={emailrep.get('spam')}")
        if data.get("is_disposable"):
            lines.append("WARNING: Disposable email address detected")
        for r in data.get("social_hits", [])[:5]:
            lines.append(f"Social hit: {r.get('title','')} | {r.get('link','')}")

    elif scan_type == "username":
        found = data.get("found", [])
        lines.append(f"Total accounts found: {len(found)}")
        cats = data.get("categories", {})
        for cat, n in cats.items():
            lines.append(f"  {cat}: {n} platforms")
        for acc in found[:15]:
            meta = acc.get("meta", {})
            lines.append(f"  [{acc.get('site')}] {acc.get('url','')} | name={acc.get('name','')} | bio={str(acc.get('bio',''))[:60]}")
            if meta:
                lines.append(f"    meta: {meta}")

    elif scan_type == "phone":
        c = data.get("country", {})
        lines.append(f"Number: {data.get('normalized')}")
        lines.append(f"Country: {c.get('country','?')} ({c.get('prefix','?')})")
        for r in data.get("web_results", [])[:5]:
            lines.append(f"Web mention: {r.get('title','')} | {r.get('link','')}")
            if r.get("snippet"):
                lines.append(f"  {r['snippet'][:100]}")

    elif scan_type == "ip":
        g = data.get("geo", {})
        s = data.get("shodan", {})
        lines.append(f"IP: {data.get('query')}")
        lines.append(f"Location: {g.get('city')}, {g.get('country')} | ISP: {g.get('isp')} | ASN: {g.get('asn')}")
        lines.append(f"VPN/Proxy: {g.get('proxy')} | Hosting/DC: {g.get('hosting')} | Mobile: {g.get('mobile')}")
        if s.get("ports"):
            lines.append(f"Open ports: {s['ports']}")
        if s.get("vulns"):
            lines.append(f"CVEs: {s['vulns']}")
        if s.get("hostnames"):
            lines.append(f"Hostnames: {s['hostnames']}")

    elif scan_type == "domain":
        r = data.get("rdap", {})
        d = data.get("dns", {})
        lines.append(f"Domain: {data.get('query')} → IP: {data.get('resolved_ip')}")
        lines.append(f"Registrar: {r.get('registrar','?')} | Registered: {r.get('registered','?')} | Expires: {r.get('expiry','?')}")
        lines.append(f"Subdomains found: {len(data.get('subdomains',[]))}")
        if data.get("subdomains"):
            lines.append(f"  Sample: {data['subdomains'][:8]}")
        s = data.get("shodan", {})
        if s.get("ports"):
            lines.append(f"Open ports: {s['ports']}")
        if s.get("vulns"):
            lines.append(f"CVEs: {s['vulns']}")

    return "\n".join(lines) if lines else "No detailed data available."
