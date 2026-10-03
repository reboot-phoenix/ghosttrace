<div align="center">

# 👻 GhostTrace

### The most powerful free OSINT intelligence platform you can self-host.
### No API keys needed for scans. Free to self-host.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-ghosttrace.up.railway.app-7c6aff?style=for-the-badge&logo=railway)](https://ghosttrace.up.railway.app)
[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-black?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)


**Built by Ashtid D. — BSc IT, Techno India University**

</div>

---

## 🧠 What is GhostTrace?

GhostTrace is a full-stack OSINT (Open Source Intelligence) platform built for investigators, security researchers, and anyone who wants to audit their digital footprint. It aggregates data from **dozens of free public sources simultaneously** and presents everything in a clean, professional intelligence dashboard.

No subscriptions. No paywalls. Scans need no API keys out of the box (the optional AI brief needs an Anthropic key).

---

## ⚡ Scan Modes

<table>
<tr>
<td width="50%">

### 🔍 Username
Checks **3,100+ platforms** simultaneously using Maigret — the most powerful username OSINT engine available. Also runs 35 native API lookups for enriched profile data (bio, avatar, follower count, location).

**Platforms include:** GitHub · Reddit · GitLab · npm · PyPI · Docker Hub · Keybase · Chess.com · Lichess · Codeforces · Duolingo · Last.fm · Twitch · Medium · Substack · TryHackMe · Dribbble · Behance · Replit · HackerRank · LeetCode · Mastodon · SoundCloud · Vimeo · Flickr · Tumblr + 3,000 more

</td>
<td width="50%">

### 📧 Email
Runs **5 intelligence sources in parallel:**
- 🔥 **Holehe** — 120+ site registration check (passive, no login)
- 🐙 **GitHub commit search** — reveals real name + repos
- 🖼️ **Gravatar** — profile, avatar, linked URLs
- 💀 **Breach check** — LeakCheck public (free, no key)
- 🔎 **EmailRep.io** — reputation, spam, blacklist flags
- ✉️ **Web search** — verbatim email mentions
- 🚫 **Disposable detection** — 500+ throwaway domains

</td>
</tr>
<tr>
<td width="50%">

### 🌐 IP Address
- 📍 **Geolocation** — country, city, region, timezone
- 🏢 **ISP / ASN / Organisation**
- 🛡️ **Shodan InternetDB** — open ports + CVEs (no key!)
- 🔍 **RDAP** — network range, registration info
- ⚠️ **VPN / Proxy / Hosting** detection
- 📱 **Mobile carrier** detection

</td>
<td width="50%">

### 🔗 Domain
- 📋 **WHOIS/RDAP** — registrar, dates, nameservers
- 🔡 **DNS records** — A, AAAA, MX, TXT, NS
- 🗂️ **Subdomain discovery** via crt.sh (SSL certificate logs)
- 🛡️ **Shodan** — ports + CVEs on resolved IP
- 🌍 **IP geolocation** of the domain's server
- 🕰️ **Deep-links** — Wayback Machine, URLScan, VirusTotal

</td>
</tr>
<tr>
<td width="50%">

### 👤 Name
- 🎯 **14 pre-built Google dork queries** — each clickable
- LinkedIn · GitHub · Twitter · Instagram · TikTok · YouTube · Reddit · Medium · News · PDFs · Email · Phone · Academic papers · Images
- 🌐 Social platform deep-search links
- 🔍 Auto web search with optional context filters (city, company, college, job title)

</td>
<td width="50%">

### 📱 Phone
- 🌍 **Country detection** — 80+ country codes
- 📡 **Carrier / line type** heuristics
- 🔄 **Format variants** — all common formats generated
- 🌐 **Web search** across all variants
- 🔗 **9 deep-links** — Truecaller · Sync.me · NumLookup · SpamCalls · CallerID Test · WhoCallsMe · WhatsApp · Telegram · Google

</td>
</tr>
</table>

---

## 🆓 Everything is Free

| Source | What it provides | Key needed? |
|--------|-----------------|-------------|
| **Maigret** | 3,100+ site username search | ❌ Never |
| **Holehe** | 120+ site email registration | ❌ Never |
| **Shodan InternetDB** | Open ports + CVEs for any IP | ❌ Never |
| **crt.sh** | SSL cert logs → subdomains | ❌ Never |
| **ip-api.com** | IP geolocation + ISP + ASN | ❌ Never |
| **RDAP** | Modern WHOIS replacement | ❌ Never |
| **GitHub API** | Commit author search | ❌ Never (60 req/hr) |
| **Gravatar** | Profile + avatar lookup | ❌ Never |
| **EmailRep.io** | Email reputation | ❌ Never |
| **LeakCheck public** | Breach data | ❌ Never |
| **Cloudflare DoH** | DNS records | ❌ Never |
| **DuckDuckGo** | Web search fallback | ❌ Never |
| **Google CSE** | Web search (better results) | ✅ Optional — 100/day free |
| **HIBP** | Full breach detail | ✅ Optional — $3.50/mo |

**Total cost for scans: $0.** The optional AI brief uses your own Anthropic API usage.

---

## 🚀 Deploy in 2 Minutes (Railway — Recommended)

Railway is a simple host for this app. Free-tier limits and terms change, so check railway.app for current pricing.

**1.** Go to 👉 [railway.app](https://railway.app) → **Login with GitHub**

**2.** Click **New Project** → **Deploy from GitHub repo** → select `reboot-phoenix/ghosttrace`

**3.** Set start command:
```
gunicorn app:app --workers 1 --timeout 120
```

**4.** Click **Deploy** → done. Live at `your-app.up.railway.app`

---

## 🔧 Local Setup

```bash
# Clone
git clone https://github.com/reboot-phoenix/ghosttrace.git
cd ghosttrace

# Install dependencies
pip install -r requirements.txt

# Run
python app.py
# → http://localhost:5000
```

Requirements: Python 3.10+

---

## 🔑 Optional Environment Variables

All variables are optional. The app works perfectly with zero configuration.

| Variable | Purpose | How to get | Benefit |
|----------|---------|-----------|---------|
| `GOOGLE_CSE_KEY` | Google search API key | [Google Cloud Console](https://console.cloud.google.com/apis/credentials) | 100 searches/day, more reliable than DDG |
| `GOOGLE_CSE_ID` | Google Search Engine ID | [programmablesearchengine.google.com](https://programmablesearchengine.google.com) | Required alongside `GOOGLE_CSE_KEY` |
| `HIBP_API_KEY` | Have I Been Pwned | [haveibeenpwned.com/API](https://haveibeenpwned.com/API/Key) | Full breach detail ($3.50/mo) |
| `LEAKCHECK_KEY` | LeakCheck paid | [leakcheck.io](https://leakcheck.io) | More breach sources |
| `ANTHROPIC_API_KEY` | AI intelligence brief | [console.anthropic.com](https://console.anthropic.com) | Enables the AI Brief tab |
| `SCAN_SIGNING_KEY` | Random secret string | any long random value | Keeps AI-brief signatures valid across restarts |
| `TRUSTED_PROXIES` | Reverse-proxy hops in front of the app (default `1`) | your host's docs | Correct client IPs for rate limiting; set `0` if not behind a proxy |
| `FLASK_DEBUG` | `1` enables debug mode when running `python app.py` | — | Local development only, never in production |

### Setting variables on Railway:
Service → **Variables** tab → **New Variable** → add key + value → Railway auto-redeploys.

### Setting up Google CSE (free, 100 queries/day):
1. Go to [programmablesearchengine.google.com](https://programmablesearchengine.google.com) → **New search engine** → add `www.google.com` as placeholder site → **Create**
2. Copy your **Search Engine ID**
3. Go to [console.cloud.google.com](https://console.cloud.google.com) → Enable **Custom Search API** → **Create Credentials** → **API key**
4. Add both to Railway variables

---

## 🏗️ Architecture

```
ghosttrace/
├── app.py                  # Flask server, rate limiter (20 scans/hr, 10 briefs/hr), routes
├── config.py               # API keys, 500+ disposable domains, social map
├── detector.py             # Auto-detects email/phone/ip/domain/username/name
├── requirements.txt
├── Procfile
├── fly.toml                # Fly.io config (alternative host)
│
├── modules/
│   ├── search.py           # Google CSE → DuckDuckGo fallback
│   ├── breach.py           # HIBP → LeakCheck paid → LeakCheck public
│   ├── holehe_runner.py    # Subprocess wrapper (120+ sites)
│   ├── maigret_runner.py   # Subprocess wrapper (3,100+ sites)
│   ├── email.py            # Email OSINT — 5 parallel sources
│   ├── username.py         # Username — 35 APIs + Maigret concurrent
│   ├── phone.py            # Phone — country, formats, deep-links
│   ├── name.py             # Name — 14 dorks + social links
│   ├── ip_domain.py        # IP/Domain — Shodan, RDAP, DNS, crt.sh
│   ├── correlate.py        # Identity extraction + correlation pivots (deep)
│   ├── social_pivot.py     # Deep mode — IG/FB/X/TikTok profile candidates + scoring
│   ├── report.py           # Structured intelligence report
│   └── ai_brief.py         # Optional AI brief (needs ANTHROPIC_API_KEY)
│
├── templates/
│   └── index.html          # Two-panel dashboard UI
│
└── static/
    ├── css/style.css       # Dark intelligence dashboard (689 lines)
    └── js/app.js           # Full frontend — scan, render, history, export
```

**Key decisions:**
- Single Gunicorn worker (`--workers 1`) — Maigret/Holehe are subprocesses, multi-worker breaks them
- `ThreadPoolExecutor` for concurrent I/O — email scan runs 5 sources simultaneously, username runs 35 native checks at once
- In-memory rate limiter — 20 scans/hour and 10 AI briefs/hour per IP; client IP comes from `ProxyFix` (`TRUSTED_PROXIES`), not raw headers; resets on restart (swap to Redis if scaling)
- `/brief` only accepts scan results the server signed (HMAC), so it can't be used as an open proxy to your Anthropic key
- No server-side storage — results never saved, history lives in browser `localStorage` only (older history entries can't be re-briefed after a restart unless `SCAN_SIGNING_KEY` is set)

---

## 🔬 Fast vs Deep Mode

| | Fast (default) | Deep |
|---|---|---|
| Scan + identity extraction | ✅ | ✅ |
| Correlation pivots (extra lookups on discovered names, emails, repos) | ❌ | ✅ |
| Social profile candidates (Instagram · Facebook · X · TikTok) | ❌ | ✅ |

Deep mode builds candidate handles from evidence already in the scan (handles linked in found profiles, the searched username, the email local-part, name variants) and probes those platforms with Maigret. Every hit gets a score and a **PROBABLE** or **LINKED** label with reasons. Nothing is ever marked confirmed: a matching handle does not prove identity, so verify manually. Only public, unauthenticated checks are used: no logins, no account-recovery or contact-sync lookups.

---

## ⚠️ Legal & Ethics

This tool is built for:
- ✅ Auditing your own digital footprint
- ✅ Authorized security research
- ✅ OSINT education and training
- ✅ Finding your own exposed data

This tool is **NOT** for:
- ❌ Stalking or harassing individuals
- ❌ Unauthorized investigation of private persons
- ❌ Any illegal activity under your jurisdiction

All data sources used are **publicly available**. GhostTrace does not store, log, or share any scan results. Use responsibly.

---

## 🛠️ Tech Stack

<div align="center">

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=flat-square&logo=flask&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=flat-square&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=flat-square&logo=css3&logoColor=white)
![Railway](https://img.shields.io/badge/Railway-0B0D0E?style=flat-square&logo=railway&logoColor=white)

</div>

---

<div align="center">

Made with 🖤 by **Ashtid D.**
BSc IT — Techno India University

*GhostTrace — because everyone leaves a trace.*

</div>


## Scam-indicator checks (v3.1)

GhostTrace now returns a `scam_risk` verdict (`likely_scam` / `suspicious` / `no_strong_signals`) with the evidence behind it, for phone numbers, UPI IDs, emails, domains and URLs. It judges *indicators*, not people, and is heuristic: verify with the official source and report fraud at cybercrime.gov.in or 1930.

New/changed env vars: `LASTFM_API_KEY` (optional, replaces a previously hard-coded key), `SCAN_SIGNING_KEY` (set in production).

Security hardening in v3.1: server-side validation of every scan type, SSRF-safe fetching (`modules/safe_http.py`), signed-result expiry on `/brief`, security headers, threaded gunicorn worker.
