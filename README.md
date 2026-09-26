<div align="center">

# 👻 GhostTrace

### The most powerful free OSINT intelligence platform you can self-host.
### Zero API keys. Zero cost. Zero compromises.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-ghosttrace.up.railway.app-7c6aff?style=for-the-badge&logo=railway)](https://ghosttrace.up.railway.app)
[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-black?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Cost](https://img.shields.io/badge/Cost-%240%2Fmonth-brightgreen?style=for-the-badge)](/)

**Built by Ashtid D. — BSc IT, Techno India University**

</div>

---

## 🧠 What is GhostTrace?

GhostTrace is a full-stack OSINT (Open Source Intelligence) platform built for investigators, security researchers, and anyone who wants to audit their digital footprint. It aggregates data from **dozens of free public sources simultaneously** and presents everything in a clean, professional intelligence dashboard.

No subscriptions. No paywalls. No API keys required out of the box.

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

**Total monthly cost: $0.00**

---

## 🚀 Deploy in 2 Minutes (Railway — Recommended)

Railway is the easiest free host for this app. No credit card. No cold starts on the free tier.

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
├── app.py                  # Flask server, rate limiter (20/hr), all routes
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
│   └── ip_domain.py        # IP/Domain — Shodan, RDAP, DNS, crt.sh
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
- In-memory rate limiter — 20 scans/hour per IP, resets on restart (swap to Redis if scaling)
- No server-side storage — results never saved, history lives in browser `localStorage` only

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
