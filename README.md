# 👻 GhostTrace v3 — OSINT Intelligence Platform

The best free OSINT tool you can self-host. Zero API keys required.

---

## What it does

| Scan type | What it checks | Cost |
|-----------|---------------|------|
| **Username** | 3,100+ platforms via Maigret + 35 native APIs (GitHub, Reddit, GitLab, npm, PyPI, Chess.com, Lichess, Codeforces, Duolingo, Last.fm…) | Free |
| **Email** | Breach data (LeakCheck public) · Holehe 120+ sites · GitHub commit search (reveals real name) · Gravatar profile · EmailRep reputation | Free |
| **IP Address** | Geo + ISP (ip-api.com) · Shodan InternetDB (ports, CVEs) · RDAP/WHOIS | Free |
| **Domain** | DNS records · WHOIS/RDAP · crt.sh subdomains · Shodan · Geolocation of IP | Free |
| **Phone** | Country/carrier detection · Format variants · Web search · 9 deep-links | Free |
| **Name** | 14 Google dork queries · Social platform search links · Web results | Free |

---

## Setup (local)

```bash
git clone https://github.com/yourusername/ghosttrace.git
cd ghosttrace
pip install -r requirements.txt
python app.py
# → http://localhost:5000
```

---

## Deployment (free, no credit card)

### Option 1: Fly.io (BEST — always on, no cold starts)

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Login / sign up (no card needed for free tier)
fly auth login

# First deploy
fly launch         # picks up fly.toml automatically
fly deploy

# Your app lives at https://ghosttrace.fly.dev
```

The free tier gives you 3 shared VMs, 256 MB RAM, globally distributed.
**No cold starts** — your app stays running 24/7.

### Option 2: Koyeb (also good, no card for free tier)

1. Go to https://app.koyeb.com → New Service → GitHub
2. Connect this repo
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app --workers 1 --timeout 120 --bind 0.0.0.0:$PORT`
5. Deploy

Note: Koyeb free tier scales to zero after 1 hour of inactivity (cold start ~10s).

### Option 3: Render (what you used before)

Same as before — renders.yaml works. Cold start after 15 min idle.

### Why NOT Cloudflare Workers/Pages for the backend

Cloudflare Workers run JavaScript only, with a 10ms CPU limit.
Maigret and Holehe are Python subprocesses. They cannot run on Cloudflare.
You can use Cloudflare Pages for a pure static frontend (no backend), but
that means losing Maigret, Holehe, and all the server-side logic.

---

## Optional: Free Search API

Without any key, the app uses DuckDuckGo (free, may be blocked on cloud IPs).

For better search results (100 queries/day, completely free, no card):

1. Go to https://programmablesearchengine.google.com
2. Create a new search engine → set it to search the whole web
3. Get your Search Engine ID (cx)
4. Go to https://console.cloud.google.com → Enable "Custom Search API"
5. Create an API key
6. Set as environment variables:
   - `GOOGLE_CSE_KEY=your_key`
   - `GOOGLE_CSE_ID=your_cx`

On Fly.io: `fly secrets set GOOGLE_CSE_KEY=xxx GOOGLE_CSE_ID=yyy`
On Koyeb: set in dashboard → Environment Variables
On Render: set in dashboard → Environment

---

## Tech stack

| Component | What | Cost |
|-----------|------|------|
| Flask | Web framework | Free |
| Maigret | 3,100+ site username search | Free |
| Holehe | 120+ site email check | Free |
| ip-api.com | IP geolocation | Free (45 req/min) |
| Shodan InternetDB | Ports + CVEs for any IP | Free (no key) |
| crt.sh | SSL cert transparency → subdomains | Free |
| Cloudflare DoH | DNS records | Free |
| RDAP | Modern WHOIS | Free |
| LeakCheck public | Breach data | Free |
| EmailRep.io | Email reputation | Free |
| GitHub API | Commit author search | Free (unauthenticated) |
| DuckDuckGo | Fallback web search | Free |
| Google CSE | Web search (optional) | 100/day free |

**Total: $0/month. Zero API keys required.**

---

## Environment variables (all optional)

| Variable | What | Where to get |
|----------|------|-------------|
| `GOOGLE_CSE_KEY` | Google CSE API key | Google Cloud Console |
| `GOOGLE_CSE_ID`  | Google CSE engine ID | programmablesearchengine.google.com |
| `HIBP_API_KEY`   | Have I Been Pwned key | haveibeenpwned.com/API — $3.50/mo |
| `LEAKCHECK_KEY`  | LeakCheck paid key | leakcheck.io |

---

## Credit

Built by Ashtid D. — BSc IT, Techno India University
Powered by: Maigret · Holehe · Shodan InternetDB · crt.sh · EmailRep · ip-api · RDAP
