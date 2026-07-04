# 👻 GhostTrace

**Find out what the internet knows about you.**

GhostTrace is an OSINT (Open Source Intelligence) tool that scans usernames and phone numbers across major platforms to reveal your digital footprint — the same kind of reconnaissance a real attacker or recruiter could do manually, automated and put in front of you first.

🔗 **Live app:** _add your Render URL here_
📦 **Repo:** https://github.com/reboot-phoenix/ghosttrace

---

## What it does

- **Username scan** — checks 15 platforms (GitHub, Reddit, TikTok, YouTube, Twitch, Spotify, Steam, Medium, Dev.to, Keybase, Pastebin, Hacker News, Pinterest, Linktree, Replit) concurrently and reports which ones have an account under that name, plus an exposure score.
- **Phone number scan** — normalizes the number, detects likely country from the calling code, and generates direct lookup links (Google, Truecaller, Sync.me, WhatsApp) for manual verification.
- **Manual-check platforms** — Instagram, Facebook, X, LinkedIn, Snapchat, BeReal block automated scraping, so GhostTrace gives you pre-filled direct links instead of pretending to auto-verify them.
- **Exposure score** — a 0–100% score based on how many platforms return a match, with a live animated ring.
- **Scan history** — your last 6 scans are kept locally in your browser (never sent to a server) so you can re-run them in one click.
- **Export report** — download a plain-text investigation summary of any scan.

## Why it exists

Built as a hands-on project alongside a cybersecurity / junior pentester internship, to practice:
- Reconnaissance / OSINT methodology
- Concurrent HTTP requests and rate-limit-aware scraping (`ThreadPoolExecutor`)
- Flask REST API design
- Frontend/backend contract design (JSON response shapes)

## Tech stack

| Layer      | Tech                                  |
|------------|----------------------------------------|
| Backend    | Python, Flask, Gunicorn                |
| Scanning   | `requests`, `concurrent.futures`       |
| Frontend   | Vanilla HTML/CSS/JS (no framework)     |
| Hosting    | Render.com (free tier)                 |

No database. No accounts. No data stored server-side — everything except scan history (which lives only in your browser's `localStorage`) is stateless.

## Running it locally

```bash
git clone https://github.com/reboot-phoenix/ghosttrace.git
cd ghosttrace
pip install -r requirements.txt
python app.py
```

Then open `http://localhost:5000`.

## API

### `GET /health`
Returns service status.

### `POST /detect`
```json
{ "query": "ashtid123" }
```
Returns the auto-detected input type (`username`, `email`, `phone`, `ip`, `url`, `domain`, `hash_md5`, `hash_sha1`, `hash_sha256`, or `unknown`).

### `POST /scan`
```json
{ "type": "username", "query": "ashtid123" }
```
Returns:
```json
{
  "success": true,
  "query": "ashtid123",
  "type": "username",
  "score": 47,
  "summary": { "found": 7, "checked": 15, "manual": 6, "level": "Medium" },
  "results": [ { "platform": "GitHub", "url": "...", "status": "found", "type": "auto" } ]
}
```

## Project structure

```
ghosttrace/
├── app.py                 # Flask routes: /, /health, /detect, /scan
├── detector.py             # Regex-based input type detection
├── checker.py               # Dispatches scan_type -> module
├── config.py
├── modules/
│   ├── username.py         # Concurrent platform checker + exposure score
│   └── phone.py             # Phone normalization + lookup links
├── templates/
│   └── index.html
├── static/
│   ├── css/style.css
│   └── js/app.js
└── requirements.txt
```

## ⚠️ Ethical use

GhostTrace only aggregates information that platforms already expose publicly (whether a username exists). It does not bypass authentication, scrape private data, or store anything server-side. Use it to audit **your own** digital footprint, or accounts you have explicit permission to investigate. Don't use it to stalk, harass, or deanonymize people without consent.

## Known limitations

- Platform detection relies on string-matching each site's "not found" page text, which can break silently if a platform changes its 404 page copy.
- No caching/rate-limiting yet — rapid repeated scans could get your server IP soft-blocked by some platforms.
- Free-tier Render hosting cold-starts after ~15 minutes idle; first request can take 30–50 seconds.

## Roadmap

- [ ] Add email and IP scan types (detector already recognizes them, no scanner module yet)
- [ ] Cache results for a short TTL to avoid re-hitting platforms on repeat scans
- [ ] Add a lightweight rate limiter on `/scan`
- [ ] Swap string-matching "not found" checks for status-code + selector based checks where platforms support it

---

Built by **Ashtid** — BSc IT, Techno India University.
