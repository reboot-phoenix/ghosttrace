# 👻 GhostTrace

**Find out what the internet knows about you.**

GhostTrace is an OSINT tool that scans names, emails, and phone numbers across the web to reveal your digital footprint — the same recon a real attacker or recruiter could do manually, automated and in front of you first.

🔗 **Live app:** https://ghosttrace-iy8f.onrender.com/
📦 **Repo:** https://github.com/reboot-phoenix/ghosttrace

---

## Features

- **Name scan** — searches the web for public mentions with optional filters (college, location, company, job title). Prioritises social hits (LinkedIn, GitHub, Reddit, etc.)
- **Email scan** — Gravatar profile check, breach database lookup (which breaches the email appeared in), web search for public mentions, and manual deep-links to HIBP, LeakCheck, Epieos, and Hunter.io
- **Phone scan** — country detection, web search for public mentions, and direct lookup links (Truecaller, Sync.me, NumLookup, WhatsApp, Telegram)
- **Exposure score** — 0–100% score with a live animated ring
- **Scan history** — last 6 scans stored locally in your browser
- **Export report** — download a plain-text investigation summary

---

## Tech stack

| Layer    | Tech                                        |
|----------|---------------------------------------------|
| Backend  | Python, Flask, Gunicorn                     |
| Search   | SerpAPI → Google CSE → DuckDuckGo (fallback chain) |
| Breaches | LeakCheck Public API (free) + HIBP          |
| Frontend | Vanilla HTML/CSS/JS                         |
| Hosting  | Render.com (free tier)                      |

---

## Running locally

```bash
git clone https://github.com/reboot-phoenix/ghosttrace.git
cd ghosttrace
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`.

Optional env vars for full functionality:

```
GOOGLE_CSE_KEY   # Google API key (100 free queries/day — recommended)
GOOGLE_CSE_ID    # Your Programmable Search Engine ID
SERPAPI_KEY      # SerpAPI key (100 free searches/month)
HIBP_API_KEY     # HIBP paid key ($3.50/mo)
```

---

## ⚠️ Ethical use

GhostTrace only aggregates publicly accessible information. Use it to audit **your own** footprint, or accounts you have explicit permission to investigate. Do not use it to stalk, harass, or deanonymize people without consent.

---

Built by **Ashtid D.** — BSc IT, Techno India University
