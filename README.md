# 👻 GhostTrace

**Find out what the internet knows about you.**

GhostTrace is an OSINT recon tool that scans names, emails, phone numbers, and usernames across the web to reveal your digital footprint — the same recon a real attacker or recruiter would do manually, automated and in front of you first.

🔗 **Live app:** https://ghosttrace-iy8f.onrender.com/
📦 **Repo:** https://github.com/reboot-phoenix/ghosttrace

---

## Demo

> _Add a screenshot or GIF here — drag one into this file on GitHub_
> `![GhostTrace demo](assets/demo.png)`

---

## Features

| Feature | Description |
|---|---|
| **Name scan** | Web search with optional filters (college, location, company, job title). Prioritises social hits (LinkedIn, GitHub, Reddit, etc.) |
| **Email scan** | Gravatar profile check, breach database lookup, web search for public mentions, deep-links to HIBP / LeakCheck / Epieos / Hunter.io |
| **Phone scan** | Country detection, web search mentions, direct lookup links (Truecaller, Sync.me, NumLookup, WhatsApp, Telegram) |
| **Username scan** | Cross-platform username presence check |
| **Exposure score** | 0–100% score with a live animated ring |
| **Scan history** | Last 6 scans stored locally in your browser |
| **Export report** | Download a plain-text investigation summary |

---

## Tech Stack

| Layer | Tech |
|---|---|
| Backend | Python, Flask, Gunicorn |
| Search | SerpAPI → Google CSE → DuckDuckGo (fallback chain) |
| Breaches | LeakCheck Public API (free) + HIBP |
| Frontend | Vanilla HTML / CSS / JS |
| Hosting | Render.com (free tier) |

---

## Running Locally

```bash
git clone https://github.com/reboot-phoenix/ghosttrace.git
cd ghosttrace
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`.

### Optional environment variables

| Variable | Purpose |
|---|---|
| `GOOGLE_CSE_KEY` | Google API key (100 free queries/day — recommended) |
| `GOOGLE_CSE_ID` | Programmable Search Engine ID |
| `SERPAPI_KEY` | SerpAPI key (100 free searches/month) |
| `HIBP_API_KEY` | HIBP paid key ($3.50/mo) |

Create a `.env` file in the repo root or export them in your shell. The app degrades gracefully without them — DuckDuckGo is used as a fallback.

---

## API Reference

### `POST /detect`
Auto-detects input type.
```json
{ "query": "user@example.com" }
```
Returns: `{ "detected": "email", ... }`

### `POST /scan`
Runs a scan. `type` can be `auto`, `name`, `email`, `phone`, or `username`.
```json
{ "query": "Ashtid D.", "type": "name" }
```
Returns: `{ "score": 42, "summary": "...", "results": [...] }`

Rate limit: **15 scans / hour per IP**.

### `GET /health`
Returns service status and version.

---

## ⚠️ Ethical Use

GhostTrace only aggregates publicly accessible information. Use it to audit **your own** footprint, or accounts you have explicit permission to investigate. Do not use it to stalk, harass, or deanonymize people without consent.

---

## License

MIT — see [LICENSE](LICENSE).

---

Built by **Ashtid D.** · BSc IT, Techno India University · [LinkedIn](https://linkedin.com/in/ashtid-d)
