"""
app.py — GhostTrace v3 Flask application

Routes:
  GET  /              → index.html
  GET  /health        → status
  POST /detect        → input type detection
  POST /scan          → OSINT scan (fast or deep)
  POST /brief         → AI intelligence brief (accepts only server-signed scan results)
  GET  /ping          → keep-alive

scan modes:
  fast  — scan + identity extraction, no extra network pivots (default)
  deep  — fast + correlation pivots + social profile pivoting (IG/FB/X/TikTok candidates)

Security notes:
  - Client IP comes from ProxyFix (TRUSTED_PROXIES hops), never from a raw client header.
  - /brief only accepts scan results this server signed (HMAC), so it can't be used as an
    open prompt proxy to the Anthropic key. Set SCAN_SIGNING_KEY to keep signatures valid
    across restarts.
"""

from __future__ import annotations
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, request, jsonify, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

from detector import detect_input, SUPPORTED_TYPES
from modules.email    import scan_email
from modules.username import scan_username
from modules.phone    import scan_phone
from modules.name     import scan_name
from modules.ip_domain import scan_ip, scan_domain
from modules.correlate import correlate
from modules.report    import build_report
from modules.ai_brief  import generate_brief
from config import RATE_LIMIT_MAX, RATE_LIMIT_WINDOW

BRIEF_RATE_LIMIT_MAX = 10                       # AI briefs per window per IP (costs money)
MAX_BODY_BYTES       = 1024 * 1024              # 1 MB request cap

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES

# Number of trusted reverse-proxy hops in front of the app (Railway/Fly = 1). 0 = none.
_TRUSTED_PROXIES = int(os.environ.get("TRUSTED_PROXIES", "1"))
if _TRUSTED_PROXIES > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_TRUSTED_PROXIES, x_proto=1, x_host=1)

_SIGNING_KEY = (os.environ.get("SCAN_SIGNING_KEY") or "").encode() or secrets.token_bytes(32)

# ── Rate limiter ──────────────────────────────────────────────────────────────
_rate_store: dict[tuple[str, str], deque] = defaultdict(deque)
_rate_lock  = threading.Lock()
_last_purge = 0.0
_PURGE_EVERY = 300  # seconds

def _purge_expired(now: float) -> None:
    """Drop idle IPs so the store can't grow without bound. Caller holds the lock."""
    global _last_purge
    if now - _last_purge < _PURGE_EVERY:
        return
    _last_purge = now
    for key in [k for k, dq in _rate_store.items() if not dq or now - dq[-1] > RATE_LIMIT_WINDOW]:
        del _rate_store[key]

def _is_rate_limited(ip: str, bucket: str = "scan", limit: int | None = None) -> bool:
    limit = RATE_LIMIT_MAX if limit is None else limit
    now = time.time()
    with _rate_lock:
        _purge_expired(now)
        dq = _rate_store[(bucket, ip)]
        while dq and now - dq[0] > RATE_LIMIT_WINDOW:
            dq.popleft()
        if len(dq) >= limit:
            return True
        dq.append(now)
        return False

def rate_limited(bucket: str = "scan", limit: int | None = None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr or "unknown"   # already resolved by ProxyFix
            if _is_rate_limited(ip, bucket, limit):
                max_n = RATE_LIMIT_MAX if limit is None else limit
                return jsonify({"error": f"Rate limit: {max_n} {bucket}s/hour. Try again later."}), 429
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ── Result signing (so /brief only trusts results this server produced) ───────
def _canon(obj):
    """Normalise so Python and JS JSON round-trips hash identically (e.g. 20.0 vs 20)."""
    if isinstance(obj, float) and obj.is_integer():
        return int(obj)
    if isinstance(obj, dict):
        return {str(k): _canon(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_canon(v) for v in obj]
    return obj

def _sign(payload: dict) -> str:
    blob = json.dumps(_canon(payload), sort_keys=True, separators=(",", ":"), default=str)
    return hmac.new(_SIGNING_KEY, blob.encode(), hashlib.sha256).hexdigest()

def _verify(result: dict) -> bool:
    sig = result.get("_sig")
    if not isinstance(sig, str):
        return False
    payload = {k: v for k, v in result.items() if k != "_sig"}
    return hmac.compare_digest(sig, _sign(payload))

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/health")
def health():
    return jsonify({"status": "online", "service": "GhostTrace", "version": "3.0"})

@app.route("/ping")
def ping():
    return "pong", 200

@app.route("/detect", methods=["POST"])
def detect():
    body  = request.get_json(silent=True) or {}
    query = (body.get("query") or "").strip()
    if not query:
        return jsonify({"error": "No query provided"}), 400
    kind = detect_input(query)
    return jsonify({"type": kind, "supported": kind in SUPPORTED_TYPES, "query": query})

@app.route("/scan", methods=["POST"])
@rate_limited("scan")
def scan():
    body      = request.get_json(silent=True) or {}
    query     = (body.get("query") or "").strip()
    scan_type = (body.get("scan_type") or "").strip().lower()
    filters   = body.get("filters", [])
    mode      = (body.get("mode") or "fast").strip().lower()  # "fast" or "deep"
    if mode not in ("fast", "deep"):
        mode = "fast"
    if not isinstance(filters, list):
        filters = []
    filters = [str(f)[:60] for f in filters[:5]]

    if not query:
        return jsonify({"error": "No query provided"}), 400
    if len(query) > 320:
        return jsonify({"error": "Query too long"}), 400
    if not scan_type or scan_type == "auto":
        scan_type = detect_input(query)

    # A pasted URL is scanned as its domain
    if scan_type == "url":
        host = urlparse(query).hostname
        if host:
            query, scan_type = host, "domain"

    if scan_type not in SUPPORTED_TYPES:
        return jsonify({"error": f"Unsupported type: {scan_type}. Supported: {sorted(SUPPORTED_TYPES)}"}), 400

    try:
        # ── Run the scan ──────────────────────────────────────────────────
        if scan_type == "email":    raw = scan_email(query)
        elif scan_type == "username": raw = scan_username(query)
        elif scan_type == "phone":  raw = scan_phone(query)
        elif scan_type == "name":   raw = scan_name(query, filters)
        elif scan_type == "ip":     raw = scan_ip(query)
        elif scan_type == "domain": raw = scan_domain(query)
        else: return jsonify({"error": "Unknown scan type"}), 400

        raw["scan_type"] = scan_type
        raw["timestamp"] = int(time.time())
        raw["mode"]      = mode

        # ── Correlation + report (deep adds network pivots + social pivoting) ──
        correlation = correlate(raw, deep=(mode == "deep"))
        report      = build_report(raw, correlation, scan_mode=mode)

        payload = {**raw, "correlation": correlation, "report": report}
        payload["_sig"] = _sign(payload)
        return jsonify(payload)

    except Exception:
        app.logger.exception("scan failed (type=%s)", scan_type)
        return jsonify({"error": "Scan failed. Please try again."}), 500

@app.route("/brief", methods=["POST"])
@rate_limited("brief", BRIEF_RATE_LIMIT_MAX)
def brief():
    body = request.get_json(silent=True) or {}
    scan_result = body.get("scan_result")
    if not isinstance(scan_result, dict) or not scan_result:
        return jsonify({"error": "No scan_result provided"}), 400
    if not _verify(scan_result):
        return jsonify({"error": "Scan result is invalid or expired. Re-run the scan, then generate the brief."}), 400
    try:
        return jsonify(generate_brief(scan_result))
    except Exception:
        app.logger.exception("brief failed")
        return jsonify({"error": "Brief generation failed.", "brief": None, "generated": False}), 500

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=int(os.environ.get("PORT", 5000)))
