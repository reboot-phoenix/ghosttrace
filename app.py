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

from detector import detect_input, is_valid_for_type, SUPPORTED_TYPES
from modules.scam import assess as assess_scam
from modules.threat_feeds import check as check_feeds
from modules.page_analysis import analyze as analyze_page, first_seen
from modules import reports as report_db
from modules import feed_db, jobs
from modules.pipeline import run_scan
from modules.timeouts import ScanTimeout
from modules.web_mentions import scam_mentions
from modules.email    import scan_email
from modules.username import scan_username
from modules.phone    import scan_phone
from modules.name     import scan_name
from modules.ip_domain import scan_ip, scan_domain
from modules.correlate import correlate
from modules.report    import build_report
from modules.ai_brief  import generate_brief
from config import RATE_LIMIT_MAX, RATE_LIMIT_WINDOW

BRIEF_MAX_AGE_S      = 3600                     # signed scan results expire after 1 hour
BRIEF_RATE_LIMIT_MAX = 10                       # AI briefs per window per IP (costs money)
MAX_BODY_BYTES       = 1024 * 1024              # 1 MB request cap

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES

# Number of trusted reverse-proxy hops in front of the app (Railway/Fly = 1). 0 = none.
_TRUSTED_PROXIES = int(os.environ.get("TRUSTED_PROXIES", "1"))
if _TRUSTED_PROXIES > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_TRUSTED_PROXIES, x_proto=1, x_host=1)

_SIGNING_KEY = (os.environ.get("SCAN_SIGNING_KEY") or "").encode() or secrets.token_bytes(32)
if not os.environ.get("SCAN_SIGNING_KEY"):
    app.logger.warning("SCAN_SIGNING_KEY not set: AI-brief signatures reset on every restart")

feed_db.start_background_refresh()   # loads/refreshes the known-bad database off the request path

@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return resp

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
    try:
        feeds = feed_db.stats()
    except Exception:
        feeds = {}
    return jsonify({"status": "online", "service": "GhostTrace", "version": "3.1", "feeds": feeds})

@app.route("/ping")
def ping():
    return "pong", 200

@app.route("/detect", methods=["POST"])
@rate_limited("detect", 120)
def detect():
    body  = request.get_json(silent=True) or {}
    query = (body.get("query") or "").strip()
    if not query:
        return jsonify({"error": "No query provided"}), 400
    kind = detect_input(query)
    return jsonify({"type": kind, "supported": kind in SUPPORTED_TYPES, "query": query})

def _scanners() -> dict:
    """Looked up at call time so tests can patch app.scan_* functions."""
    return {"email": scan_email, "username": scan_username, "phone": scan_phone,
            "name": scan_name, "ip": scan_ip, "domain": scan_domain}


def _prepare(body: dict):
    """Validate a scan request. Returns (params, None) or (None, error_response)."""
    query     = (body.get("query") or "").strip()
    scan_type = (body.get("scan_type") or "").strip().lower()
    filters   = body.get("filters", [])
    mode      = (body.get("mode") or "fast").strip().lower()
    if mode not in ("fast", "deep"):
        mode = "fast"
    if not isinstance(filters, list):
        filters = []
    filters = [str(f)[:60] for f in filters[:5]]

    if not query:
        return None, (jsonify({"error": "No query provided"}), 400)
    if len(query) > 320:
        return None, (jsonify({"error": "Query too long"}), 400)
    if not scan_type or scan_type == "auto":
        scan_type = detect_input(query)

    # A pasted URL is scanned as its domain, but the full URL is kept for scam analysis
    original_url = None
    if scan_type == "url":
        host = urlparse(query).hostname
        if host:
            original_url = query
            query, scan_type = host, "domain"

    if scan_type not in SUPPORTED_TYPES:
        return None, (jsonify({"error": f"Unsupported type: {scan_type}. Supported: {sorted(SUPPORTED_TYPES)}"}), 400)
    # Never trust a client-supplied scan_type: the value must actually match it
    if not is_valid_for_type(scan_type, query):
        return None, (jsonify({"error": f"Query is not a valid {scan_type}"}), 400)
    return {"query": query, "scan_type": scan_type, "mode": mode,
            "filters": filters, "original_url": original_url}, None


@app.route("/scan", methods=["POST"])
@rate_limited("scan")
def scan():
    params, err = _prepare(request.get_json(silent=True) or {})
    if err:
        return err
    try:
        payload = run_scan(params, _scanners(), _sign)
        return jsonify(payload)
    except ScanTimeout as e:
        return jsonify({"error": str(e)}), 504
    except Exception:
        app.logger.exception("scan failed (type=%s)", params["scan_type"])
        return jsonify({"error": "Scan failed. Please try again."}), 500

@app.route("/scan/start", methods=["POST"])
@rate_limited("scan")
def scan_start():
    params, err = _prepare(request.get_json(silent=True) or {})
    if err:
        return err
    scanners = _scanners()
    try:
        jid = jobs.submit(lambda progress: run_scan(params, scanners, _sign, progress),
                          request.remote_addr or "unknown")
    except jobs.Busy as e:
        return jsonify({"error": str(e)}), e.code
    return jsonify({"job_id": jid, "type": params["scan_type"]}), 202

@app.route("/scan/status/<job_id>")
@rate_limited("scan-status", 1800)
def scan_status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Unknown or expired job"}), 404
    return jsonify(job)

@app.route("/report", methods=["POST"])
@rate_limited("report", 10)
def report_scam():
    body = request.get_json(silent=True) or {}
    kind = (body.get("kind") or "").strip().lower()
    value = (body.get("value") or "").strip()
    category = (body.get("category") or "other").strip().lower()
    if kind not in ("phone", "upi", "email", "domain") or not value or len(value) > 320:
        return jsonify({"error": "Invalid report"}), 400
    if not is_valid_for_type(kind, value):
        return jsonify({"error": f"Not a valid {kind}"}), 400
    try:
        res = report_db.add_report(kind, value, category, request.remote_addr or "unknown")
    except Exception:
        app.logger.exception("report failed")
        return jsonify({"error": "Could not save report"}), 500
    if res["status"] == "limit":
        return jsonify({"error": "Daily report limit reached"}), 429
    return jsonify(res)

@app.route("/brief", methods=["POST"])
@rate_limited("brief", BRIEF_RATE_LIMIT_MAX)
def brief():
    body = request.get_json(silent=True) or {}
    scan_result = body.get("scan_result")
    if not isinstance(scan_result, dict) or not scan_result:
        return jsonify({"error": "No scan_result provided"}), 400
    if not _verify(scan_result):
        return jsonify({"error": "Scan result is invalid or expired. Re-run the scan, then generate the brief."}), 400
    ts = scan_result.get("timestamp")
    if not isinstance(ts, (int, float)) or time.time() - ts > BRIEF_MAX_AGE_S:
        return jsonify({"error": "Scan result expired. Re-run the scan, then generate the brief."}), 400
    try:
        return jsonify(generate_brief(scan_result))
    except Exception:
        app.logger.exception("brief failed")
        return jsonify({"error": "Brief generation failed.", "brief": None, "generated": False}), 500

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=int(os.environ.get("PORT", 5000)))
