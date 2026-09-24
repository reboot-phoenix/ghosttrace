"""
app.py — GhostTrace v3 Flask application

Routes:
  GET  /              → index.html
  GET  /health        → status
  POST /detect        → input type detection
  POST /scan          → OSINT scan (main)
  GET  /ping          → keep-alive for free hosting

Rate limit: 20 scans/hour per IP (in-memory, resets on restart)
Note: swap to Redis-backed flask-limiter if scaling to multi-worker
"""

from __future__ import annotations
import time
import json
from collections import defaultdict, deque
from functools import wraps

from flask import Flask, request, jsonify, render_template

from detector import detect_input, SUPPORTED_TYPES
from modules.email import scan_email
from modules.username import scan_username
from modules.phone import scan_phone
from modules.name import scan_name
from modules.ip_domain import scan_ip, scan_domain
from config import RATE_LIMIT_MAX, RATE_LIMIT_WINDOW

app = Flask(__name__)

# ── In-memory rate limiter ────────────────────────────────────────────────────
_rate_store: dict[str, deque] = defaultdict(deque)

def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    dq  = _rate_store[ip]
    while dq and now - dq[0] > RATE_LIMIT_WINDOW:
        dq.popleft()
    if len(dq) >= RATE_LIMIT_MAX:
        return True
    dq.append(now)
    return False


def rate_limited(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
        if _is_rate_limited(ip):
            return jsonify({"error": "Rate limit: 20 scans/hour. Try again later."}), 429
        return fn(*args, **kwargs)
    return wrapper


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({"status": "online", "service": "GhostTrace", "version": "3.0"})


@app.route("/ping")
def ping():
    """Keep-alive endpoint — call every 10 min from a cron to prevent cold starts."""
    return "pong", 200


@app.route("/detect", methods=["POST"])
def detect():
    body = request.get_json(silent=True) or {}
    query = (body.get("query") or "").strip()
    if not query:
        return jsonify({"error": "No query provided"}), 400
    kind = detect_input(query)
    return jsonify({
        "type": kind,
        "supported": kind in SUPPORTED_TYPES,
        "query": query,
    })


@app.route("/scan", methods=["POST"])
@rate_limited
def scan():
    body = request.get_json(silent=True) or {}
    query     = (body.get("query") or "").strip()
    scan_type = (body.get("scan_type") or "").strip().lower()
    filters   = body.get("filters", [])   # for name scan only

    if not query:
        return jsonify({"error": "No query provided"}), 400

    # Auto-detect type if not supplied
    if not scan_type or scan_type == "auto":
        scan_type = detect_input(query)

    if scan_type not in SUPPORTED_TYPES:
        return jsonify({"error": f"Unsupported type: {scan_type}. Supported: {sorted(SUPPORTED_TYPES)}"}), 400

    try:
        if scan_type == "email":
            result = scan_email(query)
        elif scan_type == "username":
            result = scan_username(query)
        elif scan_type == "phone":
            result = scan_phone(query)
        elif scan_type == "name":
            result = scan_name(query, filters)
        elif scan_type == "ip":
            result = scan_ip(query)
        elif scan_type == "domain":
            result = scan_domain(query)
        else:
            return jsonify({"error": "Unknown scan type"}), 400
    except Exception as e:
        return jsonify({"error": f"Scan error: {str(e)}"}), 500

    result["scan_type"] = scan_type
    result["timestamp"] = int(time.time())
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
