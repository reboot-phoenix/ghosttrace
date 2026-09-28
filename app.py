"""
app.py — GhostTrace v3 Flask application

Routes:
  GET  /              → index.html
  GET  /health        → status
  POST /detect        → input type detection
  POST /scan          → OSINT scan (fast or deep)
  POST /brief         → AI intelligence brief
  GET  /ping          → keep-alive

scan modes:
  fast  — scan only, no correlation (default, ~15-30s)
  deep  — scan + correlation + pivot analysis (~60-120s)
"""

from __future__ import annotations
import time
from collections import defaultdict, deque
from functools import wraps

from flask import Flask, request, jsonify, render_template

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

app = Flask(__name__)

# ── Rate limiter ──────────────────────────────────────────────────────────────
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
@rate_limited
def scan():
    body      = request.get_json(silent=True) or {}
    query     = (body.get("query") or "").strip()
    scan_type = (body.get("scan_type") or "").strip().lower()
    filters   = body.get("filters", [])
    mode      = (body.get("mode") or "fast").strip().lower()  # "fast" or "deep"

    if not query:
        return jsonify({"error": "No query provided"}), 400
    if not scan_type or scan_type == "auto":
        scan_type = detect_input(query)
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

        # ── Correlation + report (fast always runs basic, deep runs full) ──
        correlation = correlate(raw)
        report      = build_report(raw, correlation, scan_mode=mode)

        # Return everything
        return jsonify({
            **raw,
            "correlation": correlation,
            "report":      report,
        })

    except Exception as e:
        return jsonify({"error": f"Scan error: {str(e)}"}), 500

@app.route("/brief", methods=["POST"])
@rate_limited
def brief():
    body = request.get_json(silent=True) or {}
    scan_result = body.get("scan_result", {})
    if not scan_result:
        return jsonify({"error": "No scan_result provided"}), 400
    result = generate_brief(scan_result)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
