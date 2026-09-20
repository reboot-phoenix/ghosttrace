import time
from collections import defaultdict, deque

from flask import Flask, render_template, request, jsonify

from checker import scan
from detector import detect_input

app = Flask(__name__)

# ----------------------------------------
# Rate limiting (in-memory, per-IP)
# ----------------------------------------
# In-memory is fine because Render runs this with a single worker
# (WEB_CONCURRENCY=1). If that ever changes, swap _request_log for
# a Redis-backed store (e.g. flask-limiter + redis://).
# TODO: move to flask-limiter + Redis if scaling beyond 1 worker

RATE_LIMIT_MAX = 15          # max scans
RATE_LIMIT_WINDOW = 3600     # per hour (seconds)

MAX_QUERY_LENGTH = 200        # reject absurdly long inputs early

_request_log = defaultdict(deque)


def _client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_rate_limited(ip):
    now = time.time()
    log = _request_log[ip]

    while log and now - log[0] > RATE_LIMIT_WINDOW:
        log.popleft()

    if len(log) >= RATE_LIMIT_MAX:
        return True, log[0]

    log.append(now)
    return False, None


# ----------------------------------------
# Home
# ----------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# ----------------------------------------
# Health Check
# ----------------------------------------

@app.route("/health")
def health():
    return jsonify({
        "status": "online",
        "service": "GhostTrace",
        "version": "2.0"
    })


# ----------------------------------------
# Detect Input
# ----------------------------------------

@app.route("/detect", methods=["POST"])
def detect():
    data = request.get_json(silent=True) or {}
    query = data.get("query", "").strip()

    if not query:
        return jsonify({"success": False, "error": "No input provided."}), 400

    if len(query) > MAX_QUERY_LENGTH:
        return jsonify({
            "success": False,
            "error": f"Input too long (max {MAX_QUERY_LENGTH} characters)."
        }), 400

    detected = detect_input(query)

    return jsonify({
        "success": True,
        "query": query,
        "detected": detected
    })


# ----------------------------------------
# Scan
# ----------------------------------------

SUPPORTED_TYPES = {"name", "email", "phone", "username"}


@app.route("/scan", methods=["POST"])
def scan_api():

    ip = _client_ip()
    limited, oldest = is_rate_limited(ip)

    if limited:
        retry_after = int(RATE_LIMIT_WINDOW - (time.time() - oldest))
        response = jsonify({
            "success": False,
            "error": (
                f"Rate limit reached ({RATE_LIMIT_MAX} scans/hour). "
                f"Try again in about {max(retry_after // 60, 1)} minute(s)."
            )
        })
        response.status_code = 429
        response.headers["Retry-After"] = str(max(retry_after, 1))
        return response

    data = request.get_json(silent=True) or {}
    query = data.get("query", "").strip()
    scan_type = data.get("type", "auto")

    if not query:
        return jsonify({
            "success": False,
            "error": "Please enter something to investigate."
        }), 400

    if len(query) > MAX_QUERY_LENGTH:
        return jsonify({
            "success": False,
            "error": f"Input too long (max {MAX_QUERY_LENGTH} characters)."
        }), 400

    if scan_type == "auto":
        scan_type = detect_input(query)

    # Reject types the scanner doesn't handle (ip, url, domain, hash_*, unknown)
    if scan_type not in SUPPORTED_TYPES:
        return jsonify({
            "success": False,
            "error": (
                f"Cannot scan input type '{scan_type}'. "
                f"Supported: {', '.join(sorted(SUPPORTED_TYPES))}."
            )
        }), 400

    try:
        results, score, summary = scan(scan_type, query)
        return jsonify({
            "success": True,
            "query": query,
            "type": scan_type,
            "score": score,
            "summary": summary,
            "results": results
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ----------------------------------------
# 404
# ----------------------------------------

@app.errorhandler(404)
def page_not_found(error):
    return jsonify({
        "success": False,
        "error": "Endpoint not found."
    }), 404


# ----------------------------------------
# Run
# ----------------------------------------

if __name__ == "__main__":
    # debug=True is fine locally; Render uses gunicorn (start command),
    # so this block never runs in production.
    app.run(host="0.0.0.0", port=5000, debug=True)
