from flask import Flask, render_template, request, jsonify
from checker import check_username, check_phone
from detector import detect_input

app = Flask(__name__)


# -----------------------------
# Scanner Registry
# -----------------------------

SCANNERS = {
    "username": check_username,
    "phone": check_phone,
}


# -----------------------------
# Home
# -----------------------------

@app.route("/")
def home():
    return render_template("index.html")


# -----------------------------
# Health Check
# -----------------------------

@app.route("/health")
def health():
    return jsonify({
        "status": "online",
        "version": "2.0",
        "service": "GhostTrace"
    })


# -----------------------------
# Auto Detect Input
# -----------------------------

@app.route("/detect", methods=["POST"])
def detect():

    data = request.get_json()

    query = data.get("query", "").strip()

    if not query:
        return jsonify({
            "success": False,
            "error": "Empty query."
        }), 400

    detected = detect_input(query)

    return jsonify({
        "success": True,
        "query": query,
        "detected": detected
    })


# -----------------------------
# Main Scan
# -----------------------------

@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json()

    query = data.get("query", "").strip()
    scan_type = data.get("type", "auto")

    if not query:
        return jsonify({
            "success": False,
            "error": "Please enter something to scan."
        }), 400

    # Automatic Detection
    if scan_type == "auto":
        scan_type = detect_input(query)

    if scan_type not in SCANNERS:
        return jsonify({
            "success": False,
            "error": f"No scanner available for '{scan_type}'."
        }), 400

    scanner = SCANNERS[scan_type]

    results, score = scanner(query)

    return jsonify({

        "success": True,

        "query": query,

        "type": scan_type,

        "score": score,

        "results": results

    })


# -----------------------------
# 404
# -----------------------------

@app.errorhandler(404)
def page_not_found(e):
    return jsonify({
        "success": False,
        "error": "Endpoint not found."
    }), 404


# -----------------------------
# Run
# -----------------------------

if __name__ == "__main__":
    app.run(debug=True)
