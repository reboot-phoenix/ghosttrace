from flask import Flask, render_template, request, jsonify

from checker import scan

from detector import detect_input

app = Flask(__name__)


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

    data = request.get_json()

    query = data.get("query", "").strip()

    if not query:

        return jsonify({

            "success": False,

            "error": "No input provided."

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

@app.route("/scan", methods=["POST"])
def scan_api():

    data = request.get_json()

    query = data.get("query", "").strip()

    scan_type = data.get("type", "auto")

    if not query:

        return jsonify({

            "success": False,

            "error": "Please enter something to investigate."

        }), 400

    if scan_type == "auto":

        scan_type = detect_input(query)

    try:

        results, score, summary = scan(

            scan_type,

            query

        )

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

    app.run(

        host="0.0.0.0",

        port=5000,

        debug=True

    )
