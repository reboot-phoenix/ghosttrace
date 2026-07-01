from flask import Flask, render_template, request, jsonify
from checker import check_username, check_phone

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    scan_type = data.get("type")
    query = data.get("query", "").strip()

    if not query:
        return jsonify({"error": "Please enter something to scan"})

    if scan_type == "username":
        results, score = check_username(query)
        return jsonify({
            "results": results,
            "score": score,
            "type": "username",
            "query": query
        })
    elif scan_type == "phone":
        results, score = check_phone(query)
        return jsonify({
            "results": results,
            "score": score,
            "type": "phone",
            "query": query
        })
    else:
        return jsonify({"error": "Invalid scan type"})

if __name__ == "__main__":
    app.run(debug=True)
