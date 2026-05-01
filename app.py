"""
NetGuard IDS - Flask Backend API
Run: python app.py
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from ids_engine import IDSEngine
from database import Database
import threading
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

db = Database(os.getenv("MONGO_URI", "mongodb://localhost:27017/netguard"))
ids = IDSEngine(db)

# ── Routes ──────────────────────────────────────────

@app.route("/api/status", methods=["GET"])
def status():
    return jsonify({
        "status": "running",
        "ml_enabled": ids.ml_enabled,
        "capturing": ids.capturing,
        "uptime": ids.get_uptime(),
        "total_packets": ids.total_packets,
        "total_attacks": ids.total_attacks,
        "blocked_ips": ids.blocked_count,
    })


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    limit = int(request.args.get("limit", 50))
    severity = request.args.get("severity")
    attack_type = request.args.get("type")
    src_ip = request.args.get("src_ip")

    alerts = db.get_alerts(
        limit=limit,
        severity=severity,
        attack_type=attack_type,
        src_ip=src_ip
    )
    return jsonify(alerts)


@app.route("/api/traffic", methods=["GET"])
def get_traffic():
    """Returns last 30 seconds of traffic data for charts."""
    return jsonify(ids.get_traffic_history())


@app.route("/api/stats", methods=["GET"])
def get_stats():
    return jsonify({
        "total_packets": ids.total_packets,
        "attacks_detected": ids.total_attacks,
        "blocked_count": ids.blocked_count,
        "uptime": ids.get_uptime(),
        "severity_counts": db.get_severity_counts(),
        "attack_type_counts": db.get_attack_type_counts(),
    })


@app.route("/api/block", methods=["POST"])
def block_ip():
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP required"}), 400
    ids.block_ip(ip)
    return jsonify({"success": True, "blocked_ip": ip})


@app.route("/api/settings", methods=["GET", "POST"])
def settings():
    if request.method == "GET":
        return jsonify({
            "ml_enabled": ids.ml_enabled,
            "deep_inspect": ids.deep_inspect,
            "auto_block": ids.auto_block,
            "threshold": ids.threshold,
        })
    data = request.get_json()
    if "ml_enabled" in data:
        ids.ml_enabled = data["ml_enabled"]
    if "deep_inspect" in data:
        ids.deep_inspect = data["deep_inspect"]
    if "auto_block" in data:
        ids.auto_block = data["auto_block"]
    if "threshold" in data:
        ids.threshold = int(data["threshold"])
    return jsonify({"success": True})


@app.route("/api/capture/start", methods=["POST"])
def start_capture():
    if not ids.capturing:
        t = threading.Thread(target=ids.start_capture, daemon=True)
        t.start()
    return jsonify({"capturing": True})


@app.route("/api/capture/stop", methods=["POST"])
def stop_capture():
    ids.stop_capture()
    return jsonify({"capturing": False})


# ── Main ─────────────────────────────────────────────

if __name__ == "__main__":
    print("🛡️  NetGuard IDS Backend starting...")
    # Auto-start capture in background
    t = threading.Thread(target=ids.start_capture, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5000, debug=False)
