"""
api_server.py - REST API bridge for the Windows Dashboard UI.
Runs on Kali alongside the detection engine.
Exposes baseline.db data over HTTP so the Windows dashboard can query it.

Usage:
    pip install flask flask-cors
    python api_server.py --db-path baseline.db --port 5000
"""

import argparse
import sqlite3
from pathlib import Path
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests from the Windows browser

DB_PATH = "baseline.db"


def get_db():
    """Opens a read-only connection to the SQLite database."""
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/api/stats")
def get_stats():
    """Summary statistics for the Overview dashboard card."""
    conn = get_db()
    try:
        total_alerts  = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        high_sev      = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='High'").fetchone()[0]
        medium_sev    = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='Medium'").fetchone()[0]
        low_sev       = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='Low'").fetchone()[0]
        known_aps     = conn.execute("SELECT COUNT(*) FROM known_aps").fetchone()[0]
        known_clients = conn.execute("SELECT COUNT(*) FROM known_clients").fetchone()[0]
        alert_types   = conn.execute(
            "SELECT anomaly_type, COUNT(*) as count FROM alerts GROUP BY anomaly_type ORDER BY count DESC"
        ).fetchall()
        return jsonify({
            "total_alerts":   total_alerts,
            "high_severity":  high_sev,
            "medium_severity": medium_sev,
            "low_severity":   low_sev,
            "known_aps":      known_aps,
            "known_clients":  known_clients,
            "alert_types":    [dict(r) for r in alert_types],
        })
    finally:
        conn.close()


@app.route("/api/alerts")
def get_alerts():
    """All alerts, newest first. Supports ?limit= and ?severity= query params."""
    limit    = request.args.get("limit", 200, type=int)
    severity = request.args.get("severity", None)
    conn = get_db()
    try:
        if severity:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE severity=? ORDER BY timestamp DESC LIMIT ?",
                (severity, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/timeline")
def get_timeline():
    """All alerts sorted chronologically for the Timeline view."""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp ASC LIMIT 500"
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/baseline/aps")
def get_known_aps():
    """All known access points from the baseline."""
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM known_aps ORDER BY last_seen DESC").fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/baseline/clients")
def get_known_clients():
    """All known clients from the baseline."""
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM known_clients ORDER BY last_seen DESC").fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/health")
def health():
    """Simple health check so the dashboard can verify connectivity."""
    return jsonify({"status": "ok", "db": DB_PATH})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wireless Forensics API Server")
    parser.add_argument("--db-path", default="baseline.db", help="Path to the SQLite baseline database")
    parser.add_argument("--port",    type=int, default=5000,  help="Port to run on")
    parser.add_argument("--host",    default="0.0.0.0",       help="Host to bind to")
    args = parser.parse_args()

    DB_PATH = args.db_path
    if not Path(DB_PATH).exists():
        print(f"[WARNING] Database not found at '{DB_PATH}'. Run main.py --learn first.")

    print(f"[*] API server starting on http://{args.host}:{args.port}")
    print(f"[*] Reading from: {DB_PATH}")
    app.run(host=args.host, port=args.port, debug=False)
