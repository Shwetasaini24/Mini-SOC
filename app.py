"""
Mini SOC (Security Operations Center) - Flask Backend
Author: Senior Cybersecurity Engineer
Description: Real-time log monitoring and threat detection system
"""

import os
import re
import json
import random
import sqlite3
import hashlib
import threading
import time
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session, flash, g
)
from werkzeug.utils import secure_filename
from functools import wraps

# ─── App Configuration ────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "soc-secret-key-change-in-production")

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR  = os.path.join(BASE_DIR, "uploads")
DATABASE    = os.path.join(BASE_DIR, "instance", "soc.db")
ALLOWED_EXT = {"txt", "log"}

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

# ─── Threat Detection Thresholds ─────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5     # failed attempts before brute-force alert
SCAN_THRESHOLD        = 20    # requests/IP before port-scan alert
HIGH_ERROR_THRESHOLD  = 10    # 4xx/5xx count before suspicious-activity alert

# ─── Live Simulation State ────────────────────────────────────────────────────
simulation_active = False
simulation_thread = None

# ─── Database Helpers ─────────────────────────────────────────────────────────

def get_db():
    """Open a per-request DB connection stored on Flask's 'g' object."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db:
        db.close()

def query_db(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rv  = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(sql, args=()):
    db = get_db()
    db.execute(sql, args)
    db.commit()

def init_db():
    """Create all tables if they don't exist."""
    with sqlite3.connect(DATABASE) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    UNIQUE NOT NULL,
                password TEXT    NOT NULL,
                created  TEXT    DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS logs (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address   TEXT,
                timestamp    TEXT,
                method       TEXT,
                path         TEXT,
                status_code  INTEGER,
                response_size INTEGER,
                raw_line     TEXT,
                severity     TEXT DEFAULT 'LOW',
                created_at   TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS threats (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_type TEXT,
                ip_address  TEXT,
                description TEXT,
                severity    TEXT DEFAULT 'MEDIUM',
                count       INTEGER DEFAULT 1,
                detected_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS stats (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                total_logs    INTEGER DEFAULT 0,
                total_threats INTEGER DEFAULT 0,
                last_updated  TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)
        # Seed default admin user  (password: admin123)
        pw_hash = hashlib.sha256("admin123".encode()).hexdigest()
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
            ("admin", pw_hash)
        )
        conn.commit()

# ─── Auth Helpers ─────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ─── Log Parser ───────────────────────────────────────────────────────────────

# Apache Combined Log Format pattern
APACHE_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\d+|-)'
)

# Generic failed-login pattern (syslog / auth.log style)
FAILEDLOGIN_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*(?:Failed password|authentication failure|Invalid user)',
    re.IGNORECASE
)

def parse_log_line(line):
    """
    Try to parse a log line using Apache format first,
    then fall back to generic failed-login detection.
    Returns a dict or None.
    """
    line = line.strip()
    if not line:
        return None

    m = APACHE_PATTERN.match(line)
    if m:
        status = int(m.group("status"))
        size   = int(m.group("size")) if m.group("size") != "-" else 0
        return {
            "ip_address":    m.group("ip"),
            "timestamp":     m.group("timestamp"),
            "method":        m.group("method"),
            "path":          m.group("path"),
            "status_code":   status,
            "response_size": size,
            "raw_line":      line,
            "severity":      classify_severity(status),
        }

    m = FAILEDLOGIN_PATTERN.search(line)
    if m:
        return {
            "ip_address":    m.group("ip"),
            "timestamp":     datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000"),
            "method":        "AUTH",
            "path":          "/login",
            "status_code":   401,
            "response_size": 0,
            "raw_line":      line,
            "severity":      "HIGH",
        }

    return None


def classify_severity(status_code):
    """Map HTTP status code to threat severity."""
    if status_code in (200, 201, 204, 301, 302, 304):
        return "LOW"
    if status_code in (400, 403, 404, 405, 408):
        return "MEDIUM"
    if status_code >= 500 or status_code == 401:
        return "HIGH"
    return "LOW"


# ─── Threat Detection ─────────────────────────────────────────────────────────

def detect_threats():
    """
    Analyse recently stored logs for threat patterns.
    Writes detected threats to the threats table.
    """
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row

        # --- Brute Force: 5+ 401s from same IP ---
        rows = conn.execute("""
            SELECT ip_address, COUNT(*) AS cnt
            FROM logs
            WHERE status_code = 401
            GROUP BY ip_address
            HAVING cnt >= ?
        """, (BRUTE_FORCE_THRESHOLD,)).fetchall()

        for row in rows:
            existing = conn.execute(
                "SELECT id FROM threats WHERE threat_type='BRUTE_FORCE' AND ip_address=?",
                (row["ip_address"],)
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE threats SET count=?, detected_at=CURRENT_TIMESTAMP WHERE id=?",
                    (row["cnt"], existing["id"])
                )
            else:
                conn.execute(
                    "INSERT INTO threats (threat_type, ip_address, description, severity, count) VALUES (?,?,?,?,?)",
                    ("BRUTE_FORCE", row["ip_address"],
                     f"Brute force detected: {row['cnt']} failed auth attempts",
                     "HIGH", row["cnt"])
                )

        # --- HTTP Error Flood: 10+ 4xx/5xx from same IP ---
        rows = conn.execute("""
            SELECT ip_address, COUNT(*) AS cnt
            FROM logs
            WHERE status_code >= 400
            GROUP BY ip_address
            HAVING cnt >= ?
        """, (HIGH_ERROR_THRESHOLD,)).fetchall()

        for row in rows:
            existing = conn.execute(
                "SELECT id FROM threats WHERE threat_type='HTTP_FLOOD' AND ip_address=?",
                (row["ip_address"],)
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE threats SET count=?, detected_at=CURRENT_TIMESTAMP WHERE id=?",
                    (row["cnt"], existing["id"])
                )
            else:
                conn.execute(
                    "INSERT INTO threats (threat_type, ip_address, description, severity, count) VALUES (?,?,?,?,?)",
                    ("HTTP_FLOOD", row["ip_address"],
                     f"HTTP error flood: {row['cnt']} 4xx/5xx responses",
                     "MEDIUM", row["cnt"])
                )

        # --- Port/Path Scan: 20+ distinct paths from same IP ---
        rows = conn.execute("""
            SELECT ip_address, COUNT(DISTINCT path) AS cnt
            FROM logs
            GROUP BY ip_address
            HAVING cnt >= ?
        """, (SCAN_THRESHOLD,)).fetchall()

        for row in rows:
            existing = conn.execute(
                "SELECT id FROM threats WHERE threat_type='PATH_SCAN' AND ip_address=?",
                (row["ip_address"],)
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE threats SET count=?, detected_at=CURRENT_TIMESTAMP WHERE id=?",
                    (row["cnt"], existing["id"])
                )
            else:
                conn.execute(
                    "INSERT INTO threats (threat_type, ip_address, description, severity, count) VALUES (?,?,?,?,?)",
                    ("PATH_SCAN", row["ip_address"],
                     f"Path scan detected: {row['cnt']} unique paths probed",
                     "HIGH", row["cnt"])
                )

        conn.commit()


# ─── Live Simulation ──────────────────────────────────────────────────────────

FAKE_IPS   = [f"192.168.{random.randint(0,5)}.{random.randint(1,254)}" for _ in range(12)]
FAKE_PATHS = ["/login", "/admin", "/wp-admin", "/api/v1/users", "/", "/index.php",
              "/.env", "/config.php", "/phpmyadmin", "/shell.php", "/backup.zip"]
FAKE_METHODS = ["GET", "POST", "PUT", "DELETE"]
FAKE_STATUSES = [200, 200, 200, 301, 400, 401, 401, 403, 404, 500, 502]

def simulation_worker():
    """Background thread that inserts fake log entries every 2 seconds."""
    global simulation_active
    while simulation_active:
        ip     = random.choice(FAKE_IPS)
        path   = random.choice(FAKE_PATHS)
        method = random.choice(FAKE_METHODS)
        status = random.choice(FAKE_STATUSES)
        ts     = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        size   = random.randint(100, 5000)

        with sqlite3.connect(DATABASE) as conn:
            conn.execute("""
                INSERT INTO logs (ip_address, timestamp, method, path, status_code, response_size, raw_line, severity)
                VALUES (?,?,?,?,?,?,?,?)
            """, (ip, ts, method, path, status, size,
                  f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size}',
                  classify_severity(status)))
            conn.commit()

        # Run threat detection every 10 simulated entries
        if random.random() < 0.1:
            detect_threats()

        time.sleep(2)


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        pw_hash  = hashlib.sha256(password.encode()).hexdigest()

        with sqlite3.connect(DATABASE) as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username=? AND password=?",
                (username, pw_hash)
            ).fetchone()

        if user:
            session["user_id"]  = user[0]
            session["username"] = user[1]
            return redirect(url_for("dashboard"))
        flash("Invalid credentials. Default: admin / admin123", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session.get("username"))


# ─── API Endpoints ────────────────────────────────────────────────────────────

@app.route("/api/stats")
@login_required
def api_stats():
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        total_logs    = conn.execute("SELECT COUNT(*) AS c FROM logs").fetchone()["c"]
        total_threats = conn.execute("SELECT COUNT(*) AS c FROM threats").fetchone()["c"]
        high_sev      = conn.execute("SELECT COUNT(*) AS c FROM logs WHERE severity='HIGH'").fetchone()["c"]
        med_sev       = conn.execute("SELECT COUNT(*) AS c FROM logs WHERE severity='MEDIUM'").fetchone()["c"]

        # Top attacking IPs (by total requests)
        top_ips = conn.execute("""
            SELECT ip_address, COUNT(*) AS cnt
            FROM logs
            GROUP BY ip_address
            ORDER BY cnt DESC
            LIMIT 10
        """).fetchall()

        # Status code distribution
        status_dist = conn.execute("""
            SELECT status_code, COUNT(*) AS cnt
            FROM logs
            GROUP BY status_code
            ORDER BY cnt DESC
            LIMIT 10
        """).fetchall()

        # Hourly log volume (last 24 h)
        hourly = conn.execute("""
            SELECT strftime('%H:00', created_at) AS hour, COUNT(*) AS cnt
            FROM logs
            WHERE created_at >= datetime('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour
        """).fetchall()

        # Recent threats
        recent_threats = conn.execute("""
            SELECT * FROM threats
            ORDER BY detected_at DESC
            LIMIT 20
        """).fetchall()

    return jsonify({
        "total_logs":    total_logs,
        "total_threats": total_threats,
        "high_severity": high_sev,
        "med_severity":  med_sev,
        "top_ips":       [dict(r) for r in top_ips],
        "status_dist":   [dict(r) for r in status_dist],
        "hourly":        [dict(r) for r in hourly],
        "threats":       [dict(r) for r in recent_threats],
        "sim_active":    simulation_active,
    })


@app.route("/api/logs")
@login_required
def api_logs():
    page     = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    severity = request.args.get("severity", "")
    offset   = (page - 1) * per_page

    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        if severity:
            rows = conn.execute(
                "SELECT * FROM logs WHERE severity=? ORDER BY id DESC LIMIT ? OFFSET ?",
                (severity.upper(), per_page, offset)
            ).fetchall()
            total = conn.execute(
                "SELECT COUNT(*) AS c FROM logs WHERE severity=?",
                (severity.upper(),)
            ).fetchone()["c"]
        else:
            rows  = conn.execute(
                "SELECT * FROM logs ORDER BY id DESC LIMIT ? OFFSET ?",
                (per_page, offset)
            ).fetchall()
            total = conn.execute("SELECT COUNT(*) AS c FROM logs").fetchone()["c"]

    return jsonify({
        "logs":  [dict(r) for r in rows],
        "total": total,
        "page":  page,
    })


@app.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    f = request.files["file"]
    if f.filename == "":
        return jsonify({"error": "No file selected"}), 400

    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in ALLOWED_EXT:
        return jsonify({"error": "Only .txt or .log files allowed"}), 400

    filename = secure_filename(f.filename)
    filepath = os.path.join(UPLOAD_DIR, filename)
    f.save(filepath)

    inserted = 0
    failed   = 0

    with sqlite3.connect(DATABASE) as conn:
        with open(filepath, "r", errors="ignore") as fh:
            for line in fh:
                parsed = parse_log_line(line)
                if parsed:
                    conn.execute("""
                        INSERT INTO logs
                          (ip_address, timestamp, method, path, status_code, response_size, raw_line, severity)
                        VALUES (?,?,?,?,?,?,?,?)
                    """, (
                        parsed["ip_address"], parsed["timestamp"],
                        parsed["method"],     parsed["path"],
                        parsed["status_code"],parsed["response_size"],
                        parsed["raw_line"],   parsed["severity"],
                    ))
                    inserted += 1
                else:
                    failed += 1
        conn.commit()

    # Run threat detection on the newly loaded data
    detect_threats()

    return jsonify({
        "success":  True,
        "inserted": inserted,
        "skipped":  failed,
        "message":  f"Parsed {inserted} log entries ({failed} lines skipped).",
    })


@app.route("/api/simulation/start", methods=["POST"])
@login_required
def start_simulation():
    global simulation_active, simulation_thread
    if not simulation_active:
        simulation_active = True
        simulation_thread = threading.Thread(target=simulation_worker, daemon=True)
        simulation_thread.start()
    return jsonify({"status": "started"})


@app.route("/api/simulation/stop", methods=["POST"])
@login_required
def stop_simulation():
    global simulation_active
    simulation_active = False
    return jsonify({"status": "stopped"})


@app.route("/api/clear", methods=["POST"])
@login_required
def clear_data():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute("DELETE FROM logs")
        conn.execute("DELETE FROM threats")
        conn.commit()
    return jsonify({"success": True})


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False)
