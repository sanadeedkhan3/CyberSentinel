"""
dashboard/app.py
-----------------
Phase 6: Flask Dashboard with full authentication.
"""
import os, sys, time
from datetime import datetime
from flask import Flask, render_template, jsonify, request, session, redirect, url_for

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from db.database import get_connection, get_recent_alerts, get_packet_count
from dashboard.auth import (
    init_auth_db, authenticate, create_session, invalidate_session,
    validate_session, change_password, get_audit_log, login_required,
    get_current_user, cleanup_expired_sessions, SECRET_KEY
)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["JSON_SORT_KEYS"] = False


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    # Already logged in? Go to dashboard
    if validate_session(session.get("token")):
        return redirect(url_for("index"))

    if request.method == "GET":
        success_msg = request.args.get("success")
        return render_template("login.html", error=None, warning=None,
                               success=success_msg, must_change=False)

    username   = request.form.get("username", "").strip().lower()
    password   = request.form.get("password", "")
    ip         = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")

    ok, msg, user = authenticate(username, password, ip, user_agent)

    if not ok:
        return render_template("login.html", error=msg, warning=None,
                               success=None, must_change=False,
                               prefill_username=username)

    token = create_session(username, ip)
    session["token"] = token

    if user.get("must_change_password"):
        return render_template("login.html", error=None, warning=None,
                               success=None, must_change=True)

    return redirect(url_for("index"))


@app.route("/change-password", methods=["POST"])
def do_change_password():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    new_pw  = request.form.get("new_password", "")
    conf_pw = request.form.get("confirm_password", "")

    if new_pw != conf_pw:
        return render_template("login.html", error=None, warning=None,
                               success=None, must_change=True,
                               change_error="Passwords do not match.")

    ok, msg = change_password(user["username"], new_pw)
    if not ok:
        return render_template("login.html", error=None, warning=None,
                               success=None, must_change=True,
                               change_error=msg)

    return redirect(url_for("login", success="Password changed! Please sign in with your new password."))


@app.route("/logout")
def logout():
    token = session.pop("token", None)
    if token:
        invalidate_session(token)
    return redirect(url_for("login", success="You have been signed out securely."))


# ── Dashboard routes (protected) ──────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    cleanup_expired_sessions()
    return render_template("dashboard.html")


@app.route("/api/stats")
@login_required
def api_stats():
    conn = get_connection()
    total_packets = get_packet_count()
    total_alerts  = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    critical      = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='Critical'").fetchone()[0]
    high          = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='High'").fetchone()[0]
    devices       = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM traffic_windows").fetchone()[0]
    windows       = conn.execute("SELECT COUNT(*) FROM traffic_windows").fetchone()[0]
    conn.close()
    return jsonify({"total_packets": total_packets, "total_alerts": total_alerts,
                    "critical": critical, "high": high,
                    "devices": devices, "windows": windows})


@app.route("/api/alerts")
@login_required
def api_alerts():
    limit = int(request.args.get("limit", 20))
    hours = int(request.args.get("hours", 0))
    conn  = get_connection()

    if hours > 0:
        since = time.time() - hours * 3600
        rows  = conn.execute("""
            SELECT * FROM alerts WHERE timestamp >= ?
            ORDER BY timestamp DESC LIMIT ?
        """, (since, limit)).fetchall()
    else:
        rows = conn.execute("""
            SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?
        """, (limit,)).fetchall()
    conn.close()

    alerts = []
    for row in rows:
        a = dict(row)
        if a.get("timestamp"):
            a["time_str"] = datetime.fromtimestamp(a["timestamp"]).strftime("%H:%M:%S")
        a["severity"]           = a.get("severity")           or "Unknown"
        a["threat_type"]        = a.get("threat_type")        or "Anomalous Behavior"
        a["explanation"]        = a.get("explanation")        or "Analysis pending..."
        a["recommended_action"] = a.get("recommended_action") or "Monitor device."
        alerts.append(a)
    return jsonify(alerts)


@app.route("/api/traffic")
@login_required
def api_traffic():
    conn = get_connection()
    rows = conn.execute("""
        SELECT window_start, SUM(bytes_per_sec) as total_bps,
               SUM(packet_count) as total_pkts, COUNT(DISTINCT src_ip) as active_devices
        FROM traffic_windows
        GROUP BY ROUND(window_start / 30)
        ORDER BY window_start DESC LIMIT 20
    """).fetchall()
    conn.close()
    rows = list(reversed(rows))
    return jsonify({
        "labels" : [datetime.fromtimestamp(r["window_start"]).strftime("%H:%M:%S") for r in rows],
        "bytes"  : [round(r["total_bps"] / 1024, 2) for r in rows],
        "packets": [r["total_pkts"] for r in rows],
        "devices": [r["active_devices"] for r in rows],
    })


@app.route("/api/devices")
@login_required
def api_devices():
    conn = get_connection()
    rows = conn.execute("""
        SELECT b.src_ip, b.window_count, b.avg_bytes_per_sec,
               b.avg_unique_dst_ports, b.model_trained, MAX(tw.window_end) as last_seen
        FROM device_baselines b
        LEFT JOIN traffic_windows tw ON b.src_ip = tw.src_ip
        GROUP BY b.src_ip ORDER BY last_seen DESC
    """).fetchall()
    conn.close()
    devices = []
    for r in rows:
        d = dict(r)
        if d.get("last_seen"):
            d["last_seen_str"] = datetime.fromtimestamp(d["last_seen"]).strftime("%H:%M:%S")
        d["avg_bytes_per_sec"]    = round(d.get("avg_bytes_per_sec") or 0, 1)
        d["avg_unique_dst_ports"] = round(d.get("avg_unique_dst_ports") or 0, 1)
        devices.append(d)
    return jsonify(devices)


@app.route("/api/severity_counts")
@login_required
def api_severity_counts():
    conn = get_connection()
    rows = conn.execute("""
        SELECT severity, COUNT(*) as count FROM alerts
        WHERE severity IS NOT NULL GROUP BY severity
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/audit-log")
@login_required
def api_audit_log():
    return jsonify(get_audit_log(limit=30))


@app.route("/api/me")
@login_required
def api_me():
    user = get_current_user()
    return jsonify({"username": user["username"], "role": user["role"]})


def run_dashboard(port=5000, debug=False):
    init_auth_db()
    print(f"[DASHBOARD] Starting at http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=False)


@app.route("/api/change-password", methods=["POST"])
@login_required
def api_change_password():
    user = get_current_user()
    data = request.get_json()
    current  = data.get("current", "")
    new_pw   = data.get("new_password", "")
    confirm  = data.get("confirm", "")

    if new_pw != confirm:
        return jsonify({"ok": False, "error": "Passwords do not match."})

    # Verify current password
    from dashboard.auth import get_auth_conn, verify_password
    conn = get_auth_conn()
    row  = conn.execute("SELECT * FROM users WHERE username=?", (user["username"],)).fetchone()
    conn.close()
    if not verify_password(current, row["salt"], row["password_hash"]):
        return jsonify({"ok": False, "error": "Current password is incorrect."})

    ok, msg = change_password(user["username"], new_pw)
    return jsonify({"ok": ok, "error": msg if not ok else None})


# ── IP Management ─────────────────────────────────────────────────────────────

@app.route("/api/block-ip", methods=["POST"])
@login_required
def api_block_ip():
    """Block an IP at the OS firewall level."""
    import subprocess, platform
    data   = request.get_json()
    ip     = data.get("ip", "").strip()
    reason = data.get("reason", "Blocked via CyberSentinel")

    if not ip:
        return jsonify({"ok": False, "error": "No IP provided"})

    # Save to block list in DB
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip         TEXT PRIMARY KEY,
            reason     TEXT,
            blocked_at REAL,
            blocked_by TEXT
        )
    """)
    user = get_current_user()
    conn.execute("""
        INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, blocked_by)
        VALUES (?, ?, ?, ?)
    """, (ip, reason, time.time(), user["username"]))
    conn.commit()
    conn.close()

    # Attempt OS-level block
    system = platform.system()
    cmd_ok = False
    try:
        if system == "Windows":
            result = subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=CyberSentinel_Block_{ip}",
                "dir=in", "action=block",
                f"remoteip={ip}", "enable=yes"
            ], capture_output=True, timeout=10)
            # Also block outbound
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=CyberSentinel_Block_{ip}_out",
                "dir=out", "action=block",
                f"remoteip={ip}", "enable=yes"
            ], capture_output=True, timeout=10)
            cmd_ok = result.returncode == 0
        elif system in ("Linux", "Darwin"):
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                           capture_output=True, timeout=10)
            cmd_ok = True
    except Exception as e:
        print(f"[BLOCK] OS firewall command failed: {e}")

    return jsonify({
        "ok": True,
        "firewall_applied": cmd_ok,
        "message": f"IP {ip} blocked in database." + (" Firewall rule applied." if cmd_ok else " Note: Run as Administrator to apply firewall rules.")
    })


@app.route("/api/unblock-ip", methods=["POST"])
@login_required
def api_unblock_ip():
    """Unblock an IP."""
    import subprocess, platform
    data = request.get_json()
    ip   = data.get("ip", "").strip()

    conn = get_connection()
    conn.execute("CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, reason TEXT, blocked_at REAL, blocked_by TEXT)")
    conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()

    system = platform.system()
    try:
        if system == "Windows":
            subprocess.run(["netsh","advfirewall","firewall","delete","rule",f"name=CyberSentinel_Block_{ip}"], capture_output=True, timeout=10)
            subprocess.run(["netsh","advfirewall","firewall","delete","rule",f"name=CyberSentinel_Block_{ip}_out"], capture_output=True, timeout=10)
        elif system in ("Linux","Darwin"):
            subprocess.run(["iptables","-D","INPUT","-s",ip,"-j","DROP"], capture_output=True, timeout=10)
    except Exception as e:
        print(f"[UNBLOCK] {e}")

    return jsonify({"ok": True, "message": f"IP {ip} unblocked."})


@app.route("/api/blocked-ips")
@login_required
def api_blocked_ips():
    conn = get_connection()
    conn.execute("CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, reason TEXT, blocked_at REAL, blocked_by TEXT)")
    rows = conn.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        if d.get("blocked_at"):
            d["blocked_at_str"] = datetime.fromtimestamp(d["blocked_at"]).strftime("%Y-%m-%d %H:%M")
        result.append(d)
    return jsonify(result)


@app.route("/api/ip-activity/<ip>")
@login_required
def api_ip_activity(ip):
    """Return full traffic history for a specific IP."""
    conn = get_connection()

    # Traffic windows
    windows = conn.execute("""
        SELECT window_start, packet_count, bytes_per_sec, unique_dst_ports,
               unique_dst_ips, tcp_count, udp_count, icmp_count
        FROM traffic_windows
        WHERE src_ip = ?
        ORDER BY window_start DESC
        LIMIT 50
    """, (ip,)).fetchall()

    # Alerts for this IP
    alerts = conn.execute("""
        SELECT timestamp, anomaly_score, confidence_pct, threat_type,
               severity, explanation, recommended_action
        FROM alerts
        WHERE src_ip = ?
        ORDER BY timestamp DESC
        LIMIT 20
    """, (ip,)).fetchall()

    # Top destination IPs
    top_dsts = conn.execute("""
        SELECT dst_ip, COUNT(*) as count, SUM(size_bytes) as total_bytes
        FROM raw_packets
        WHERE src_ip = ?
        GROUP BY dst_ip
        ORDER BY count DESC
        LIMIT 10
    """, (ip,)).fetchall()

    # Top ports
    top_ports = conn.execute("""
        SELECT dst_port, COUNT(*) as count
        FROM raw_packets
        WHERE src_ip = ? AND dst_port IS NOT NULL
        GROUP BY dst_port
        ORDER BY count DESC
        LIMIT 10
    """, (ip,)).fetchall()

    # Baseline
    baseline = conn.execute(
        "SELECT * FROM device_baselines WHERE src_ip = ?", (ip,)
    ).fetchone()

    conn.close()

    def fmt_windows(rows):
        result = []
        for r in rows:
            d = dict(r)
            d["time_str"] = datetime.fromtimestamp(d["window_start"]).strftime("%H:%M:%S")
            result.append(d)
        return result

    def fmt_alerts(rows):
        result = []
        for r in rows:
            d = dict(r)
            if d.get("timestamp"):
                d["time_str"] = datetime.fromtimestamp(d["timestamp"]).strftime("%H:%M:%S")
            result.append(d)
        return result

    return jsonify({
        "ip"       : ip,
        "windows"  : fmt_windows(windows),
        "alerts"   : fmt_alerts(alerts),
        "top_dsts" : [dict(r) for r in top_dsts],
        "top_ports": [dict(r) for r in top_ports],
        "baseline" : dict(baseline) if baseline else None,
    })


# ── User Management ───────────────────────────────────────────────────────────

@app.route("/api/users")
@login_required
def api_users():
    from dashboard.auth import get_auth_conn
    conn = get_auth_conn()
    rows = conn.execute("""
        SELECT username, role, created_at, last_login, is_active, must_change_password
        FROM users ORDER BY created_at
    """).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        if d.get("last_login"):
            d["last_login_str"] = datetime.fromtimestamp(d["last_login"]).strftime("%Y-%m-%d %H:%M")
        else:
            d["last_login_str"] = "Never"
        if d.get("created_at"):
            d["created_str"] = datetime.fromtimestamp(d["created_at"]).strftime("%Y-%m-%d")
        result.append(d)
    return jsonify(result)


@app.route("/api/users/add", methods=["POST"])
@login_required
def api_add_user():
    from dashboard.auth import get_auth_conn, hash_password, validate_password_strength
    data     = request.get_json()
    username = data.get("username","").strip().lower()
    password = data.get("password","")
    role     = data.get("role","viewer")

    if not username or len(username) < 3:
        return jsonify({"ok": False, "error": "Username must be at least 3 characters."})

    issues = validate_password_strength(password)
    if issues:
        return jsonify({"ok": False, "error": issues[0]})

    conn = get_auth_conn()
    existing = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"ok": False, "error": f"Username '{username}' already exists."})

    salt, pw_hash = hash_password(password)
    conn.execute("""
        INSERT INTO users (username, password_hash, salt, role, created_at, must_change_password)
        VALUES (?, ?, ?, ?, ?, 0)
    """, (username, pw_hash, salt, role, time.time()))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": f"User '{username}' created successfully."})


@app.route("/api/users/delete", methods=["POST"])
@login_required
def api_delete_user():
    from dashboard.auth import get_auth_conn
    data     = request.get_json()
    username = data.get("username","")
    current  = get_current_user()

    if username == current["username"]:
        return jsonify({"ok": False, "error": "You cannot delete your own account."})
    if username == "admin":
        return jsonify({"ok": False, "error": "The admin account cannot be deleted."})

    conn = get_auth_conn()
    conn.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "message": f"User '{username}' deleted."})


@app.route("/api/users/toggle", methods=["POST"])
@login_required
def api_toggle_user():
    from dashboard.auth import get_auth_conn
    data     = request.get_json()
    username = data.get("username","")
    conn     = get_auth_conn()
    conn.execute("UPDATE users SET is_active = 1 - is_active WHERE username=?", (username,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ── Email & PDF endpoints ─────────────────────────────────────────────────────

@app.route("/api/send-test-email", methods=["POST"])
@login_required
def api_send_test_email():
    try:
        from notifications.email_alerter import send_test_email
        ok, msg = send_test_email()
        return jsonify({"ok": ok, "message": msg})
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)})


@app.route("/api/download-report")
@login_required
def api_download_report():
    try:
        from notifications.pdf_report import generate_pdf_report
        from flask import send_file
        hours = int(request.args.get("hours", 24))
        path  = generate_pdf_report(hours=hours)
        return send_file(path, as_attachment=True,
                         download_name=f"cybersentinel_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                         mimetype="application/pdf")
    except ImportError:
        return jsonify({"error": "reportlab not installed. Run: pip install reportlab"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/heatmap")
@login_required
def api_heatmap():
    """Return alert counts grouped by day-of-week and hour for the heatmap."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT
            CAST(strftime('%w', datetime(timestamp,'unixepoch','localtime')) AS INTEGER) as dow,
            CAST(strftime('%H', datetime(timestamp,'unixepoch','localtime')) AS INTEGER) as hour,
            COUNT(*) as count
        FROM alerts
        GROUP BY dow, hour
    """).fetchall()
    conn.close()

    # Build 7x24 grid (days x hours), all zeros
    grid = [[0]*24 for _ in range(7)]
    max_val = 0
    for r in rows:
        grid[r["dow"]][r["hour"]] = r["count"]
        max_val = max(max_val, r["count"])

    return jsonify({"grid": grid, "max": max_val,
                    "days": ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"]})


@app.route("/api/email-status")
@login_required
def api_email_status():
    try:
        from notifications.email_alerter import is_email_configured, ALERT_EMAIL
        return jsonify({"configured": is_email_configured(), "alert_email": ALERT_EMAIL if is_email_configured() else None})
    except Exception:
        return jsonify({"configured": False, "alert_email": None})